// spl_daemon: 常驻 KeyMint SPL 配置服务
// 以 uid 1000 运行（要读 /vendor/lib64 下的 .so），监听 abstract unix socket @spl-daemon。
// 协议见 docs/03-工具与用法.md
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/system_properties.h>
#include <android/log.h>

#include "lib/spl_ta.h"
#include "lib/spl_req.h"

#define TAG "spl-daemon"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define SOCK_NAME "spl-daemon"
#define DEFAULT_HOLD_MS 2000

static spl_ta *g_ta;
static spl_values g_base;
static spl_values g_cur;
static int g_applied;          // 1 = 当前处于目标值
static long long g_hold_until; // ms，0 = 不用自动恢复

// 收到 TERM/INT 时先回基线再退：不然被 service.sh / 卸载停掉时 TA 会停在目标值上，
// 一直到重启或下一次配置。
static volatile sig_atomic_t g_stop;

static void on_stop(int sig) {
    (void)sig;
    g_stop = 1;
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

// 基线从系统属性推出来，不用手工配
static void derive_baseline(spl_values *out) {
    char v[PROP_VALUE_MAX];
    out->os = 160000;
    out->sys = 0;
    out->vendor = 0;
    out->boot = 0;      // 0 = 不发送 boot tag，TA 不收这个
    out->flag = 3;
    if (__system_property_get("ro.build.version.release", v) > 0) out->os = spl_parse_os_release(v);
    if (__system_property_get("ro.build.version.security_patch", v) > 0) out->sys = spl_parse_patch_level(v, 0);
    if (__system_property_get("ro.vendor.build.security_patch", v) > 0) out->vendor = spl_parse_patch_level(v, 1);
    if (__system_property_get("vendor.gatekeeper.disable_spu", v) > 0) out->flag = spl_flag_from_disable_spu(v);
}

static void reply(int fd, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) (void)!write(fd, buf, (size_t)n);
}

static void do_restore(void) {
    long long us = 0;
    spl_ta_apply(g_ta, &g_base, &us);
    g_cur = g_base;
    g_applied = 0;
    g_hold_until = 0;
}

static int same(const spl_values *a, const spl_values *b) {
    return a->os == b->os && a->sys == b->sys && a->vendor == b->vendor && a->flag == b->flag;
}

static void handle(int fd, const char *line) {
    spl_values v = { 0 };
    uint32_t hold = 0;
    int has_values = 0;
    spl_cmd cmd = spl_parse_cmd(line, &v, &hold, &has_values);

    switch (cmd) {
    case SPL_CMD_PING:
        reply(fd, "OK pong\n");
        break;

    case SPL_CMD_STATUS:
        reply(fd, "OK base=%u/%u/%u/%u cur=%u/%u/%u/%u applied=%d hold_ms_left=%lld\n",
              g_base.os, g_base.sys, g_base.vendor, g_base.flag,
              g_cur.os, g_cur.sys, g_cur.vendor, g_cur.flag, g_applied,
              g_hold_until > now_ms() ? g_hold_until - now_ms() : 0);
        break;

    case SPL_CMD_BASELINE:
        if (has_values) g_base = v;
        reply(fd, "OK base=%u/%u/%u/%u\n", g_base.os, g_base.sys, g_base.vendor, g_base.flag);
        break;

    case SPL_CMD_RESTORE: {
        long long t0 = now_ms();
        do_restore();
        reply(fd, "OK restored in %lldms\n", now_ms() - t0);
        break;
    }

    case SPL_CMD_APPLY: {
        if (!hold) hold = DEFAULT_HOLD_MS;
        if (same(&v, &g_cur)) {
            g_hold_until = now_ms() + hold;
            reply(fd, "OK same-value us=0 hold_ms=%u\n", hold);
            break;
        }
        long long us = 0;
        int rc = spl_ta_apply(g_ta, &v, &us);
        g_cur = v;
        g_applied = 1;
        g_hold_until = now_ms() + hold;
        // rc 可能是 16，那是本机 TA 的"已配置"提示，值已经生效，不能当失败
        reply(fd, "OK applied us=%lld rc=%d hold_ms=%u\n", us, rc, hold);
        break;
    }

    default:
        reply(fd, "ERR bad-command\n");
        break;
    }
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    g_ta = spl_ta_open();
    if (!g_ta) { LOGI("ta_open failed"); return 2; }
    derive_baseline(&g_base);
    g_cur = g_base;

    // 先下发一次基线，确认通道通了
    { long long us = 0; spl_ta_apply(g_ta, &g_base, &us); }

    // 自 daemonize；SPL_FOREGROUND=1 时留在前台方便调试
    if (!getenv("SPL_FOREGROUND")) {
        pid_t p = fork();
        if (p > 0) return 0;
        setsid();
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
    }

    // 正常停止（SIGTERM/SIGINT）要能回基线，SIGKILL 做不到 —— 停进程的地方
    // 先发 TERM 等一会儿再发 KILL（见 service.sh / uninstall.sh）。
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { LOGI("socket: %s", strerror(errno)); return 3; }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = 0;                                  // abstract namespace
    memcpy(addr.sun_path + 1, SOCK_NAME, strlen(SOCK_NAME));
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(SOCK_NAME));
    if (bind(srv, (struct sockaddr *)&addr, alen) != 0) { LOGI("bind: %s", strerror(errno)); return 4; }
    listen(srv, 8);

    LOGI("listening @%s base=%u/%u/%u/%u", SOCK_NAME, g_base.os, g_base.sys, g_base.vendor, g_base.flag);

    for (;;) {
        fd_set rfds;
        struct timeval tv = { 0, 50000 };   // 50ms，用来跑看门狗
        FD_ZERO(&rfds);
        FD_SET(srv, &rfds);
        int n = select(srv + 1, &rfds, NULL, NULL, &tv);
        if (n < 0 && errno != EINTR) break;

        if (n > 0 && FD_ISSET(srv, &rfds)) {
            int c = accept(srv, NULL, NULL);
            if (c >= 0) {
                char line[512];
                ssize_t r = read(c, line, sizeof(line) - 1);
                if (r > 0) {
                    line[r] = 0;
                    char *nl = strpbrk(line, "\r\n");
                    if (nl) *nl = 0;
                    handle(c, line);
                }
                close(c);
            }
        }

        // relay 挂了没来 RESTORE，到点自己回基线，别把假日期留在设备上
        if (g_applied && g_hold_until && now_ms() > g_hold_until) {
            do_restore();
            LOGI("watchdog restored");
        }

        if (g_stop) {
            int was = g_applied;
            if (was) do_restore();
            LOGI("stopping (was_applied=%d)", was);
            break;
        }
    }
    return 0;
}
