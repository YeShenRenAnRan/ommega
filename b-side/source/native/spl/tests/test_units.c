// 纯逻辑层单测：协议解析、属性解析、CBOR 构造。主机上直接跑，不需要设备。
// gcc -std=c11 -I../src ../src/lib/spl_req.c test_units.c -o test_units
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../src/lib/spl_req.h"

static int g_pass, g_fail;

#define CHECK(cond, fmt, ...) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("FAIL %s:%d  " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); } \
} while (0)

#define CHECK_EQ_U(a, b) CHECK((a) == (b), "%s = %u, want %u", #a, (unsigned)(a), (unsigned)(b))
#define CHECK_EQ_I(a, b) CHECK((a) == (b), "%s = %d, want %d", #a, (int)(a), (int)(b))
#define CHECK_EQ_S(a, b) CHECK(strcmp((a), (b)) == 0, "%s = \"%s\", want \"%s\"", #a, (a), (b))

static void test_os_release(void) {
    CHECK_EQ_U(spl_parse_os_release("16"), 160000);
    CHECK_EQ_U(spl_parse_os_release("17"), 170000);
    CHECK_EQ_U(spl_parse_os_release("16.1"), 160100);
    CHECK_EQ_U(spl_parse_os_release("15.2"), 150200);
    CHECK_EQ_U(spl_parse_os_release(""), 0);
    CHECK_EQ_U(spl_parse_os_release(NULL), 0);
    CHECK_EQ_U(spl_parse_os_release("abc"), 0);
}

static void test_patch_level(void) {
    CHECK_EQ_U(spl_parse_patch_level("2026-08-01", 0), 202608);
    CHECK_EQ_U(spl_parse_patch_level("2026-08-01", 1), 20260801);
    CHECK_EQ_U(spl_parse_patch_level("2025-12-05", 1), 20251205);
    CHECK_EQ_U(spl_parse_patch_level("", 1), 0);
    CHECK_EQ_U(spl_parse_patch_level(NULL, 1), 0);
    CHECK_EQ_U(spl_parse_patch_level("2026-13-01", 1), 0);   // 月份越界
    CHECK_EQ_U(spl_parse_patch_level("2026-00-01", 1), 0);
}

static void test_spu_flag(void) {
    CHECK_EQ_U(spl_flag_from_disable_spu("true"), 3);
    CHECK_EQ_U(spl_flag_from_disable_spu("false"), 4);
    CHECK_EQ_U(spl_flag_from_disable_spu(NULL), 4);
}

static void test_parse_cmd(void) {
    spl_values v;
    uint32_t hold;
    int has;

    memset(&v, 0, sizeof(v));
    CHECK_EQ_I(spl_parse_cmd("PING", &v, &hold, &has), SPL_CMD_PING);
    CHECK_EQ_I(spl_parse_cmd("ping", &v, &hold, &has), SPL_CMD_PING);
    CHECK_EQ_I(spl_parse_cmd("RESTORE", &v, &hold, &has), SPL_CMD_RESTORE);
    CHECK_EQ_I(spl_parse_cmd("STATUS", &v, &hold, &has), SPL_CMD_STATUS);

    CHECK_EQ_I(spl_parse_cmd("APPLY 170000 202609 20260901", &v, &hold, &has), SPL_CMD_APPLY);
    CHECK_EQ_U(has, 1);
    CHECK_EQ_U(v.os, 170000);
    CHECK_EQ_U(v.sys, 202609);
    CHECK_EQ_U(v.vendor, 20260901);
    CHECK_EQ_U(v.flag, 3);        // 没写 flag，默认 3
    CHECK_EQ_U(hold, 0);          // 没写 hold，交给调用方补默认值

    CHECK_EQ_I(spl_parse_cmd("apply 1 2 3 4 1500", &v, &hold, &has), SPL_CMD_APPLY);
    CHECK_EQ_U(v.flag, 4);
    CHECK_EQ_U(hold, 1500);

    CHECK_EQ_I(spl_parse_cmd("APPLY 1 2", &v, &hold, &has), SPL_CMD_INVALID);
    CHECK_EQ_U(has, 0);

    memset(&v, 0, sizeof(v));
    CHECK_EQ_I(spl_parse_cmd("BASELINE", &v, &hold, &has), SPL_CMD_BASELINE);
    CHECK_EQ_U(has, 0);
    CHECK_EQ_I(spl_parse_cmd("BASELINE 160000 202608 20260801 3", &v, &hold, &has), SPL_CMD_BASELINE);
    CHECK_EQ_U(has, 1);
    CHECK_EQ_U(v.os, 160000);
    CHECK_EQ_U(v.flag, 3);

    CHECK_EQ_I(spl_parse_cmd("NOPE", &v, &hold, &has), SPL_CMD_INVALID);
    CHECK_EQ_I(spl_parse_cmd("", &v, &hold, &has), SPL_CMD_INVALID);
    CHECK_EQ_I(spl_parse_cmd(NULL, &v, &hold, &has), SPL_CMD_INVALID);
}

static void test_cbor(void) {
    spl_values v;
    memset(&v, 0, sizeof(v));
    v.os = 170000; v.sys = 202609; v.vendor = 20260901; v.boot = 0; v.flag = 3;
    uint8_t buf[64];
    size_t n = spl_build_cbor(buf, sizeof(buf), &v);

    CHECK_EQ_U(n, 43);
    CHECK_EQ_U(spl_cbor_len(&v), 43);
    CHECK_EQ_U(buf[0], 0xa5);   // map(5)
    CHECK_EQ_U(buf[1], 0x16);   // 键 22
    CHECK_EQ_U(buf[2], 0x04);   // 4 项

    // 头部之后是 4 个 (tag, value) 对，每对 10 字节
    static const uint32_t want_tag[4] = { 0x300002c1, 0x300002c2, 0x300002ce, 0x30003a99 };
    static const uint32_t want_val[4] = { 170000, 202609, 20260901, 3 };
    for (int i = 0; i < 4; i++) {
        const uint8_t *p = buf + 3 + i * 10;
        uint32_t tag = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4];
        uint32_t val = ((uint32_t)p[6] << 24) | ((uint32_t)p[7] << 16) | ((uint32_t)p[8] << 8) | p[9];
        CHECK_EQ_U(p[0], 0x1a);
        CHECK_EQ_U(p[5], 0x1a);
        CHECK_EQ_U(tag, want_tag[i]);
        CHECK_EQ_U(val, want_val[i]);
    }

    // 带 boot 时多一项（0x300002cf），长度 53
    v.boot = 20260901;
    n = spl_build_cbor(buf, sizeof(buf), &v);
    CHECK_EQ_U(n, 53);
    CHECK_EQ_U(spl_cbor_len(&v), 53);
    CHECK_EQ_U(buf[0], 0xa6);
    CHECK_EQ_U(buf[2], 0x05);
    CHECK_EQ_U(buf[33], 0x1a);  // 第四个 tag 的 CBOR 头
    {
        const uint8_t *p = buf + 33;
        uint32_t tag = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4];
        uint32_t val = ((uint32_t)p[6] << 24) | ((uint32_t)p[7] << 16) | ((uint32_t)p[8] << 8) | p[9];
        CHECK_EQ_U(tag, 0x300002cf);
        CHECK_EQ_U(val, 20260901);
    }

    // 缓冲区不够时拒绝写入
    CHECK_EQ_U(spl_build_cbor(buf, 10, &v), 0);
    CHECK_EQ_U(spl_build_cbor(NULL, sizeof(buf), &v), 0);
}

int main(void) {
    test_os_release();
    test_patch_level();
    test_spu_flag();
    test_parse_cmd();
    test_cbor();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
