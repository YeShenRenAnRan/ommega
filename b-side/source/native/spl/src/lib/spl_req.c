#include "spl_req.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void upcase(char *s) {
    for (; *s; s++) if (*s >= 'a' && *s <= 'z') *s -= 32;
}

spl_cmd spl_parse_cmd(const char *line, spl_values *v, uint32_t *out_hold_ms, int *has_all_values) {
    char cmd[32] = { 0 };
    unsigned a = 0, b = 0, c = 0, fl = 0, hold = 0;
    int got;

    if (!line || !v) return SPL_CMD_INVALID;
    if (out_hold_ms) *out_hold_ms = 0;
    if (has_all_values) *has_all_values = 0;

    got = sscanf(line, "%31s %u %u %u %u %u", cmd, &a, &b, &c, &fl, &hold);
    if (got < 1) return SPL_CMD_INVALID;
    upcase(cmd);

    if (strcmp(cmd, "PING") == 0) return SPL_CMD_PING;
    if (strcmp(cmd, "RESTORE") == 0) return SPL_CMD_RESTORE;
    if (strcmp(cmd, "STATUS") == 0) return SPL_CMD_STATUS;

    if (strcmp(cmd, "APPLY") == 0) {
        if (got < 4) return SPL_CMD_INVALID;
        v->os = a; v->sys = b; v->vendor = c;
        v->flag = (got >= 5 && fl) ? fl : 3;
        if (out_hold_ms) *out_hold_ms = (got >= 6) ? hold : 0;
        if (has_all_values) *has_all_values = 1;
        return SPL_CMD_APPLY;
    }

    if (strcmp(cmd, "BASELINE") == 0) {
        if (got >= 4) {
            v->os = a; v->sys = b; v->vendor = c;
            v->flag = (got >= 5 && fl) ? fl : 3;
            if (has_all_values) *has_all_values = 1;
        }
        return SPL_CMD_BASELINE;
    }

    return SPL_CMD_INVALID;
}

uint32_t spl_parse_os_release(const char *release) {
    int major, minor = 0;
    if (!release || !*release) return 0;
    major = atoi(release);
    const char *dot = strchr(release, '.');
    if (dot) minor = atoi(dot + 1);
    if (major <= 0) return 0;
    return (uint32_t)(major * 10000 + minor * 100);
}

uint32_t spl_parse_patch_level(const char *patch, int with_day) {
    int y = 0, m = 0, d = 0;
    if (!patch) return 0;
    if (sscanf(patch, "%d-%d-%d", &y, &m, &d) < 3) return 0;
    if (y < 2000 || m < 1 || m > 12 || d < 1 || d > 31) return 0;
    return with_day ? (uint32_t)(y * 10000 + m * 100 + d) : (uint32_t)(y * 100 + m);
}

uint32_t spl_flag_from_disable_spu(const char *prop_value) {
    return (prop_value && strcmp(prop_value, "true") == 0) ? 3u : 4u;
}

static void put_u32(uint8_t *p, uint32_t x) {
    p[0] = 0x1a;
    p[1] = (uint8_t)(x >> 24);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 8);
    p[4] = (uint8_t)x;
}

// map(n)：22 -> 项数，0x300002c1 -> os，0x300002c2 -> sys，0x300002ce -> vendor
//          [0x300002cf -> boot]，[0x30003a99 -> flag]
size_t spl_cbor_len(const spl_values *v) {
    size_t pairs = 4;
    if (v && v->boot) pairs++;
    return 3 + pairs * 10;
}

size_t spl_build_cbor(uint8_t *buf, size_t cap, const spl_values *v) {
    size_t n = 0;
    if (!buf || !v) return 0;
    if (cap < spl_cbor_len(v)) return 0;

    size_t pairs = 4 + (v->boot ? 1 : 0);
    buf[n++] = (uint8_t)(0xa0 | (pairs + 1));  // map(pairs + 1)，第一对是 22 -> 项数
    buf[n++] = 0x16;                            // 键 22
    buf[n++] = (uint8_t)pairs;                  // 项数
    put_u32(buf + n, 0x300002c1); n += 5; put_u32(buf + n, v->os);     n += 5;
    put_u32(buf + n, 0x300002c2); n += 5; put_u32(buf + n, v->sys);    n += 5;
    put_u32(buf + n, 0x300002ce); n += 5; put_u32(buf + n, v->vendor); n += 5;
    if (v->boot) { put_u32(buf + n, 0x300002cf); n += 5; put_u32(buf + n, v->boot); n += 5; }
    put_u32(buf + n, 0x30003a99); n += 5; put_u32(buf + n, v->flag);   n += 5;
    return n;
}
