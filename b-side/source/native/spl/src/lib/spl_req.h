// 纯逻辑层：不碰设备、不碰 dlopen，主机上就能跑单测
#pragma once
#include <stdint.h>
#include <stddef.h>

// OS/System/Vendor 三个版本号 + SPU 标记，全部是十进制整数
typedef struct {
    uint32_t os;       // 160000 = Android 16，170000 = 17
    uint32_t sys;      // 202608   YYYYMM
    uint32_t vendor;   // 20260801 YYYYMMDD
    uint32_t boot;     // 20260801；0 = 不发送这个 tag（TA 不收时保持原值）
    uint32_t flag;     // 0x3a99 的值，SPU 不支持时是 3，支持时是 4
} spl_values;

// 协议命令
typedef enum {
    SPL_CMD_INVALID = 0,
    SPL_CMD_APPLY,
    SPL_CMD_RESTORE,
    SPL_CMD_BASELINE,
    SPL_CMD_STATUS,
    SPL_CMD_PING,
} spl_cmd;

// 解析一行请求。返回命令类型；APPLY/BASELINE 要求至少有 3 个数值。
// out_hold_ms: APPLY 的保持时长，没写就是 0（由调用方补默认值）
spl_cmd spl_parse_cmd(const char *line, spl_values *v, uint32_t *out_hold_ms, int *has_all_values);

// "16" -> 160000，"16.1" -> 160100
uint32_t spl_parse_os_release(const char *release);

// "2026-08-01"，with_day=0 -> 202608，with_day=1 -> 20260801
uint32_t spl_parse_patch_level(const char *patch, int with_day);

// vendor.gatekeeper.disable_spu = "true" 时 SPU 不可用，flag 取 3，否则 4
uint32_t spl_flag_from_disable_spu(const char *prop_value);

// 手工拼 0x2116 的 CBOR 请求（备用路径 / 单测夹具）
// 返回写入字节数；buf 至少 64 字节
size_t spl_build_cbor(uint8_t *buf, size_t cap, const spl_values *v);

// CBOR 请求的正确长度（用来校验 spl_build_cbor）
size_t spl_cbor_len(const spl_values *v);
