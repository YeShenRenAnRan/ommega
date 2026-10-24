// TA 通道封装：直接驱动原厂 libqtikeymint / libkeymasterdeviceutils 的 KeymasterUtils
// 只能在设备上跑，而且必须 uid 1000（vendor 库对 ksu 域不开放读权限）
#pragma once
#include <stdint.h>
#include "spl_req.h"

typedef struct spl_ta spl_ta;

// 打开通道并构造 KeymasterUtils。失败返回 NULL
spl_ta *spl_ta_open(void);

// 下发一组值。us_out 返回本次耗时（含 set_version 前置 + configure）
// 返回 sendCmd 的原始返回码（注意：本机 TA 会返回 16，但值仍然生效）
int spl_ta_apply(spl_ta *t, const spl_values *v, long long *us_out);

void spl_ta_close(spl_ta *t);
