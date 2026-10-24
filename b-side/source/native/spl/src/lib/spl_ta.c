#include "spl_ta.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>

// ---- 原厂结构（从 libqtikeymint.so 反汇编对出来的，见 docs/04-反汇编笔记.md）----
typedef struct { const uint8_t *data; size_t length; } km_blob;

typedef struct {
    uint32_t tag;
    uint32_t pad;
    union {
        uint32_t enumerated;
        uint32_t integer;
        uint64_t long_integer;
        uint64_t date_time;
        int boolean;
        km_blob blob;
    } v;
} km_param;

typedef struct { km_param *params; size_t length; } km_param_set;

typedef void (*ctor_t)(void *, int);
typedef int (*init_t)(void *, unsigned, km_blob *);
typedef int (*send_t)(void *, const km_blob *, km_blob *);
typedef int (*ser_int_t)(void *, uint64_t, km_blob *);
typedef int (*ser_params_t)(void *, const km_param_set *, km_blob *);

#define SER_VTABLE_OFF 0x44878    // KeymasterSerialize 的 vtable 在 libqtikeymint.so 里的偏移
#define OBJ_SIZE 0x4000           // KeymasterUtils 实例（够大就行，原厂也不会超过这个）

struct spl_ta {
    void *obj;      // KeymasterUtils*
    void *ser;      // KeymasterSerialize 临时对象（只用它的 vtable）
    ctor_t ctor;
    init_t init;
    send_t send;
    ser_int_t ser_int;
    ser_params_t ser_params;
};

static uintptr_t module_base(const char *name) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) { base = (uintptr_t)strtoull(line, NULL, 16); break; }
    }
    fclose(f);
    return base;
}

static void *pick(void *handles[2], const char *sym) {
    for (int i = 0; i < 2; i++) {
        if (!handles[i]) continue;
        void *p = dlsym(handles[i], sym);
        if (p) return p;
    }
    return NULL;
}

spl_ta *spl_ta_open(void) {
    void *h  = dlopen("/vendor/lib64/libqtikeymint.so", RTLD_NOW | RTLD_GLOBAL);
    void *hu = dlopen("/vendor/lib64/libkeymasterdeviceutils.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h && !hu) return NULL;
    void *handles[2] = { h, hu };

    spl_ta *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    void *c1 = pick(handles, "_ZN14keymasterutils14KeymasterUtilsC1E26keymaster_security_level_t");
    void *c2 = pick(handles, "_ZN14keymasterutils14KeymasterUtilsC2E26keymaster_security_level_t");
    t->ctor       = (ctor_t)(c1 ? c1 : c2);
    t->init       = (init_t)pick(handles, "_ZN14keymasterutils14KeymasterUtils4initEjP16keymaster_blob_t");
    t->send       = (send_t)pick(handles, "_ZN14keymasterutils14KeymasterUtils7sendCmdERK16keymaster_blob_tPS1_");
    t->ser_int    = (ser_int_t)pick(handles, "_ZN18KeymasterSerialize16serializeIntegerEmP16keymaster_blob_t");
    t->ser_params = (ser_params_t)pick(handles, "_ZN18KeymasterSerialize21serializeClientParamsEPK25keymaster_key_param_set_tP16keymaster_blob_t");

    if (!t->ctor || !t->init || !t->send || !t->ser_int || !t->ser_params) {
        free(t);
        return NULL;
    }

    uintptr_t base = module_base("libqtikeymint.so");
    t->ser = calloc(1, 32);
    if (base && t->ser) *(uintptr_t *)t->ser = base + SER_VTABLE_OFF;

    t->obj = calloc(1, OBJ_SIZE);
    if (!t->obj) { free(t->ser); free(t); return NULL; }
    t->ctor(t->obj, 1);   // 1 = TRUSTED_ENVIRONMENT
    return t;
}

int spl_ta_apply(spl_ta *t, const spl_values *v, long long *us_out) {
    struct timespec t0, t1;
    if (!t || !v) return -1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    // 第一段：keymint_set_version()，原厂 configure() 之前必须先走这一步
    km_blob vb = { 0, 0 }, vr = { 0, 0 };
    t->init(t->obj, 0x3121, &vb);
    if (t->ser_int(t->ser, 300, &vb) != 0) return -10;
    t->send(t->obj, &vb, &vr);

    // 第二段：configure(param_set)
    km_param params[5];
    memset(params, 0, sizeof(params));
    size_t n = 0;
    params[n].tag = 0x300002c1; params[n].v.integer = v->os;     n++;
    params[n].tag = 0x300002c2; params[n].v.integer = v->sys;    n++;
    params[n].tag = 0x300002ce; params[n].v.integer = v->vendor; n++;
    if (v->boot) { params[n].tag = 0x300002cf; params[n].v.integer = v->boot; n++; }
    if (v->flag) { params[n].tag = 0x30003a99; params[n].v.integer = v->flag; n++; }
    km_param_set ps = { params, n };

    km_blob cb = { 0, 0 }, cr = { 0, 0 };
    t->init(t->obj, 0x2116, &cb);
    if (t->ser_params(t->ser, &ps, &cb) != 0) return -11;
    int rc = t->send(t->obj, &cb, &cr);

    if (us_out) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        *us_out = (long long)(t1.tv_sec - t0.tv_sec) * 1000000LL + (t1.tv_nsec - t0.tv_nsec) / 1000;
    }
    return rc;
}

void spl_ta_close(spl_ta *t) {
    if (!t) return;
    free(t->obj);
    free(t->ser);
    free(t);
}
