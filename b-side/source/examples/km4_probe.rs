//! HIDL Keymaster 4.x 探针：在真机上把 [`hidl_km`] 那条链路一层层试通。
//!
//! 这台 B 端是「有 HIDL keymaster、没有 AIDL KeyMint」的机器（天玑 1200 那类），
//! 所以 `relay_tee::get_system_keymint` 一定连不上 —— 这个探针就是用来把这句
//! `NameNotFound` 换成「HIDL 这边到底通到了哪一步」的。
//!
//! 分层验证，前一层挂了后面就不用看了：
//!
//! 1. `hwservicemanager` 里到底注册了哪个版本（4.1 / 4.0 / 都没有）；
//! 2. `getHardwareInfo()` —— 只回一个 u32 和两个字符串，**不碰结构体布局**，
//!    通了就说明「事务号 + 参数形状 + 回包解码」这条基本链路成立；
//! 3. `addRngEntropy()` —— 带一个 `vec<uint8_t>` 形参，验 buffer object 那半边；
//! 4. `generateKey()` —— 第一个要编 `vec<KeyParameter>` 的调用，验 32 字节定长布局。
//!    这一层挂了要看 ErrorCode：`UNSUPPORTED_TAG`/`INVALID_TAG` 说明参数编对了、
//!    真 TEE 不认；要是 HIDL 那层直接崩（Status 非 0），才是布局编错了。
//!
//! ```text
//! adb push target/aarch64-linux-android/release/examples/km4_probe /data/local/tmp/
//! adb shell su -c /data/local/tmp/km4_probe
//! ```
//!
//! 不做破坏性操作：第 4 步只生成一个 EC 密钥，拿到 keyblob 之后立刻 `deleteKey`
//! 删掉（`generateKey` 不带 `NO_AUTH_REQUIRED` 的密钥不会有副作用，但删干净更省心）。

use anyhow::Result;

use ommegaclient_b::keymaster::hidl_km::{
    HidlKeymaster, KmParam, TAG_ALGORITHM, TAG_APPLICATION_ID, TAG_DIGEST, TAG_EC_CURVE,
    TAG_KEY_SIZE, TAG_NO_AUTH_REQUIRED, TAG_PURPOSE, TAG_RSA_PUBLIC_EXPONENT,
};

/// `KeyPurpose::SIGN`。
const PURPOSE_SIGN: u32 = 2;
/// `Algorithm::EC`。
const ALGORITHM_EC: u32 = 3;
/// `Digest::SHA_2_256`。
const DIGEST_SHA_256: u32 = 4;
/// `EcCurve::P_256`。
const EC_CURVE_P256: u32 = 1;

fn main() -> Result<()> {
    println!("== 1. 探 HIDL Keymaster 4.x ==");
    let km = match HidlKeymaster::open()? {
        Some(km) => km,
        None => {
            println!("   4.1 / 4.0 都没注册。");
            println!("   这台机器要么没有 /dev/hwbinder，要么 keymaster 还是 @3.0（Android 10 及更早）。");
            println!("   跑一下这些看看它到底有什么：");
            println!("     service list | grep -iE 'keymint|keymaster'");
            println!("     lshal | grep -iE 'keymint|keymaster'");
            println!("     ls -l /vendor/lib64/ | grep keymaster");
            return Ok(());
        }
    };
    println!(
        "   ✓ 连上 {}（句柄 {}，HAL 版本号 {}）",
        km.version().fq_name(),
        km.handle(),
        km.version().hal_version()
    );
    println!(
        "     ↑ 这是连上后自检出来、对端真正认的那个 interface descriptor；\
         \n       它不一定等于 getService 用的注册名（MTK 有实现以 @4.1 注册、只认 @4.0）。"
    );

    println!("== 2. getHardwareInfo()（不碰结构体布局）==");
    match km.get_hardware_info() {
        Ok((level, name, author)) => {
            let level_name = match level {
                0 => "SOFTWARE",
                1 => "TRUSTED_ENVIRONMENT",
                2 => "STRONGBOX",
                _ => "?",
            };
            println!("   ✓ securityLevel = {level} ({level_name})");
            println!("     keymasterName       = {name:?}");
            println!("     keymasterAuthorName = {author:?}");
            println!("   → 事务号、hidl_string 回包解码都对上了。");
        }
        Err(e) => {
            println!("   ✗ {e:#}");
            println!("   → 基本链路就没通，后面不用试了。");
            return Ok(());
        }
    }

    println!("== 3. addRngEntropy(vec<uint8_t>)（验 buffer object 形参）==");
    match km.add_rng_entropy(&[0xA5u8; 32]) {
        Ok(()) => println!("   ✓ OK"),
        Err(e) => println!("   ✗ {e:#}（链路通了但 TEE 拒了，也算验过）"),
    }
    // 对照实验：`addRngEntropy` 即使把 vec 读成空的也可能返回 OK，所以它单独
    // 证明不了「vec 参数被读进来了」。`deleteKey` 拿一个垃圾 blob 一定会被 TEE
    // 拒绝，但拒绝的形状能区分两件事：`KM_ERROR_*`（小负数）= 参数读进去了；
    // `-22 BAD_VALUE` = 连读都没读成功。
    println!("-- 3b 对照：deleteKey(vec<uint8_t>) 垃圾 blob --");
    match km.delete_key(&[0xAAu8; 32]) {
        Ok(()) => println!("   ✓ 居然删成功了（不该）"),
        Err(e) => println!("   → {e:#}"),
    }
    println!("-- 3c 对照：addRngEntropy(空 vec) --");
    match km.add_rng_entropy(&[]) {
        Ok(()) => println!("   ✓ OK"),
        Err(e) => println!("   → {e:#}"),
    }

    println!("== 4. generateKey(vec<KeyParameter>)（验 32 字节定长布局）==");
    // 分三档，把「对象形状」和「元素内容」分开验：
    //   4a 空 vector —— 只涉及头 + 元素数组两个对象；
    //   4b 只有标量 —— 加上 32 字节元素本身，没有嵌套对象；
    //   4c 标量 + blob —— 再加上联合体判别式和嵌套 buffer object。
    let scalars = vec![
        KmParam::integer(TAG_PURPOSE, PURPOSE_SIGN),
        KmParam::integer(TAG_ALGORITHM, ALGORITHM_EC),
        KmParam::integer(TAG_KEY_SIZE, 256),
        KmParam::integer(TAG_DIGEST, DIGEST_SHA_256),
        KmParam::integer(TAG_EC_CURVE, EC_CURVE_P256),
        KmParam::flag(TAG_NO_AUTH_REQUIRED),
    ];
    let with_blob = vec![
        KmParam::integer(TAG_PURPOSE, PURPOSE_SIGN),
        KmParam::integer(TAG_ALGORITHM, ALGORITHM_EC),
        KmParam::integer(TAG_KEY_SIZE, 256),
        KmParam::integer(TAG_DIGEST, DIGEST_SHA_256),
        KmParam::integer(TAG_EC_CURVE, EC_CURVE_P256),
        KmParam::flag(TAG_NO_AUTH_REQUIRED),
        KmParam::blob(TAG_APPLICATION_ID, b"km4-probe".to_vec()),
    ];

    try_generate_key(&km, "4a 空 vector（只有头 + 元素数组）", &[]);
    try_generate_key(&km, "4b 只有标量（无嵌套 blob）", &scalars);
    try_generate_key(&km, "4c 标量 + 一个 blob", &with_blob);

    // 4b/4c 已经过了参数读取、被 TEE 以 `UNSUPPORTED_KEY_SIZE` 拒掉。下面几档把
    // 「KEY_SIZE 这个值 TEE 到底读到没有」和「64 位 tag 走 longInteger 对不对」分开。
    // 数字直接写：Algorithm::RSA=1 / EC=3，EcCurve::P256=1 / P384=2，
    // Digest::SHA256=4 / SHA384=5，KeyPurpose::SIGN=2。
    let ec_no_size = vec![
        KmParam::integer(TAG_PURPOSE, PURPOSE_SIGN),
        KmParam::integer(TAG_ALGORITHM, ALGORITHM_EC),
        KmParam::integer(TAG_DIGEST, DIGEST_SHA_256),
        KmParam::integer(TAG_EC_CURVE, EC_CURVE_P256),
        KmParam::flag(TAG_NO_AUTH_REQUIRED),
    ];
    let ec_384 = vec![
        KmParam::integer(TAG_PURPOSE, 2),
        KmParam::integer(TAG_ALGORITHM, 3),
        KmParam::integer(TAG_KEY_SIZE, 384),
        KmParam::integer(TAG_DIGEST, 5),
        KmParam::integer(TAG_EC_CURVE, 2),
        KmParam::flag(TAG_NO_AUTH_REQUIRED),
    ];
    let rsa = vec![
        KmParam::integer(TAG_PURPOSE, 2),
        KmParam::integer(TAG_ALGORITHM, 1),
        KmParam::integer(TAG_KEY_SIZE, 2048),
        KmParam::long(TAG_RSA_PUBLIC_EXPONENT, 65537),
        KmParam::integer(TAG_DIGEST, 4),
        KmParam::flag(TAG_NO_AUTH_REQUIRED),
    ];
    try_generate_key(&km, "4d EC 不带 KEY_SIZE", &ec_no_size);
    try_generate_key(&km, "4e EC P-384 + KEY_SIZE=384", &ec_384);
    try_generate_key(&km, "4f RSA 2048 + 公开指数 65537（验 64 位 tag）", &rsa);

    println!("\n探针结束。");
    Ok(())
}

/// 跑一次 `generateKey` 并把结果说清楚。空的参数集必然拿不到密钥，所以 4a 那档
/// 看的是「错误码长什么样」：`BAD_VALUE`(-22) 说明读参数就失败了，换成
/// `KM_ERROR_*` 的小负数才说明参数读进去了、是 TEE 不认这套 tag。
fn try_generate_key(km: &HidlKeymaster, label: &str, params: &[KmParam]) {
    println!("-- {label} --");
    match km.generate_key(params) {
        Ok(gen) => {
            println!("   ✓ keyblob {} 字节", gen.key_blob.len());
            println!(
                "     softwareEnforced = {} 项，hardwareEnforced = {} 项",
                gen.characteristics.software_enforced.len(),
                gen.characteristics.hardware_enforced.len()
            );
            for p in gen
                .characteristics
                .hardware_enforced
                .iter()
                .chain(gen.characteristics.software_enforced.iter())
                .take(12)
            {
                println!("       tag 0x{:08X} = {:?}", p.tag, p.value);
            }
            match km.delete_key(&gen.key_blob) {
                Ok(()) => println!("   ✓ 顺手把刚生成的密钥删了"),
                Err(e) => println!("   ✗ deleteKey 失败：{e:#}"),
            }
        }
        Err(e) => println!("   ✗ {e:#}"),
    }
}
