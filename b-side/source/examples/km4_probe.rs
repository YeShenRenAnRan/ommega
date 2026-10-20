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
    HidlKeymaster, KmParam, TAG_ALGORITHM, TAG_DIGEST, TAG_EC_CURVE, TAG_KEY_SIZE,
    TAG_NO_AUTH_REQUIRED, TAG_PURPOSE,
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

    println!("== 4. generateKey(vec<KeyParameter>)（验 32 字节定长布局）==");
    let params = vec![
        KmParam::integer(TAG_PURPOSE, PURPOSE_SIGN),
        KmParam::integer(TAG_ALGORITHM, ALGORITHM_EC),
        KmParam::integer(TAG_KEY_SIZE, 256),
        KmParam::integer(TAG_DIGEST, DIGEST_SHA_256),
        KmParam::integer(TAG_EC_CURVE, EC_CURVE_P256),
        KmParam::flag(TAG_NO_AUTH_REQUIRED),
    ];
    match km.generate_key(&params) {
        Ok(gen) => {
            println!("   ✓ keyblob {} 字节", gen.key_blob.len());
            println!(
                "     softwareEnforced = {} 项",
                gen.characteristics.software_enforced.len()
            );
            println!(
                "     hardwareEnforced = {} 项",
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
            println!("   → KeyParameter 布局、KeyCharacteristics 回包解码都对上了。");

            match km.delete_key(&gen.key_blob) {
                Ok(()) => println!("   ✓ 顺手把刚生成的密钥删了"),
                Err(e) => println!("   ✗ deleteKey 失败：{e:#}"),
            }
        }
        Err(e) => {
            println!("   ✗ {e:#}");
            println!("   → 看 ErrorCode：UNSUPPORTED_TAG / INVALID_TAG 说明参数编对了、");
            println!("     是真 TEE 不认这套 tag；Status 非 0 才是布局编错。");
        }
    }

    println!("\n探针结束。");
    Ok(())
}
