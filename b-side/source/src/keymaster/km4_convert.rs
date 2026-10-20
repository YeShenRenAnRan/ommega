//! `kmr_wire::keymint::KeyParam` → HIDL KM4 `KmParam` 的转换层。
//!
//! 为什么需要这一层：`KeyParam` 是 KeyMint 的**带类型枚举**（`Purpose(KeyPurpose)`、
//! `KeySize(KeySizeInBits)` ……），一个变体同时表达了 tag 和值类型；而 HIDL KM4 的
//! `KeyParameter` 是 AOSP 手工摊平过的三元组
//! `(Tag tag, IntegerParams f 联合体, vec<uint8_t> blob)`，tag 本身就是判别式。
//!
//! **tag 编号不用换算。** KeyMint 沿用了 keymaster 4.x 那套 `TagType|n` 复合值，
//! `kmr_wire::keymint::Tag` 的判别值和 KM4 `types.hal` 里的 tag 常量逐位相同
//! （`Purpose = 0x20000001`、`Algorithm = 0x10000002`、`EcCurve = 0x1000000A`、
//! `RsaPublicExponent = 0x500000C8` ……）。所以这一层只是把「类型」搬进联合体，
//! 不做任何重编号 —— 这也是它能是纯映射的原因。
//!
//! 只做单向（wire → KM4）。`getKeyCharacteristics` 回来的参数我们不读：`tee_ops.rs`
//! 里没有任何一处用到 `KeyCharacteristics`，`kmr_wire` 也没有对应的 wire 类型。
//! 等真需要读的时候再补反向，别现在写一份没人用的代码。
//!
//! **tag 内部的枚举值也不用换算**，这一点逐项核对过 KM4 4.0 `types.hal`：`KeyPurpose`
//! （4 保留，`WRAP_KEY` 仍是 5）、`PaddingMode`、`Digest`、`Algorithm`、`BlockMode`、
//! `EcCurve`、`KeyOrigin`、`HardwareAuthenticatorType` 与 KeyMint 的值全部一致。
//! 只有三个值 KM4 里不存在 —— `KeyPurpose::AgreeKey`(6)、`KeyPurpose::AttestKey`(7)、
//! `EcCurve::Curve25519`(4)。b-side 的实际路径到不了它们（只做 EcP256，且
//! `ATTEST_KEY` 在 `build_attestation_params` 里就被剥掉了），所以不做值重映射；
//! 硬要重映射反而会把「TEE 拒绝了不认识的 purpose」这种真问题掩盖掉。
//! `enum_values_match_km4_types_hal` 盯着这份结论。

use kmr_wire::keymint::KeyParam;
use log::warn;

use super::hidl_km::KmParam;

/// 把一组 KeyMint 参数翻成 KM4 参数，**顺序保持不变**。
///
/// 顺序是有意义的：真 TEE 的 `generateKey` 会按参数顺序建立 key 描述，
/// 而 AOSP 的 KM4 HAL 实现本身也是顺序遍历。
pub fn params_to_km4(params: &[KeyParam]) -> Vec<KmParam> {
    params.iter().cloned().filter_map(param_to_km4).collect()
}

/// 单个参数。
///
/// KeyMint 独有、KM4 4.x `types.hal` 里没有对应 tag 的参数返回 `None`，
/// 并留一条 `warn`：把它塞给真 TEE 只会换来一个 `UnsupportedTag`，
/// 然后把整个 `generateKey` 拖挂，不如在这一层摘掉。
pub fn param_to_km4(param: KeyParam) -> Option<KmParam> {
    let tag = param.tag();
    // `Tag` 是 `#[repr(i32)]` 且带负判别值（如 `UserSecureId = -1610612234`
    // 其实就是 `0xA00001F6`），所以先转 i32 再转 u32，不能直接 as u32。
    let tag_num = tag as i32 as u32;

    let out = match param {
        // ---- ENUM：联合体里就那一格 u32 ----
        KeyParam::Purpose(v) => KmParam::integer(tag_num, v as i32 as u32),
        KeyParam::Algorithm(v) => KmParam::integer(tag_num, v as i32 as u32),
        KeyParam::BlockMode(v) => KmParam::integer(tag_num, v as i32 as u32),
        KeyParam::Digest(v) => KmParam::integer(tag_num, v as i32 as u32),
        KeyParam::EcCurve(v) => KmParam::integer(tag_num, v as i32 as u32),
        KeyParam::Origin(v) => KmParam::integer(tag_num, v as i32 as u32),
        KeyParam::Padding(v) => KmParam::integer(tag_num, v as i32 as u32),

        // ---- UINT ----
        KeyParam::KeySize(v) => KmParam::integer(tag_num, v.0),
        KeyParam::MinMacLength(v)
        | KeyParam::MaxUsesPerBoot(v)
        | KeyParam::UsageCountLimit(v)
        | KeyParam::UserId(v)
        | KeyParam::UserAuthType(v)
        | KeyParam::AuthTimeout(v)
        | KeyParam::OsVersion(v)
        | KeyParam::OsPatchlevel(v)
        | KeyParam::VendorPatchlevel(v)
        | KeyParam::BootPatchlevel(v)
        | KeyParam::MacLength(v) => KmParam::integer(tag_num, v),

        // ---- ULONG / ULONG_REP ----
        KeyParam::RsaPublicExponent(v) => KmParam::long(tag_num, v.0),
        KeyParam::UserSecureId(v) => KmParam::long(tag_num, v),

        // ---- DATE：联合体里是 u64 毫秒 ----
        KeyParam::ActiveDatetime(v)
        | KeyParam::OriginationExpireDatetime(v)
        | KeyParam::UsageExpireDatetime(v)
        | KeyParam::CreationDatetime(v) => KmParam::datetime(tag_num, v.ms_since_epoch as u64),

        // ---- BYTES ----
        KeyParam::ApplicationId(v)
        | KeyParam::ApplicationData(v)
        | KeyParam::RootOfTrust(v)
        | KeyParam::AttestationChallenge(v)
        | KeyParam::AttestationApplicationId(v)
        | KeyParam::AttestationIdBrand(v)
        | KeyParam::AttestationIdDevice(v)
        | KeyParam::AttestationIdProduct(v)
        | KeyParam::AttestationIdSerial(v)
        | KeyParam::AttestationIdImei(v)
        | KeyParam::AttestationIdSecondImei(v)
        | KeyParam::AttestationIdMeid(v)
        | KeyParam::AttestationIdManufacturer(v)
        | KeyParam::AttestationIdModel(v)
        | KeyParam::Nonce(v) => KmParam::blob(tag_num, v),

        // ---- BOOL：HIDL 里「tag 存在即为真」，`flag` 会把联合体写成 boolValue=1 ----
        KeyParam::CallerNonce
        | KeyParam::IncludeUniqueId
        | KeyParam::BootloaderOnly
        | KeyParam::RollbackResistance
        | KeyParam::EarlyBootOnly
        | KeyParam::NoAuthRequired
        | KeyParam::AllowWhileOnBody
        | KeyParam::TrustedUserPresenceRequired
        | KeyParam::TrustedConfirmationRequired
        | KeyParam::UnlockedDeviceRequired
        | KeyParam::DeviceUniqueAttestation
        | KeyParam::StorageKey
        | KeyParam::ResetSinceIdRotation => KmParam::flag(tag_num),

        // ---- KeyMint 独有，KM4 4.0/4.1 的 types.hal 里没有 ----
        // MlDsaVariant / ModuleHash / MaxBootLevel 是 KeyMint v4/v5 才加的；
        // RsaOaepMgfDigest 是 KeyMint v3 加的；CertificateSerial / Subject /
        // NotBefore / NotAfter 是 KeyMint v4 的认证密钥证书参数。
        KeyParam::MlDsaVariant(_)
        | KeyParam::RsaOaepMgfDigest(_)
        | KeyParam::MaxBootLevel(_)
        | KeyParam::ModuleHash(_)
        | KeyParam::CertificateSerial(_)
        | KeyParam::CertificateSubject(_)
        | KeyParam::CertificateNotBefore(_)
        | KeyParam::CertificateNotAfter(_) => {
            warn!("dropping KeyMint-only tag {tag:?}: KM4 4.x types.hal has no such tag");
            return None;
        }
    };
    Some(out)
}

/// 把认证类参数从密钥参数里拆出来，供 KM4 的两段式生成使用。
///
/// KeyMint 是 `generateKey(keyParams, attestKeyParams)` **一次**就把认证链带回来；
/// KM4 的 `generateKey(vec<KeyParameter> keyParams)` 只回
/// `(ErrorCode, keyBlob, KeyCharacteristics)`，**根本没有 attestParams 这个参数**。
/// 认证链单独在
/// `attestKey(vec<uint8_t> keyToAttest, vec<KeyParameter> attestParams)
///  generates (ErrorCode, vec<vec<uint8_t>> certChain)`，
/// 且 HAL 文档写明 attestParams **必须**含 `ATTESTATION_CHALLENGE`。
///
/// 所以留在 `generateKey` 里对认证没有任何用（它不产出证书），
/// 只会多给 TEE 一次用 `UnsupportedTag` 拒掉整个调用的机会。
///
/// 归 `attestKey` 的是：挑战值、application id、全部 `ATTESTATION_ID_*`。
/// 其余（含 `RESET_SINCE_ID_ROTATION`、`DEVICE_UNIQUE_ATTESTATION`、
/// `INCLUDE_UNIQUE_ID`）留在 `generateKey` —— 它们是**密钥的**授权属性，要进
/// KeyDescription 的 teeEnforced/softwareEnforced 列表，而那份列表来自密钥本身，
/// 不来自 attestParams。
pub fn split_km4_attestation(params: &[KeyParam]) -> (Vec<KeyParam>, Vec<KeyParam>) {
    let mut key_params = Vec::with_capacity(params.len());
    let mut attest_params = Vec::new();
    for param in params.iter().cloned() {
        if is_attestation_only(&param) {
            attest_params.push(param);
        } else {
            key_params.push(param);
        }
    }
    (key_params, attest_params)
}

/// 只对 `attestKey` 有意义的 tag。
fn is_attestation_only(param: &KeyParam) -> bool {
    matches!(
        param,
        KeyParam::AttestationChallenge(_)
            | KeyParam::AttestationApplicationId(_)
            | KeyParam::AttestationIdBrand(_)
            | KeyParam::AttestationIdDevice(_)
            | KeyParam::AttestationIdProduct(_)
            | KeyParam::AttestationIdSerial(_)
            | KeyParam::AttestationIdImei(_)
            | KeyParam::AttestationIdSecondImei(_)
            | KeyParam::AttestationIdMeid(_)
            | KeyParam::AttestationIdManufacturer(_)
            | KeyParam::AttestationIdModel(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_wire::keymint::{
        Algorithm, BlockMode, Digest, EcCurve, KeyOrigin, KeyPurpose, PaddingMode, Tag,
    };
    use kmr_wire::{KeySizeInBits, RsaExponent};

    /// tag 编号必须和 KM4 `types.hal` 的常量逐位相同，否则真 TEE 会回
    /// `UnsupportedTag`/`InvalidTag`。
    #[test]
    fn tag_numbers_match_km4_types_hal() {
        let p = param_to_km4(KeyParam::Purpose(KeyPurpose::Sign)).unwrap();
        assert_eq!(p.tag, 0x2000_0001);
        assert_eq!(p.value, super::super::hidl_km::KmValue::Integer(2));

        let p = param_to_km4(KeyParam::Algorithm(Algorithm::Ec)).unwrap();
        assert_eq!(p.tag, 0x1000_0002);

        let p = param_to_km4(KeyParam::KeySize(KeySizeInBits(256))).unwrap();
        assert_eq!(p.tag, 0x3000_0003);

        let p = param_to_km4(KeyParam::EcCurve(EcCurve::P256)).unwrap();
        assert_eq!(p.tag, 0x1000_000A);

        let p = param_to_km4(KeyParam::RsaPublicExponent(RsaExponent(65537))).unwrap();
        assert_eq!(p.tag, 0x5000_00C8);
    }

    /// 负判别值的 tag（`UserSecureId`）要能正确落到 `0xA00001F6`。
    #[test]
    fn negative_discriminant_tags_land_right() {
        let p = param_to_km4(KeyParam::UserSecureId(0x1234)).unwrap();
        assert_eq!(p.tag, 0xA000_01F6);
    }

    /// KeyMint 独有的 tag 必须被摘掉，不能透传给 KM4。
    #[test]
    fn keymint_only_tags_are_dropped() {
        assert!(param_to_km4(KeyParam::ModuleHash(vec![0xAB; 32])).is_none());
        assert!(param_to_km4(KeyParam::MaxBootLevel(1)).is_none());
        assert!(param_to_km4(KeyParam::CertificateSerial(vec![1, 2, 3])).is_none());
    }

    /// 参数顺序不能被打乱（真 TEE 顺序遍历）。
    #[test]
    fn order_is_preserved_and_filtered() {
        let input = vec![
            KeyParam::Purpose(KeyPurpose::Sign),
            KeyParam::ModuleHash(vec![0xAB; 32]), // 会被摘掉
            KeyParam::Algorithm(Algorithm::Ec),
        ];
        let out = params_to_km4(&input);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].tag, 0x2000_0001);
        assert_eq!(out[1].tag, 0x1000_0002);
    }

    /// tag 内部的**枚举值**也必须和 KM4 `types.hal` 相同。这一层只搬 tag、不重编号值，
    /// 所以任何一边改了编号，这里必须响。
    ///
    /// 右边这些数字是从 KM4 4.0 `types.hal` 抄下来的，不是「等于自己」的空转断言。
    #[test]
    fn enum_values_match_km4_types_hal() {
        assert_eq!(KeyPurpose::Encrypt as i32, 0);
        assert_eq!(KeyPurpose::Decrypt as i32, 1);
        assert_eq!(KeyPurpose::Sign as i32, 2);
        assert_eq!(KeyPurpose::Verify as i32, 3);
        // 4 在 KM4 里是保留值，WRAP_KEY 就是 5。KeyMint 只是往后多接了 6/7。
        assert_eq!(KeyPurpose::WrapKey as i32, 5);

        assert_eq!(PaddingMode::None as i32, 1);
        assert_eq!(PaddingMode::RsaOaep as i32, 2);
        assert_eq!(PaddingMode::RsaPss as i32, 3);
        assert_eq!(PaddingMode::RsaPkcs115Encrypt as i32, 4);
        assert_eq!(PaddingMode::RsaPkcs115Sign as i32, 5);

        assert_eq!(Digest::None as i32, 0);
        assert_eq!(Digest::Md5 as i32, 1);
        assert_eq!(Digest::Sha1 as i32, 2);
        assert_eq!(Digest::Sha224 as i32, 3);
        assert_eq!(Digest::Sha256 as i32, 4);
        assert_eq!(Digest::Sha384 as i32, 5);
        assert_eq!(Digest::Sha512 as i32, 6);

        assert_eq!(Algorithm::Rsa as i32, 1);
        assert_eq!(Algorithm::Ec as i32, 3);
        assert_eq!(Algorithm::Aes as i32, 32);

        assert_eq!(BlockMode::Ecb as i32, 1);
        assert_eq!(BlockMode::Cbc as i32, 2);
        assert_eq!(BlockMode::Ctr as i32, 3);
        assert_eq!(BlockMode::Gcm as i32, 32);

        assert_eq!(EcCurve::P224 as i32, 0);
        assert_eq!(EcCurve::P256 as i32, 1);
        assert_eq!(EcCurve::P384 as i32, 2);
        assert_eq!(EcCurve::P521 as i32, 3);

        assert_eq!(KeyOrigin::Generated as i32, 0);
        assert_eq!(KeyOrigin::Imported as i32, 2);
        assert_eq!(KeyOrigin::SecurelyImported as i32, 4);

        assert_eq!(
            kmr_wire::keymint::HardwareAuthenticatorType::Password as i32,
            1
        );
        assert_eq!(
            kmr_wire::keymint::HardwareAuthenticatorType::Fingerprint as i32,
            2
        );
    }

    /// 认证类参数必须和密钥参数分开：KM4 的 `generateKey` 拿不到 challenge，
    /// 认证链只能另外走 `attestKey`。
    #[test]
    fn attestation_params_are_split_out() {
        let input = vec![
            KeyParam::Algorithm(Algorithm::Ec),
            KeyParam::AttestationChallenge(vec![1, 2, 3, 4]),
            KeyParam::AttestationApplicationId(vec![5, 6]),
            KeyParam::AttestationIdBrand(b"brand".to_vec()),
            KeyParam::Purpose(KeyPurpose::Sign),
            // 看着像认证参数，其实是**密钥的**授权属性，必须留在 generateKey。
            KeyParam::ResetSinceIdRotation,
        ];
        let (key, attest) = split_km4_attestation(&input);
        assert_eq!(key.len(), 3);
        assert_eq!(attest.len(), 3);

        assert_eq!(key[0].tag(), Tag::Algorithm);
        assert_eq!(key[1].tag(), Tag::Purpose);
        assert_eq!(key[2].tag(), Tag::ResetSinceIdRotation);

        // 拆出来的两桶各自保持原来的相对顺序。
        assert_eq!(attest[0].tag(), Tag::AttestationChallenge);
        assert_eq!(attest[1].tag(), Tag::AttestationApplicationId);
        assert_eq!(attest[2].tag(), Tag::AttestationIdBrand);
    }
}
