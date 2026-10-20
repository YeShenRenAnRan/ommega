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

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_wire::keymint::{Algorithm, EcCurve, KeyPurpose};
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
}
