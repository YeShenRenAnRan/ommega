//! 软件 SOTER TA。
//!
//! 原厂 `vendor.qti.hardware.soter.ISoter/default` 只是 TEE 里那个 applet 的薄代理，
//! applet 起不来时整族调用一律 -20（PKG110 / 安卓 15 实测），宿主和应用一起哑，产线
//! 工具（工程模式那页）也跟着报红。这里把服务名原样接过来，用我们自己的软件实现应答，
//! 调用方（soterserver、oplus 的 cryptoeng）一行都不用改。
//!
//! 号码表跟宿主 dex 里 `ISoter$Stub$Proxy` 对过：1/3/4/5/7/8/9/10/11/12/13 是运行时
//! 那 11 个方法；2/6/14 原厂 HAL 是空号，只有产线 provisioning（cryptoeng）会调，
//! 我们用同一套 ASK 顶上，工程模式的 SOTER key 就看 14 号那一笔是不是 0。

use rsbinder::{
    hub, Binder, Interface, Parcel, Remotable, Result as BinderResult, Stability, TransactionCode,
};

use crate::hook::soter;
use crate::hook::soter_local::{self, Answer};
use crate::hook::soter_relay;

pub const SERVICE_NAME: &str = "vendor.qti.hardware.soter.ISoter/default";
const DESCRIPTOR: &str = "vendor.qti.hardware.soter.ISoter";

/// 原厂 HAL 声明的 14 个号码。
/// 号码表：**4 槽排布（2 / 6 / 14 空号）**，这是 NX721J 上 soterserver 实际发的形状。
/// 依据：实测它发 code 5 / 9 时只带 uid（= generateAskKeyPair / hasAskAlready）；
/// APK 里那份 1–11 连号的 `ISoter.java` 是没被用到的类，按它读会丢 alias。
const EXPORT_ASK_PUBLIC_KEY: u32 = 1;
const EXPORT_ATTK_PUBLIC_KEY: u32 = 2;
const EXPORT_AUTH_KEY_PUBLIC_KEY: u32 = 3;
const FINISH_SIGN: u32 = 4;
const GENERATE_ASK_KEY_PAIR: u32 = 5;
const GENERATE_ATTK_KEY_PAIR: u32 = 6;
const GENERATE_AUTH_KEY_PAIR: u32 = 7;
const GET_DEVICE_ID: u32 = 8;
const HAS_ASK_ALREADY: u32 = 9;
const HAS_AUTH_KEY: u32 = 10;
const INIT_SIGN: u32 = 11;
const REMOVE_ALL_UID_KEY: u32 = 12;
const REMOVE_AUTH_KEY: u32 = 13;
const VERIFY_ATTK_KEY_PAIR: u32 = 14;

/// servicemanager 注册时会用这个 code 来问“你这个 binder 是什么接口”，拿不到名字就
/// 记成空列表，之后 vendor 客户端按（名字 + 接口名）取服务一律 null。
const INTERFACE_TRANSACTION: u32 = 0x5f4e_5446;

/// 不同设备 / 不同 SoterService 版本的 HAL 号码排布不一样：
/// - **4 槽排布（2/6/14 空号）**：NX721J 这类，实测 soterserver 发 9/5 时只带 uid；
/// - **1–11 连号**：APK 里另一种 `ISoter`，9 是 initSign、7 是 hasAskAlready。
///
/// 两者对同一个号的含义相反，光看 code 分不出来。但**参数长度能分**：首笔
/// `hasAskAlready` 在 4 槽里是 9、连号里是 7，而且都只带一个 int（4 字节）。
/// 于是第一次见到它就定下布局并缓存，之后把连号的号换算成 4 槽的规范号，
/// 后续所有逻辑只用一套写法。
static LAYOUT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const LAYOUT_UNKNOWN: u8 = 0;
const LAYOUT_14: u8 = 1;
const LAYOUT_11: u8 = 2;

fn note_layout(code: u32, avail: usize) {
    use std::sync::atomic::Ordering;
    if LAYOUT.load(Ordering::Relaxed) != LAYOUT_UNKNOWN {
        return;
    }
    match (code, avail) {
        // hasAskAlready / generateAskKeyPair：两种排布里都只带一个 int，号却不同。
        (9, 4) | (5, 4) => {
            LAYOUT.store(LAYOUT_14, Ordering::Relaxed);
        }
        (7, 4) | (4, 4) => {
            LAYOUT.store(LAYOUT_11, Ordering::Relaxed);
        }
        _ => {}
    }
}

/// 把任意排布的号码换成 4 槽的规范号（后面的逻辑只认这套）。
fn canonical_code(code: u32, avail: usize) -> u32 {
    use std::sync::atomic::Ordering;
    note_layout(code, avail);
    if LAYOUT.load(Ordering::Relaxed) != LAYOUT_11 {
        return code;
    }
    match code {
        2 => 3,   // exportAuthKeyPublicKey
        3 => 4,   // finishSign
        4 => 5,   // generateAskKeyPair
        5 => 7,   // generateAuthKeyPair
        6 => 8,   // getDeviceId
        7 => 9,   // hasAskAlready
        8 => 10,  // hasAuthKey
        9 => 11,  // initSign
        10 => 12, // removeAllUidKey
        11 => 13, // removeAuthKey
        other => other,
    }
}

fn op_name(code: u32) -> &'static str {
    match code {
        EXPORT_ASK_PUBLIC_KEY => "exportAskPublicKey",
        EXPORT_ATTK_PUBLIC_KEY => "exportAttkPublicKey",
        EXPORT_AUTH_KEY_PUBLIC_KEY => "exportAuthKeyPublicKey",
        FINISH_SIGN => "finishSign",
        GENERATE_ASK_KEY_PAIR => "generateAskKeyPair",
        GENERATE_ATTK_KEY_PAIR => "generateAttkKeyPair",
        GENERATE_AUTH_KEY_PAIR => "generateAuthKeyPair",
        GET_DEVICE_ID => "getDeviceId",
        HAS_ASK_ALREADY => "hasAskAlready",
        HAS_AUTH_KEY => "hasAuthKey",
        INIT_SIGN => "initSign",
        REMOVE_ALL_UID_KEY => "removeAllUidKey",
        REMOVE_AUTH_KEY => "removeAuthKey",
        VERIFY_ATTK_KEY_PAIR => "verifyAttkKeyPair",
        _ => "unknown",
    }
}

/// `int xxx(out byte[] data)` 那一类：返回值 + AIDL 原生 byte[]。
/// 不是 `SoterBufferReturn` parcelable —— cryptoeng（C++ ndk 客户端）的反汇编里就是
/// 一个 vector<uint8_t> out 加一个 int 返回，按 parcelable 拼它会在解析时越界崩。
///
/// 除这一类，其余全按 parcelable 给：soterserver、SoterChecker、工程模式那页都是
/// Java 客户端，读的就是 `SoterBufferReturn`（[非空标记][总长][byte[]][dataLength]）。
///
/// 以前只认 soterserver 一个进程名，其余一律给原生形状 —— 结果所有第三方/自带的 Java
/// 检测器都把数据解成垃圾（2026-10-20 SoterChecker 报告：`len=825 data=0`、
/// `short blob len=0`）。反过来判断之后，「给原生」变成一个要手动点名的例外。
///
/// 名单：环境变量 `OMMEGA_SOTER_NATIVE_CALLERS`（逗号分隔，按 cmdline 包含匹配）。
/// 空字符串 = 全部走 parcelable。
fn caller_wants_parcelable() -> bool {
    let pid = rsbinder::get_calling_pid();
    // 拿不到调用者就别赌：Java 客户端占绝大多数，给原生形状只会把人家数据弄坏。
    if pid <= 0 {
        return true;
    }
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return true;
    };
    let name = raw.split(|byte| *byte == 0).next().unwrap_or_default();
    !is_native_caller(name)
}

/// 缺省走原生形状的那几个（进程名包含匹配）。oplus 的 cryptoeng 是产线/CDK 那种工具，
/// 平时不出现；出现时给它原生形状，否则它按 parcelable 解析会越界崩。
const DEFAULT_NATIVE_CALLERS: &str = "cryptoeng";

fn is_native_caller(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let list = std::env::var("OMMEGA_SOTER_NATIVE_CALLERS")
        .unwrap_or_else(|_| DEFAULT_NATIVE_CALLERS.to_string());
    list.split(',')
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .any(|pattern| contains_bytes(name, pattern.as_bytes()))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// `int xxx(out SoterBufferReturn)` 那一类：按调用方选形状。
fn write_bytes_reply(reply: &mut Parcel, data: &[u8], code: i32) -> BinderResult<()> {
    let parcelable = caller_wants_parcelable();
    log::info!(
        "event=soterta shape parcelable={parcelable} code={code} data={}",
        data.len()
    );
    reply.write_i32(code)?;
    if parcelable {
        // AIDL 的 parcelable 只有 `[非空标记][总长][byte[]][dataLength]`，里面的 resultCode
        // 就是**方法返回值**（上一行）那一格，parcelable 里**没有**第二份。
        //
        // 1.7.4 曾经给 Android 17 多加过一格 resultCode（`[总长][resultCode][byte[]][dataLength]`），
        // 那是错的：总长后面直接就是 byte[]，多写 4 字节会把 byte[] 的长度顶成 0，
        // 读端拿到 `len=825 data=0`（SoterChecker 的 T3 / C1 / X 三条 fail 就是这么来的）。
        reply.write_i32(1)?;
        let padded = (data.len() + 3) & !3;
        reply.write_i32((12 + padded) as i32)?;
        reply.write(&data.to_vec())?;
        reply.write_i32(data.len() as i32)?;
    } else {
        reply.write(&data.to_vec())?;
    }
    Ok(())
}

/// `SoterInitReturn`：`[非空标记][总长=16][status][session]`，两家 AIDL 一样。
/// 注意这个方法是**返回 parcelable 本身**，没有“方法返回值”那一格。
fn write_init_return(reply: &mut Parcel, status: i32, session: i64) -> BinderResult<()> {
    reply.write_i32(1)?;
    reply.write_i32(16)?;
    reply.write_i32(status)?;
    reply.write_i64(session)?;
    Ok(())
}

struct SoterTa;

impl Remotable for SoterTa {
    fn descriptor() -> &'static str {
        DESCRIPTOR
    }

    fn on_transact(
        &self,
        code: TransactionCode,
        reader: &mut Parcel,
        reply: &mut Parcel,
    ) -> BinderResult<()> {
        log::info!("event=soterta code={code} op={}", op_name(code));
        if code == INTERFACE_TRANSACTION {
            reply.write(&DESCRIPTOR.to_string())?;
            return Ok(());
        }
        // AIDL 的回复第一个 int 是 status（0 = OK）。Java 的 Stub$Proxy 每条回复都先
        // readException() 读它；rsbinder 做服务端不写这一格，后面所有字段就会整体
        // 错位 4 字节（soterserver 把方法返回值当 status、把非空标记当返回值，
        // exportAsk 的 exportData 就解不出来，Duck/微信卡在 askModel）。
        reply.write_i32(0)?;
        // 号码先归一到「4 槽规范号」：不同设备的排布不一样（见 LAYOUT）。
        let code = canonical_code(code, reader.data_avail());
        // 先按 AIDL 定义把入参读干净：读错位的话后面拿到的 uid/alias 全是垃圾。
        let mut uid = None;
        let mut alias = None;
        let mut challenge = None;
        let mut session = None;
        match code {
            EXPORT_ASK_PUBLIC_KEY
            | GENERATE_ASK_KEY_PAIR
            | HAS_ASK_ALREADY
            | REMOVE_ALL_UID_KEY
            | EXPORT_ATTK_PUBLIC_KEY
            | GENERATE_ATTK_KEY_PAIR => {
                uid = reader.read::<i32>().ok();
            }
            EXPORT_AUTH_KEY_PUBLIC_KEY
            | GENERATE_AUTH_KEY_PAIR
            | HAS_AUTH_KEY
            | REMOVE_AUTH_KEY => {
                uid = reader.read::<i32>().ok();
                alias = reader.read::<String>().ok();
            }
            INIT_SIGN => {
                uid = reader.read::<i32>().ok();
                alias = reader.read::<String>().ok();
                challenge = reader.read::<String>().ok();
            }
            FINISH_SIGN => {
                session = reader.read::<i64>().ok();
            }
            _ => {}
        }
        log::info!(
            "event=soterta args code={code} uid={uid:?} alias={alias:?} challenge_len={} session={session:?}",
            challenge.as_deref().map(|c| c.len()).unwrap_or(0)
        );

        // 产线 provisioning 那三个（原厂 HAL 是空号）：工程模式的 SOTER key 就看 14 号。
        match code {
            VERIFY_ATTK_KEY_PAIR => {
                reply.write_i32(0)?;
                return Ok(());
            }
            GENERATE_ATTK_KEY_PAIR => {
                reply.write_i32(0)?;
                return Ok(());
            }
            EXPORT_ATTK_PUBLIC_KEY => {
                // ATTK 用我们自己的 ASK 顶：软件 TA 里 ASK 兼 ATTK，公钥就是那一把。
                let document = soter_local::ask_public_document(uid.unwrap_or(-1));
                write_bytes_reply(reply, &document, 0)?;
                return Ok(());
            }
            _ => {}
        }

        // 剩下的 11 个号码走本地软件 TA：ASK/AuthKey/会话全部复用注入侧那套实现，
        // 这样接管和注入两条路签出来的东西是同一种，不会出现两种假链。
        let call = soter::SoterCall {
            hal: true,
            hidl: false,
            has_return_code: true,
            code,
            wire_code: code,
            op: op_name(code),
            uid,
            alias: alias.clone(),
            challenge: challenge.clone(),
            session,
            key: None,
            caller_uid: None,
            data_size: 0,
        };
        // 先问 daemon（它按配置决定是转 B 端真 TEE、走服务端还是本地兜底）；
        // 问不到才有本地自签那条退路。直接调 soter_local 的话永远只能自签，
        // 微信拿这把 ASK 去腾讯验证一定被拒（就是“系统错误”）。
        match soter_relay::answer(&call) {
            Some(Answer::Code(code)) => {
                log::info!("event=soterta reply code={code}");
                reply.write_i32(code)?;
            }
            Some(Answer::Buffer { code, data }) => {
                log::info!(
                    "event=soterta reply code={code} data={}",
                    data.as_ref().map(|d| d.len()).unwrap_or(0)
                );
                write_bytes_reply(reply, data.as_deref().unwrap_or(&[]), code)?;
            }
            Some(Answer::Init { status, session }) => {
                log::info!("event=soterta reply init status={status} session={session}");
                // initSign 返回的是 parcelable 本身，没有「方法返回值」那一格。
                write_init_return(reply, status, session)?;
            }
            None => {
                log::warn!("event=soterta reply none (no answer for this call)");
                // 没有真身份可报、或参数不够：回一个明确的错误码，别回 0 让调用方
                // 拿着空数据继续跑。NOT_FOUND 跟真机一样。
                if matches!(
                    code,
                    EXPORT_ASK_PUBLIC_KEY | EXPORT_AUTH_KEY_PUBLIC_KEY | FINISH_SIGN
                ) {
                    write_bytes_reply(reply, &[], -4)?;
                } else {
                    reply.write_i32(-4)?;
                }
            }
        }
        Ok(())
    }

    fn on_dump(&self, _writer: &mut dyn std::io::Write, _args: &[String]) -> BinderResult<()> {
        Ok(())
    }
}

/// 起服务并常驻。返回即表示服务名已经抢到手。
///
/// `driver` 决定注册到哪个 servicemanager：vendor 的 AIDL HAL 习惯落在
/// `/dev/vndbinder`（vndservicemanager），应用侧的 Java 客户端只看 `/dev/binder`。
pub fn serve(driver: &str) -> anyhow::Result<()> {
    // 第二个参数是 binder 线程池上限。传 0 会让驱动把上限设成 0：framework 那边会报
    // 「Thread Pool max thread count is 0. Cannot cache binder as linkToDeath cannot be
    // implemented」，而且 looper 会在十几秒后被驱动拒掉、进程静默退出（保活又拉起来，
    // 就是现场那个每 20 秒换一个 pid 的抖动）。这里给默认 15。
    rsbinder::ProcessState::init(driver, 15)
        .map_err(|error| anyhow::anyhow!("binder init on {driver} failed: {error}"))?;
    let binder = Binder::new_with_stability(SoterTa, Stability::Vintf);
    hub::add_service(SERVICE_NAME, binder.as_binder())?;
    log::info!("event=soterta registered {SERVICE_NAME} on {driver}");
    // 连 daemon 的 RPC 放后台：它要等 socket 就绪（最长几十秒），不能挡着注册
    // —— soterta.sh 在启动后一秒就看服务名在不在，迟一步就被当成失败回滚掉。
    std::thread::spawn(|| match crate::ipc::install_direct_rpc_session() {
        Ok(()) => log::info!("event=soterta daemon RPC ready"),
        Err(error) => {
            log::warn!("event=soterta daemon RPC unavailable ({error:#}); local signing only")
        }
    });
    // 注册完就得有人处理事务：主线程进 binder 事件循环（rsbinder 的 join_thread_pool）
    rsbinder::ProcessState::join_thread_pool()?;
    Ok(())
}
