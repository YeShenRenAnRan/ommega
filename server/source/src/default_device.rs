//! 「默认设备 id」：A 端留空时服务端拿它挑 B。
//!
//! A 端远程模式默认不带 `device_id`（模块装好就是这样，面板也不用占位一台设备）。
//! 请求照样发上来，由服务端决定落到哪台 B。
//!
//! **两条链路各有一个默认 id，互不影响**：
//!
//! - `keymint`：attest / sign / decrypt 这类走 KeyMint 的请求。落到 B 端层时优先
//!   用这一台；物理模式下它更是第一顺位。
//! - `soter`：SOTER 转发的请求（init/finish、建料、探针）。SOTER 的层序永远是
//!   B 设备层打头（`handlers::run_soter_task_inner`），所以留空时就直接落到这台。
//!
//! 为什么拆开：这两个链路要的机器往往不是同一台。KeyMint 那条要的是「补丁日期 /
//! 链好看」的那台，SOTER 那条要的是「槽位上有真料、能签」的那台；共用一个默认值
//! 就会互相拖累（改了一个把另一个也带走了）。
//!
//! 请求自带非空 `device_id` 时一律按请求来，这里什么都不做。
//!
//! 没配（空字符串）= 保持原来的行为：由各层自己按负载挑一台在线的。
//!
//! 为什么要落盘：A 端一装好就是留空，几乎所有设备都吃这个默认值。进程重启后如果
//! 退回「按负载挑」，同一轮 SOTER 流程的前后两笔就可能落到不同 B 上 —— 而同一个
//! 槽位的 ASK / AuthKey / 签名必须出自同一台（见 `soter_gate`）。所以运营在控制台
//! 填的那一台必须活过重启。
//!
//! 优先级：环境变量（文件里没有值时当初始值）→ `data/default_device.json`。
//! 文件里还留着老格式 `{"device_id":"..."}` 时，两条链路都用它，升级不改行为。

use std::sync::RwLock;

use serde_json::Value;

/// 落盘位置。跟其它状态文件一样按进程工作目录算（systemd 的 WorkingDirectory=/opt/relay）。
/// `OMMEGA_DEFAULT_DEVICE_FILE` 可覆盖。
/// 只给单测留的路径（运行时不读文件）。
#[cfg(test)]
pub const DEFAULT_PATH: &str = "data/default_device.json";

/// 老的通用环境变量：两条链路都拿它当初始值（兼容既有部署）。
pub const ENV_KEY: &str = "RELAY_DEFAULT_DEVICE_ID";

/// 设备 id 的长度上限。`device-b-xxxxxxxx` 是 17 个字符，留足余量。
const MAX_LEN: usize = 128;

/// 两条链路。别把两者当成可互换的：SOTER 要的是能签的那台，KeyMint 要的是链好看
/// 的那台，共用一台只会在某一边卡住。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Chain {
    Keymint,
    Soter,
}

impl Chain {
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Keymint => "keymint",
            Chain::Soter => "soter",
        }
    }

    fn env_key(self) -> &'static str {
        match self {
            Chain::Keymint => "RELAY_DEFAULT_KEYMINT_DEVICE_ID",
            Chain::Soter => "RELAY_DEFAULT_SOTER_DEVICE_ID",
        }
    }

    /// 只给单测的旧文件解析用。
    #[cfg(test)]
    fn file_key(self) -> &'static str {
        match self {
            Chain::Keymint => "keymint_device_id",
            Chain::Soter => "soter_device_id",
        }
    }
}

#[derive(Clone, Default)]
struct Ids {
    keymint: String,
    soter: String,
}

static IDS: RwLock<Ids> = RwLock::new(Ids {
    keymint: String::new(),
    soter: String::new(),
});

/// 只给单测留的路径解析（运行时不读文件）。
#[cfg(test)]
fn path() -> String {
    std::env::var("OMMEGA_DEFAULT_DEVICE_FILE")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PATH.to_string())
}

/// 某条链路当前的默认设备 id（空字符串 = 没指定，按负载挑）。
pub fn get(chain: Chain) -> String {
    IDS.read()
        .map(|ids| match chain {
            Chain::Keymint => ids.keymint.clone(),
            Chain::Soter => ids.soter.clone(),
        })
        .unwrap_or_else(|poisoned| {
            let ids = poisoned.into_inner();
            match chain {
                Chain::Keymint => ids.keymint.clone(),
                Chain::Soter => ids.soter.clone(),
            }
        })
}

/// 当前两条链路的默认值（控制台一屏展示用）。
pub fn get_all() -> (String, String) {
    (get(Chain::Keymint), get(Chain::Soter))
}

/// 规范化一个设备 id：去空白；空字符串表示「不指定」。
///
/// 只做宽松校验（不允许空白字符、长度上限），因为设备 id 是运营自己给 B 端起的，
/// 有自己的命名习惯；这里拦住的只是明显写错的东西（粘贴进来带空格/换行、超长串）。
fn normalize(raw: &str) -> Result<String, String> {
    let id = raw.trim();
    if id.len() > MAX_LEN {
        return Err(format!("device id too long (>{MAX_LEN} bytes)"));
    }
    if id.chars().any(|c| c.is_whitespace()) {
        return Err("device id must not contain whitespace".to_string());
    }
    Ok(id.to_string())
}

/// 改某条链路的默认值。**只作用于当前进程**：持久化请改 `.env`
/// （`RELAY_DEFAULT_KEYMINT_DEVICE_ID` / `RELAY_DEFAULT_SOTER_DEVICE_ID`）然后重启。
///
/// 不落盘是故意的：默认设备只该有一个写入口，否则又会回到「重启之后到底算哪个」的老问题。
pub fn set(chain: Chain, raw: &str) -> Result<String, String> {
    let id = normalize(raw)?;
    let current = get_all();
    let (keymint, soter) = match chain {
        Chain::Keymint => (id.clone(), current.1),
        Chain::Soter => (current.0, id.clone()),
    };
    if let Ok(mut w) = IDS.write() {
        w.keymint = keymint;
        w.soter = soter;
    }
    tracing::warn!(
        "default_device: {} 只改了内存，重启后会回到 .env 里的值",
        chain.as_str()
    );
    Ok(id)
}

/// 启动时装载一次。环境变量只在文件里没有值时当初始值（环境变量写错了不该
/// 每次重启都把控制台保存的值盖掉）。
/// 装载：**唯一来源是环境变量**。
///
/// 以前这里还会读 `data/default_device.json`，而且「文件里有值就压过环境变量」，
/// 同一份设置两个写入口，排查时分不清到底用的是哪个。8443 那个实例就是因为
/// 没有那份文件，归一回落到代码默认，把 SOTER 请求派到了一台没有 SOTER 能力的 B。
/// 现在文件那套（含 `OMMEGA_DEFAULT_DEVICE_FILE`）完全不用了。
pub fn init() {
    let mut ids = Ids::default();
    for chain in [Chain::Keymint, Chain::Soter] {
        let from_env = std::env::var(chain.env_key())
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| std::env::var(ENV_KEY).ok())
            .and_then(|v| normalize(&v).ok())
            .unwrap_or_default();
        match chain {
            Chain::Keymint => ids.keymint = from_env,
            Chain::Soter => ids.soter = from_env,
        }
    }
    if ids.keymint.is_empty() && ids.soter.is_empty() {
        tracing::info!(
            "default_device: 两条链路都未指定\
             （RELAY_DEFAULT_KEYMINT_DEVICE_ID / RELAY_DEFAULT_SOTER_DEVICE_ID 都没设），\
             A 端留空时按负载挑在线 B"
        );
    } else {
        tracing::info!(
            "default_device: keymint={:?} soter={:?}（来自 .env）",
            ids.keymint,
            ids.soter
        );
    }
    if let Ok(mut w) = IDS.write() {
        *w = ids;
    }
}

/// 只给单测用：验证旧文件的解析不回归（运行时不读文件了）。
#[cfg(test)]
fn read_file(file_path: &str) -> Ids {
    let Ok(text) = std::fs::read_to_string(file_path) else {
        return Ids::default();
    };
    // 文件格式就是 `{"keymint_device_id":"...","soter_device_id":"..."}`；
    // 老版本只有 `device_id`，那就两条都用它（升级不改行为）。
    // 解析失败就当没配，不要因此起不来。
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("default_device: {file_path} 解析失败（{e}），当作未指定");
            return Ids::default();
        }
    };
    let pick = |key: &str| {
        normalize(v.get(key).and_then(|x| x.as_str()).unwrap_or("")).unwrap_or_default()
    };
    let legacy = pick("device_id");
    Ids {
        keymint: {
            let k = pick(Chain::Keymint.file_key());
            if k.is_empty() {
                legacy.clone()
            } else {
                k
            }
        },
        soter: {
            let s = pick(Chain::Soter.file_key());
            if s.is_empty() {
                legacy
            } else {
                s
            }
        },
    }
}

/// 把一个 A 端请求的 `device_id` 按链路补齐成「实际要用的那台」。
///
/// 语义就是用户定下的那条：A 端留空 + 服务端配了这条链路的默认设备 = **完全等同于
/// A 端自带了那个 id**。所以这里在入口处就把 body 归一，而不是在某一层里临时拿默认值
/// —— 归一之后，physical / serverbox 两种模式的层序、StrongBox 分流、身份查找、
/// 队列派发、SOTER 的槽位钉/会话路由看见的都是同一台具体设备，行为与「A 端真填了
/// 这个 id」一字不差。
///
/// 请求已经带了非空 id 就原样返回（哪怕那台离线）：那是调用方点名的机器，回退逻辑
/// 自己会处理；这里不能拿默认值把点名的请求截走。
///
/// 没配默认值时原样返回，空 id 继续走各层的按负载挑选。
pub fn fill_in_body(chain: Chain, body: &Value) -> Value {
    let raw = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !raw.is_empty() {
        return body.clone();
    }
    let id = get(chain);
    if id.is_empty() {
        return body.clone();
    }
    let mut out = body.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("device_id".to_string(), Value::String(id));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 这两个用例都靠 `OMMEGA_DEFAULT_DEVICE_FILE` 指路径（进程级），并行跑会互相盖，
    /// 所以串行。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 每个用例用自己的一份文件：这些测试并行跑，共用路径会互相盖。
    fn with_file(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("ommega-dd-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("default_device.json");
        let path = file.to_str().unwrap().to_string();
        std::env::set_var("OMMEGA_DEFAULT_DEVICE_FILE", &path);
        reset_empty();
        path
    }

    fn reset_empty() {
        if let Ok(mut w) = IDS.write() {
            w.keymint.clear();
            w.soter.clear();
        }
    }

    #[test]
    fn normalize_trims_and_rejects_junk() {
        assert_eq!(normalize("  device-b-1  "), Ok("device-b-1".to_string()));
        assert_eq!(normalize(""), Ok(String::new()));
        assert!(normalize("device b-1").is_err());
        assert!(normalize(&"x".repeat(MAX_LEN + 1)).is_err());
    }

    #[test]
    fn chains_are_independent() {
        let _g = TEST_LOCK.lock().unwrap();
        let file = with_file("independent");

        assert_eq!(set(Chain::Keymint, "device-b-key").unwrap(), "device-b-key");
        assert_eq!(get(Chain::Keymint), "device-b-key");
        // 设 keymint 不动 soter。
        assert_eq!(get(Chain::Soter), "");

        assert_eq!(set(Chain::Soter, "device-b-sot").unwrap(), "device-b-sot");
        assert_eq!(get(Chain::Soter), "device-b-sot");
        // 设 soter 也不动 keymint。
        assert_eq!(get(Chain::Keymint), "device-b-key");

        // 落盘、重读：两条都还在。
        let ids = read_file(&file);
        assert_eq!(ids.keymint, "device-b-key");
        assert_eq!(ids.soter, "device-b-sot");

        // 入口归一：keymint 的请求拿 keymint 那台，soter 的拿 soter 那台。
        let empty = serde_json::json!({ "challenge": "AA", "device_id": "" });
        assert_eq!(
            fill_in_body(Chain::Keymint, &empty)["device_id"],
            "device-b-key"
        );
        assert_eq!(
            fill_in_body(Chain::Soter, &empty)["device_id"],
            "device-b-sot"
        );

        // 请求自带 id：两条链路都按请求来，不被默认值截走。
        let named = serde_json::json!({ "device_id": "device-b-own" });
        assert_eq!(
            fill_in_body(Chain::Keymint, &named)["device_id"],
            "device-b-own"
        );
        assert_eq!(
            fill_in_body(Chain::Soter, &named)["device_id"],
            "device-b-own"
        );

        // 清掉一条不影响另一条。
        assert_eq!(set(Chain::Keymint, "").unwrap(), "");
        assert_eq!(get(Chain::Keymint), "");
        assert_eq!(get(Chain::Soter), "device-b-sot");
        assert_eq!(fill_in_body(Chain::Keymint, &empty)["device_id"], "");

        let _ = std::fs::remove_dir_all(Path::new(&file).parent().unwrap());
    }

    #[test]
    fn legacy_single_id_applies_to_both() {
        let _g = TEST_LOCK.lock().unwrap();
        let file = with_file("legacy");
        std::fs::write(&file, br#"{"device_id":"device-b-old"}"#).unwrap();
        let ids = read_file(&file);
        assert_eq!(ids.keymint, "device-b-old");
        assert_eq!(ids.soter, "device-b-old");

        // 新格式优先，不再看 device_id。
        std::fs::write(
            &file,
            br#"{"device_id":"device-b-old","keymint_device_id":"device-b-k","soter_device_id":"device-b-s"}"#,
        )
        .unwrap();
        let ids = read_file(&file);
        assert_eq!(ids.keymint, "device-b-k");
        assert_eq!(ids.soter, "device-b-s");

        let _ = std::fs::remove_dir_all(Path::new(&file).parent().unwrap());
    }
}
