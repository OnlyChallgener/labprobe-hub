//! RDPI 特征库的出站同步。
//!
//! 以前是 Hub 用 paramiko **反向 SSH 进路由器**去 `cat` 这个文件，host 和 SSH 端口
//! 还是写在源码默认值里。路由器一重拨，两个都变，特征库立刻读不到 —— 真机
//! 2026-09-20 就是这样断的，而且 agent 本来就跑在路由器上、走出站隧道，根本不需要
//! 谁进来连它。
//!
//! 这里负责「读 + 推副本」（内容变了就推，没变但推得太久也重推），也负责 Hub 下发的
//! 那一次整库写入。哪些算自定义特征的判断留在 Hub，免得两边各写一套规则然后慢慢长得
//! 不一样。

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// 写入成功后要把「什么时候推的」也记下来。
fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

/// 固件的 RDPI 库；和 Hub 侧 `REMOTE_DB_PATH` 保持一致。
pub const ROUTER_DB_PATH: &str = "/usr/share/ndpi/db.default.json";
/// 写入前的事务备份。`.bak` 只是给运维看的，回滚必须用刚拍下的这一份。
const ROLLBACK_PATH: &str = "/tmp/db.default.json.rollback";
const TEMP_PATH: &str = "/tmp/db.default.json.tmp";
const BACKUP_PATH: &str = "/usr/share/ndpi/db.default.json.bak";

/// 上一次成功推送时文件的指纹。0 = 从没推过。
static PUSHED_FINGERPRINT: AtomicU64 = AtomicU64::new(0);
/// 上一次成功推送的时刻。Hub 把超过 15 分钟的副本当作没有，所以「文件没变」不等于
/// 「不用推」—— 真机 2026-09-21 就是这样：改了两次特征库之后安静了 45 分钟，卡片
/// 直接变成读不到，因为中继觉得没东西可推。
static LAST_PUSHED_AT: AtomicU64 = AtomicU64::new(0);
const KEEP_FRESH_SECONDS: u64 = 600;

/// 该不该推一份副本给 Hub。
fn should_push(mark: u64, pushed_mark: u64, last_pushed_at: u64, now: u64) -> bool {
    mark != pushed_mark || now.saturating_sub(last_pushed_at) >= KEEP_FRESH_SECONDS
}

/// FNV-1a。只用来判断「文件有没有变」，不当校验和用。
fn fingerprint(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

/// 内容没变、但上一次成功推送已经隔了太久，也要重推 —— 见 `should_push`。
pub fn changed_snapshot(now_epoch: u64) -> Result<Option<Value>> {
    let text = std::fs::read_to_string(ROUTER_DB_PATH)?;
    let mark = fingerprint(&text);
    if !should_push(
        mark,
        PUSHED_FINGERPRINT.load(Ordering::Relaxed),
        LAST_PUSHED_AT.load(Ordering::Relaxed),
        now_epoch,
    ) {
        return Ok(None);
    }
    let db: Value = serde_json::from_str(&text)?;
    let apps = db.get("apps").cloned().unwrap_or_else(|| json_empty_array());
    // `dbText` 是文件的原文。Hub 只拿 `apps` 合并再序列化会丢掉顶层的 `version`，
    // 所以写入要基于这一份；`apps` 留给卡片算数字，也兼容还没带 `dbText` 的中继。
    Ok(Some(json!({
        "apps": apps,
        "dbText": text,
        "readAtEpoch": now_epoch,
        "fingerprint": mark,
    })))
}

fn json_empty_array() -> Value {
    Value::Array(Vec::new())
}

/// 只有 Hub 收下了才记账，失败下一轮会自己重推。
pub fn note_pushed(mark: u64, now_epoch: u64) {
    PUSHED_FINGERPRINT.store(mark, Ordering::Relaxed);
    LAST_PUSHED_AT.store(now_epoch, Ordering::Relaxed);
}

fn shell(command: &str) -> Result<String> {
    let output = Command::new("sh")
        .args(&["-c", command])
        .output()
        .with_context(|| format!("run {command}"))?;
    if !output.status.success() {
        bail!(
            "{command} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Hub 那份副本是不是已经旧了。`expected == 0` 表示 Hub 没给基线，按原样写入。
fn write_is_stale(expected: u64, current: u64) -> bool {
    expected != 0 && expected != current
}

pub fn execute(action: &str, payload: &Value) -> Value {
    match action {
        "write_db" => write_db(payload),
        other => Err(anyhow!("unknown rdpi action: {other}")),
    }
    .unwrap_or_else(|error| {
        json!({"ok": false, "errorCode": "rdpi_write_failed", "error": format!("{error:#}")})
    })
}

/// 落地 Hub 合并好的整库文本：备份 → 写入 → 逐字节回读核对 → 热重载，任何一步失败都回滚。
///
/// 校验用字节相等而不是「解析后差不多」：固件读的是这个文件本身，截断半个 JSON
/// 或者少一个 `version` 都会让它加载失败，而这两种在解析比较里都看不出来。
fn write_db(payload: &Value) -> Result<Value> {
    let db_text = payload
        .get("dbText")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing dbText"))?;
    let expected = payload
        .get("expectedFingerprint")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let target: Value = serde_json::from_str(db_text).context("特征库文本不是合法 JSON")?;
    let apps = target
        .get("apps")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("特征库文本没有 apps 数组"))?;
    if apps.is_empty() {
        bail!("拒绝写入空特征库");
    }

    let current = std::fs::read_to_string(ROUTER_DB_PATH).with_context(|| format!("read {ROUTER_DB_PATH}"))?;
    let current_mark = fingerprint(&current);
    if write_is_stale(expected, current_mark) {
        // 星耀家 APP 也在往同一个文件里写自定义特征。拿旧副本合并会把对方的新条目
        // 覆盖掉，所以这一笔不做，并且强制下一轮把真内容重新推给 Hub。
        PUSHED_FINGERPRINT.store(0, Ordering::Relaxed);
        return Ok(json!({
            "ok": false,
            "errorCode": "stale_library",
            "error": "路由器上的特征库在这份副本之后又被改过，本次写入已取消，请重新点一次",
            "fingerprint": current_mark,
        }));
    }

    let restore = || -> Result<()> {
        shell(&format!(
            "cp {ROLLBACK_PATH} {ROUTER_DB_PATH} && ubus -t 3 send rdpi_reinit"
        ))?;
        Ok(())
    };

    let staged = std::fs::write(TEMP_PATH, db_text.as_bytes())
        .map_err(|error| anyhow!("写入 {TEMP_PATH} 失败: {error}"))
        .and_then(|_| {
            shell(&format!(
                "cp {ROUTER_DB_PATH} {BACKUP_PATH} && cp {ROUTER_DB_PATH} {ROLLBACK_PATH}"
            ))
            .map_err(|error| anyhow!("备份当前特征库失败: {error:#}"))
        });
    if let Err(failure) = staged {
        // 事务备份还没拍到，真文件一个字都没动过，清掉暂存就行。
        let _ = shell(&format!("rm -f {TEMP_PATH}"));
        return Err(failure);
    }
    if let Err(error) = shell(&format!("cp {TEMP_PATH} {ROUTER_DB_PATH}")) {
        restore().map_err(|rollback_error| anyhow!("{error:#}; 回滚也失败: {rollback_error:#}"))?;
        return Err(error);
    }
    let mismatch = match std::fs::read_to_string(ROUTER_DB_PATH) {
        Ok(text) if text == db_text => None,
        Ok(_) => Some(anyhow!("{ROUTER_DB_PATH} 回读内容与写入内容不一致")),
        Err(error) => Some(anyhow!("回读 {ROUTER_DB_PATH} 失败: {error}")),
    };
    if let Some(failure) = mismatch {
        restore().map_err(|rollback_error| anyhow!("{failure:#}; 回滚也失败: {rollback_error:#}"))?;
        return Err(failure);
    }
    if let Err(error) = shell("ubus -t 3 send rdpi_reinit") {
        let failure = anyhow!("RDPI 热重载失败: {error:#}");
        restore().map_err(|rollback_error| anyhow!("{failure:#}; 回滚也失败: {rollback_error:#}"))?;
        return Err(failure);
    }
    let _ = shell(&format!("rm -f {TEMP_PATH} {ROLLBACK_PATH}"));

    let mark = fingerprint(db_text);
    note_pushed(mark, now_epoch());
    Ok(json!({
        "ok": true,
        "apps": apps.len(),
        "fingerprint": mark,
        "message": "已写入路由器并触发热重载",
    }))
}

#[cfg(test)]
mod tests {
    use super::{fingerprint, should_push, write_is_stale};

    #[test]
    fn an_unchanged_library_still_gets_resent_before_the_hub_drops_it() {
        // 真机 2026-09-21：改完特征库后 45 分钟没人再动文件，中继不再推，Hub 的
        // 副本过了 15 分钟被判过期，卡片变成「读不到」。
        assert!(should_push(7, 7, 1_000, 1_700));
        assert!(!should_push(7, 7, 1_000, 1_300));
        assert!(should_push(8, 7, 1_000, 1_010));
        // 从没推过。
        assert!(should_push(7, 0, 0, 1));
    }

    #[test]
    fn same_bytes_hash_the_same_way() {
        assert_eq!(fingerprint("{\"apps\":[]}"), fingerprint("{\"apps\":[]}"));
    }

    #[test]
    fn one_changed_byte_flips_the_fingerprint() {
        // 只比 app 数量、不比内容的话，热重载会以为没变。
        assert_ne!(fingerprint("{\"apps\":[1]}"), fingerprint("{\"apps\":[2]}"));
    }

    #[test]
    fn empty_input_still_produces_a_fingerprint() {
        assert_eq!(fingerprint(""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn a_write_without_a_baseline_is_never_stale() {
        assert!(!write_is_stale(0, 42));
    }

    #[test]
    fn a_write_against_a_moved_library_is_stale() {
        // 星耀家 APP 加了一条自定义特征，指纹就变了；这一笔必须取消。
        assert!(write_is_stale(42, 43));
        assert!(!write_is_stale(42, 42));
    }
}
