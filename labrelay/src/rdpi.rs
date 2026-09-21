//! RDPI 特征库的出站同步。
//!
//! 以前是 Hub 用 paramiko **反向 SSH 进路由器**去 `cat` 这个文件
//! （`rdpi_signature_service.py:25-30` 里 host/port 还是写死的默认值）。路由器一重拨，
//! 公网 IP 和 SSH 端口就全变，特征库立刻读不到 —— 真机 2026-09-20 就是这样断的，
//! 而且 agent 本来就跑在路由器上、走出站隧道，根本不需要谁进来连它。
//!
//! 这里只负责「读 + 变了才推」。哪些算自定义特征的判断留在 Hub，免得两边各写一套
//! 规则然后慢慢长得不一样。

use anyhow::Result;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

/// 固件的 RDPI 库；和 Hub 侧 `REMOTE_DB_PATH` 保持一致。
pub const ROUTER_DB_PATH: &str = "/usr/share/ndpi/db.default.json";

/// 上一次成功推送时文件的指纹。0 = 从没推过。
static PUSHED_FINGERPRINT: AtomicU64 = AtomicU64::new(0);

/// FNV-1a。只用来判断「文件有没有变」，不当校验和用。
fn fingerprint(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

/// 内容没变就返回 `None`，调用方连 HTTP 都不必发。
pub fn changed_snapshot(now_epoch: u64) -> Result<Option<Value>> {
    let text = std::fs::read_to_string(ROUTER_DB_PATH)?;
    let mark = fingerprint(&text);
    if mark == PUSHED_FINGERPRINT.load(Ordering::Relaxed) {
        return Ok(None);
    }
    let db: Value = serde_json::from_str(&text)?;
    let apps = db.get("apps").cloned().unwrap_or_else(|| json_empty_array());
    Ok(Some(serde_json::json!({
        "apps": apps,
        "readAtEpoch": now_epoch,
        "fingerprint": mark,
    })))
}

fn json_empty_array() -> Value {
    Value::Array(Vec::new())
}

/// 只有 Hub 收下了才记账，失败下一轮会自己重推。
pub fn note_pushed(mark: u64) {
    PUSHED_FINGERPRINT.store(mark, Ordering::Relaxed);
}

pub fn pushed_fingerprint() -> u64 {
    PUSHED_FINGERPRINT.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::fingerprint;

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
}
