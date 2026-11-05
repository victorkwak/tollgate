//! Hook timings from git's trace2 event stream (L20).
//!
//! The bench runs each `git commit` with `GIT_TRACE2_EVENT=<file>`. git
//! writes a `child_start` event (`child_class` `hook`, `hook_name`) when
//! it starts a hook and a `child_exit` event with `t_rel` (seconds from
//! start to exit, measured by git) and the exit code when the hook ends.
//! So a hook's time is "hook start to allow" as git sees it, with no
//! tollgate code measuring itself. Only events of the top-level git (a
//! `sid` without `/`) count: git commands that a hook runs inherit the
//! variable and write to the same file.

use std::collections::BTreeMap;

/// One hook run.
#[derive(Debug, Clone, PartialEq)]
pub struct HookTime {
    /// Hook name (`pre-commit`, `post-commit`, ...).
    pub hook: String,
    /// Start to exit, in milliseconds.
    pub ms: f64,
    /// Exit code.
    pub code: i64,
}

/// The hooks the top-level git ran, in the order they ended.
#[must_use]
pub fn hook_times(text: &str) -> Vec<HookTime> {
    let mut started: BTreeMap<i64, String> = BTreeMap::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if ev["sid"].as_str().is_none_or(|sid| sid.contains('/')) {
            continue;
        }
        let Some(child) = ev["child_id"].as_i64() else {
            continue;
        };
        match ev["event"].as_str() {
            Some("child_start") if ev["child_class"] == "hook" => {
                if let Some(name) = ev["hook_name"].as_str() {
                    started.insert(child, name.to_owned());
                }
            }
            Some("child_exit") => {
                if let (Some(hook), Some(secs)) = (started.remove(&child), ev["t_rel"].as_f64()) {
                    out.push(HookTime {
                        hook,
                        ms: secs * 1000.0,
                        code: ev["code"].as_i64().unwrap_or(-1),
                    });
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_runs_of_the_top_level_git_only_l20() {
        // As git 2.56 writes them (trimmed): a pre-commit hook, an inner
        // git of that hook with a hook of its own, a non-hook child, and
        // post-commit.
        let text = r#"{"event":"version","sid":"S","evt":"4","exe":"2.56.0"}
{"event":"child_start","sid":"S","child_id":0,"child_class":"hook","hook_name":"pre-commit","argv":["/h/pre-commit"]}
{"event":"child_start","sid":"S/T","child_id":0,"child_class":"hook","hook_name":"post-checkout","argv":["x"]}
{"event":"child_exit","sid":"S/T","child_id":0,"pid":9,"code":0,"t_rel":0.5}
not json
{"event":"child_exit","sid":"S","child_id":0,"pid":10,"code":0,"t_rel":0.012345}
{"event":"child_start","sid":"S","child_id":1,"child_class":"?","argv":["git","maintenance"]}
{"event":"child_exit","sid":"S","child_id":1,"pid":11,"code":0,"t_rel":0.2}
{"event":"child_start","sid":"S","child_id":2,"child_class":"hook","hook_name":"post-commit","argv":["/h/post-commit"]}
{"event":"child_exit","sid":"S","child_id":2,"pid":12,"code":1,"t_rel":0.002}
"#;
        let t = hook_times(text);
        assert_eq!(t.len(), 2, "{t:?}");
        assert_eq!(t[0].hook, "pre-commit");
        assert!((t[0].ms - 12.345).abs() < 1e-9);
        assert_eq!(t[0].code, 0);
        assert_eq!(t[1].hook, "post-commit");
        assert_eq!(t[1].code, 1);
    }
}
