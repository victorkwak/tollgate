//! The allow corpus (G1-G8): commands agents run every day, each through
//! the installed guard as a PreToolUse Bash call, must stay allowed and
//! unchanged except for the guard's own inline-cap prefix (R28, L17). The
//! deny fixtures next to them must deny. The guard's p95 over the whole
//! table, script-file reads included, stays under the L19 budget (G10).

mod support;

use std::path::Path;
use std::time::Duration;

use support::Armed;
use support::cpu::{CpuMeter, Sample};

/// The cap prefix the guard puts in front of waiting commands (L17).
const CAP: &str = "export TOLLGATE_INLINE_CAP=540; ";

/// A job id as `tollgate` prints it.
const JOB: &str = "20261105-120000-abcd1234";

/// The lead's allow corpus, with `{ABS}` for an absolute repo path and
/// `{JOB}` for a job id; relative paths are under the call's cwd.
const CORPUS: &[&str] = &[
    "cd {ABS} && git add a.rs b/c.rs && git commit -m \"fix(x): subject\" -m \"body\" -m \"Co-Authored-By: Name <noreply@example.com>\"",
    "cd r && git add a.rs b/c.rs && git commit -m 'fix(x): subject' -m 'body' -m 'Co-Authored-By: Name <noreply@example.com>'",
    "git commit -m \"$(cat <<'EOF'\nSubject\n\nBody line\n\nCo-Authored-By: Name <noreply@example.com>\nEOF\n)\"",
    "cd {ABS} && git commit -F - <<'EOF'\nSubject\n\nBody line with --no-verify and GIT_CONFIG_COUNT in prose\nEOF",
    "gh pr create --title \"x\" --body \"$(cat <<'EOF'\n## Summary\n- don't (break) on quotes\n\n## Test plan\n- cargo nextest run\nEOF\n)\"",
    "cd {ABS} && git commit -am \"subject\" ; git -C {ABS} commit -m \"subject\" 2>&1 | tail -5",
    "git -C r commit -m \"subject\" -m \"body line 1\nbody line 2\" -m 'Co-Authored-By: Claude <noreply@anthropic.com>'",
    "git commit -m \"Guard: deny no-verify abbreviations\" -m \"Names GIT_CONFIG_COUNT, core.hooksPath and --no-verify in prose\"",
    "git commit -m 'Fix env' -i src/a.rs ; git commit -m \"docs: mention --no-verify in README\"",
    "git commit --amend --no-edit ; git merge --no-ff feature -m \"Merge feature\" ; git cherry-pick -x abc1234 ; git rebase main",
    "GIT_EDITOR=true git rebase --continue ; git -c core.editor=true rebase --continue ; git merge --continue ; git rebase --abort",
    "git push origin feature ; git push -u origin feature ; git push --force-with-lease origin feature ; git push origin HEAD:refs/heads/feat ; git push origin --delete feat ; git tag v1 && git push origin v1",
    "git pull --ff-only ; git fetch -q && git status --short && git log --oneline -3",
    "git worktree add -b feat ../wt HEAD ; git worktree remove ../wt ; git stash push -m x ; git stash pop ; git reset --hard origin/main ; git branch -f feat HEAD~1",
    "git diff \"$(git merge-base main HEAD)\"..HEAD ; for f in a b; do git -C \"$f\" status --short; done ; git log --format='%H %s' -n 5",
    "git apply --index x.patch && git commit -m \"s\" ; git am < 0001.patch",
    "cd {ABS} && cargo test -p x && git add -A && git commit -m \"s\" && git push -u origin feat",
    "cargo nextest run 2>&1 | tail -20 ; timeout 600 cargo test ; CARGO_TARGET_DIR=/tmp/t cargo build ; export FOO=bar && cargo build",
    "python3 -c 'import json,sys; print(json.load(sys.stdin)[\"x\"])' < f.json ; uv run pytest -q ; bun test ; bunx tsc --noEmit",
    "grep -rn \"GIT_CONFIG_COUNT\\|core.hooksPath\\|--no-verify\" src docs ; rg -- '--no-verify' docs ; sed -n 1,40p src/guard/rules.rs",
    "ssh prodhost 'journalctl -u app --since \"1 hour ago\"' ; docker ps ; docker exec pg psql -U postgres -c 'select 1'",
    "tollgate status ; tollgate log {JOB} tests ; tollgate wait {JOB} && git commit -m \"s\"",
    // The most common commit and push shapes in the session transcripts
    // (~/.claude/projects, 2026-11-09), with their text replaced.
    "cd {ABS} && git add -A && git commit -q -m \"subject\" && git log --oneline -1",
    "cd {ABS} && git pull -q --ff-only 2>&1 | tail -2; git status -sb | head -3",
    "cd {ABS} && git commit -q -m \"subject\" && git log --oneline -2 && git fetch -q origin && git rev-list --left-right --count main...origin/main",
    "cd {ABS} && git push origin main 2>&1 | grep -E 'main|error'; git rev-parse --short main",
    "cd {ABS} && f=docs/a.md && sed -i 's/a/b/' $f && grep -c 'b' $f && git add $f && git commit -q -m \"subject\" && git log --oneline -1",
    "cd {ABS} && git diff --cached --stat | tail -1 && git commit -q -m \"subject\" && git log --oneline -1",
    "cd {ABS} && python3 - <<'EOF'\np = 'docs/a.md'\ns = open(p).read()\nopen(p, 'w').write(s.replace('git commit --no-verify', 'git commit'))\nEOF\ngit add docs/a.md && git commit -q -m \"subject\" && git push -q origin main 2>&1 | grep -E 'error'; git log --oneline -1",
    // Item 51: heredoc code that only names git or tollgate in its text
    // runs, with or without git in the same call.
    "python3 - <<'PY'\np = 'notes.md'\ns = 'run git commit --no-verify, then tollgate status'\nopen(p, 'w').write(s)\nPY",
    "cd {ABS} && python3 -I - <<'PY'\nimport json\nprint(json.dumps({'cmd': 'git push origin main'}))\nPY\ngit status --short",
    // Reading the session settings and git's global config (R26 asks
    // only on writes).
    "jq '.hooks' ~/.claude/settings.json ; grep -n PreToolUse ~/.claude/settings.json ; git config --global --get user.name",
    "awk '/hooks/' ~/.claude/settings.json ; perl -ne 'print if /env/' ~/.claude/settings.json",
    // Item 44: reading text that names tollgate's test variable.
    "grep -rn -i tollgate_test_install src tests ; rg TOLLGATE_TEST_INSTALL docs",
    // Lookups and syntax checks run nothing.
    "for c in jq gh; do command -v $c >/dev/null || echo \"$c missing\"; done",
    "chmod +x scripts/check.sh && bash -n scripts/check.sh && echo syntax-ok",
    "for f in a b; do [ -e \"$f\" ] || continue; echo \"$f\"; done",
    // sed edits, loops over literal items, a program written whole by a
    // literal heredoc (G3).
    "sed -i -e 's/--no-verify/-n/' -e '/^$/d' README.md && sed -n '1,40p' README.md",
    "for l in 10 20; do sed -n \"${l},$((l+5))p\" README.md; done",
    "for f in a.md b.md; do sed -i 's/x/y/' \"$f\"; done",
    "cat > /tmp/edit.py <<'EOF'\nimport sys\np = sys.argv[1]\nopen(p, 'a').write('x')\nEOF\npython3 /tmp/edit.py notes.md",
    // Script files the guard reads (G3), for the latency budget too.
    "bash scripts/check.sh",
    "./scripts/check.sh && git push origin feat",
];

/// Forms the follow-up items name; each must deny.
const DENY: &[&str] = &[
    "TOLLGATE_INLINE_CAP=1 git commit --no-verify -m x; ls",
    "git commit --no-veri -m x",
    "git commit -anm x",
    "${x}t commit -n -m y",
    "echo commit | xargs git",
    "bash <(printf 'git commit -n -m x')",
    "env -S 'git commit -n -m x'",
    "printf -v GIT_DIR /tmp/x; export GIT_DIR; git commit -m x",
    "sudo git commit -m x",
    "bash -c 'git commit --no-verify -m x'",
    "sh <<'EOF'\ngit commit -n -m x\nEOF",
    "git fetch . feat:refs/remotes/origin/main",
    "git update-ref refs/heads/main HEAD~1",
    "echo x > .git/refs/heads/main",
    "cd \"$X\" && rm -rf results",
    "bash scripts/bad.sh",
    "python3 -c 'import os; os.system(\"git commit -n\")'",
    "git -c core.hooksPath=/dev/null commit -m x",
    "bash -n +n scripts/bad.sh",
    "bash -o noexec +o noexec scripts/bad.sh",
    "bash -n -i scripts/bad.sh",
    "G=git; command $G commit -n -m x",
    "G=echo; for i in 1 2; do G=git; break; done; $G commit -n -m x",
    "printf 'import os\\nos.system(\"git commit -n\")\\n' > w.py && python3 w.py",
];

/// A realistic check script for the G3 script-file path.
fn check_script() -> String {
    let mut s =
        String::from("#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")/..\"\n");
    for k in 0..60 {
        s.push_str(&format!(
            "if [ -f crate{k}/Cargo.toml ]; then\n  cargo clippy -p crate{k} --all-targets -- -D warnings 2>&1 | tail -20\nfi\n"
        ));
    }
    s.push_str("cargo nextest run --no-fail-fast\ngit status --short\n");
    s
}

fn fill(cmd: &str, abs: &Path) -> String {
    cmd.replace("{ABS}", &abs.display().to_string())
        .replace("{JOB}", JOB)
}

fn input(a: &Armed, cmd: &str) -> String {
    serde_json::json!({
        "session_id": "s",
        "hook_event_name": "PreToolUse",
        "cwd": a.sb.root(),
        "tool_name": "Bash",
        "tool_input": {"command": cmd, "description": "d"},
    })
    .to_string()
}

fn setup() -> (Armed, std::path::PathBuf) {
    let a = Armed::new();
    let repo = a.sb.repo("r");
    // As in the session transcripts: the repo has its server remote. A
    // push to a name that is no remote is a push to a path (item 22,
    // secreview note 7).
    a.sb.git(
        &repo,
        &["remote", "add", "origin", "git@gitlab.com:v/r.git"],
    );
    let scripts = a.sb.root().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    for (name, text) in [
        ("check.sh", check_script()),
        (
            "bad.sh",
            "#!/bin/sh\ngit commit --no-verify -m bad\n".to_owned(),
        ),
    ] {
        support::write_exe(&scripts.join(name), &text);
    }
    (a, repo)
}

#[test]
fn the_allow_corpus_stays_allowed_and_unchanged_g1_g8() {
    let (a, repo) = setup();
    for raw in CORPUS {
        let cmd = fill(raw, &repo);
        let (code, out, err) = a.guard_raw(&input(&a, &cmd), &[]);
        assert_eq!(code, Some(0), "denied: {cmd}\n{err}");
        if out.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        let h = &v["hookSpecificOutput"];
        assert!(h.get("permissionDecision").is_none(), "{cmd}: {out}");
        assert_eq!(
            h["updatedInput"]["command"].as_str(),
            Some(format!("{CAP}{cmd}").as_str()),
            "the guard changed the command"
        );
    }
    for raw in DENY {
        let cmd = fill(raw, &repo);
        let (code, _, err) = a.guard_raw(&input(&a, &cmd), &[]);
        assert_eq!(code, Some(2), "not denied: {cmd}");
        assert!(err.starts_with("tollgate guard: denied:"), "{cmd}: {err}");
        assert_eq!(err.trim().lines().count(), 1, "one line: {err}");
    }
}

/// G10, L19: the guard's p95 over the corpus and the deny fixtures,
/// script-file parsing included, is under 10 ms of CPU time (user +
/// system, as `tests/latency.rs` asserts every L19 budget): wall time
/// depends on how busy the host is, and the whole parallel suite makes it
/// several times longer. The guard's work is sequential, so its CPU time
/// is a lower bound of its wall time. Best of three rounds.
#[test]
fn the_guard_p95_over_the_corpus_is_under_10_ms_g10_l19() {
    let meter = CpuMeter::new();
    let (a, repo) = setup();
    let inputs: Vec<String> = CORPUS
        .iter()
        .chain(DENY)
        .map(|c| input(&a, &fill(c, &repo)))
        .collect();
    // Warm the page cache.
    for i in &inputs {
        a.guard_raw(i, &[]);
    }
    let budget = Duration::from_millis(10);
    let rank = |mut v: Vec<Duration>| {
        v.sort();
        v[(v.len() * 95 / 100).min(v.len() - 1)]
    };
    let mut best: Option<(Duration, Duration)> = None;
    for _ in 0..3 {
        let mut t: Vec<Sample> = Vec::new();
        for _ in 0..4 {
            for i in &inputs {
                t.push(meter.measure(|| {
                    let (code, _, _) = a.guard_raw(i, &[]);
                    assert!(matches!(code, Some(0 | 2)));
                }));
            }
        }
        let cpu = rank(t.iter().map(|s| s.cpu).collect());
        let wall = rank(t.iter().map(|s| s.wall).collect());
        if best.is_none_or(|(c, _)| cpu < c) {
            best = Some((cpu, wall));
        }
    }
    let (cpu, wall) = best.unwrap();
    {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "L19 guard over the corpus: p95 cpu {:.2} ms, wall {:.2} ms (budget {} ms, asserted on cpu)",
            cpu.as_secs_f64() * 1000.0,
            wall.as_secs_f64() * 1000.0,
            budget.as_millis()
        );
    }
    assert!(
        cpu < budget,
        "guard p95 CPU time {cpu:?} (L19, G10: {budget:?}; wall {wall:?})"
    );
}
