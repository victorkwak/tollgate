//! The guard corpus: commands agents run every day, each through the
//! installed guard as a PreToolUse Bash call. The ALLOW lists must stay
//! allowed, with no ask, and unchanged except for the guard's own
//! inline-cap prefix (R28, L17). The DENY and ASK lists next to them hold
//! one line for each rule, alone and through each wrapper the walker
//! follows. The guard's p95 over all of it, script-file reads included,
//! stays under the L19 budget.

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use support::Armed;
use support::cpu::{CpuMeter, GUARD_BUDGET, Sample};

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
    // Reading the session settings and git's global config with known
    // readers (R26 asks on writes, and when a program that may write a
    // path it is given, such as awk or perl, gets a settings path: S53).
    "jq '.hooks' ~/.claude/settings.json ; grep -n PreToolUse ~/.claude/settings.json ; git config --global --get user.name",
    "cat ~/.claude/settings.json | awk '/hooks/' ; perl -ne 'print if /env/' < ~/.claude/settings.json",
    // Item 44: reading text that names tollgate's test variable.
    "grep -rn -i tollgate_test_install src tests ; rg TOLLGATE_TEST_INSTALL docs",
    // Lookups and syntax checks run nothing.
    "for c in jq gh; do command -v $c >/dev/null || echo \"$c missing\"; done",
    "chmod +x scripts/check.sh && bash -n scripts/check.sh && echo syntax-ok",
    "for f in a b; do [ -e \"$f\" ] || continue; echo \"$f\"; done",
    // sed edits, loops over literal items, a program written whole by a
    // literal heredoc.
    "sed -i -e 's/--no-verify/-n/' -e '/^$/d' README.md && sed -n '1,40p' README.md",
    "for l in 10 20; do sed -n \"${l},$((l+5))p\" README.md; done",
    "for f in a.md b.md; do sed -i 's/x/y/' \"$f\"; done",
    "cat > /tmp/edit.py <<'EOF'\nimport sys\np = sys.argv[1]\nopen(p, 'a').write('x')\nEOF\npython3 /tmp/edit.py notes.md",
    // Script files the guard reads, for the latency budget too.
    "bash scripts/check.sh",
    "./scripts/check.sh && git push origin feat",
    "bash \"$PWD/scripts/check.sh\" && git push origin feat",
    "\"$(pwd)/scripts/check.sh\" && git status",
];

/// The false-deny corpus: harmless commands that a rule of the closed
/// grammar denied, or that only name a rule in data. They run in a repo
/// whose path has the word `tollgate` in it.
const HARMLESS: &[&str] = &[
    // Heredocs and text that only mention the rules.
    "cat >> notes.md <<'EOF'\nNever use git commit --no-verify. Do not run env -i git. GIT_CONFIG_COUNT stays set.\nEOF",
    "cat > tests/flag.rs <<'EOF'\n#[test] fn t() { assert!(deny(\"git commit --no-verify\")); }\nEOF",
    "cat > msg.txt <<'EOF'\ndocs: explain why --no-verify is denied\nEOF\ngit commit -F msg.txt",
    "cat > t.sh <<EOF\ncd $PWD && cargo test\nEOF\nbash t.sh",
    "cat > t.sh <<EOF\ncd $HOME/src/app\ngit status --short\nEOF\nbash t.sh",
    "printf 'run: tollgate install\\n' >> docs/setup.md",
    "echo \"see .claude/settings.json\" >> README.md",
    "sed -i 's/GIT_CONFIG_COUNT/GIT_CONFIG_KEY_0/' docs/spec.md",
    "grep -rn 'no-verify' docs/",
    "grep -rn -- '--no-verify' src/ tests/",
    "grep -rnIE 'core\\.hooks(Path)?' --include='*.rs' src | sort | uniq -c",
    "grep -n -E '^\\s*(pub(\\(crate\\))? )?(fn|struct) ' src/lib.rs",
    "rg -n 'TOLLGATE_[A-Z_]+' src | head",
    // Interpreters: their code is data.
    "python3 - <<'PY'\nimport re, pathlib\np = pathlib.Path(\"docs/notes.md\")\np.write_text(p.read_text().replace(\"git add . && git commit\", \"git add -A && git commit\"))\nPY",
    "python3 -c \"print('git status')\"",
    "python3 script.py a b && git status",
    "node -e \"console.log(require('./package.json').version)\" && git tag -l",
    "git log --format=%s | python3 -c \"import sys; print(len(sys.stdin.read()))\"",
    "jq -r '.scripts' package.json && git diff --stat",
    "printf 'import os\\nprint(os.getcwd())\\n' > w.py && python3 w.py && git status",
    // Commit messages and other values.
    "git commit -m \"$(date)\"",
    "git commit -m 'x' -m \"$(date)\"",
    "git commit -m \"$(printf 'x\\n\\ny')\"",
    "git commit -m \"fix: $(git rev-parse --short HEAD)\"",
    "MSG=\"fix: x\"; git commit -m \"$MSG\"",
    "git commit -m \"$(cat <<'EOF'\nfeat: add the parser\n\nBody text that names --no-verify and env -i.\nEOF\n)\"",
    "git commit -m \"docs: say that -n is denied\"",
    "git commit --allow-empty -m init",
    // Words made at run time in data positions.
    "cd \"$(git rev-parse --show-toplevel)\" && git commit -m x",
    "d=$(mktemp -d); git -C \"$d\" init -q && git -C \"$d\" commit --allow-empty -m init",
    "cd $(mktemp -d) && git init -q && git commit --allow-empty -m init",
    "git push origin \"$branch\"",
    "for f in a.rs b.rs; do git show \"HEAD:$f\" > \"/tmp/out/$f\"; done",
    "tmp=$(mktemp -d); git status > \"$tmp/s.txt\"; rm -rf \"$tmp\"",
    "cd \"$dir\" && echo x > out/rel.txt && git add out/rel.txt",
    "cd \"$X\" && rm -rf results",
    "sed -i \"s/$old/$new/\" src/a.rs && git diff",
    "\"$PY\" -m pytest -q && git status",
    "eval \"$(ssh-agent -s)\" && git fetch",
    // Everyday git.
    "git status && git diff && git log --oneline -5",
    "git add -A && git commit -m \"feat: x\" && git push",
    "git push -n origin feat",
    "git push -u origin feat",
    "git pull --rebase",
    "git fetch -n origin",
    "git merge -n feat",
    "git stash list",
    "git worktree add ../wt -b feat",
    "git checkout -b feat",
    "git switch -c feat",
    "git branch -D feat",
    "git log | sort | uniq -c | sort -rn | head",
    "git ls-files | xargs wc -l",
    "git grep -n -- '--no-verify'",
    "wc -l src/*.rs | sort -n | tail -5 && git status",
    // Everyday tools.
    "cargo test && git add -A",
    "cargo nextest run 2>&1 | grep -vE '^\\s+(PASS|Compiling)' | tail -15",
    "cargo clippy --all-targets -- -D warnings",
    "bun test && bun run build",
    "bunx biome check .",
    "uv run pytest -q",
    "uv run python -c \"print(1)\"",
    "docker compose up -d",
    "docker exec app git status",
    "ssh host 'cd repo && git pull'",
    "find . -name '*.rs' -exec grep -l git {} +",
    "find . -name '*.orig' -exec rm {} +",
    "xargs -n1 basename < files.txt",
    "tollgate status",
    "tollgate log",
    "tollgate stats --since 2d",
    "tollgate wait {JOB} && git commit -m x",
    "cat ~/.claude/settings.json",
    "ls .git/hooks",
    // What the rules of earlier guard versions denied or asked about:
    // remote changes, programs it did not know, names bash sets without
    // an assignment word, PATH and HOME changes, git values that name a
    // program, other spellings of a local repo, code on a shell's stdin.
    "git remote set-url origin ../other.git",
    "git remote add fork ../fork.git && git fetch fork",
    "git config remote.origin.url ../other.git",
    "git config --global core.pager less",
    "git -c diff.external=/usr/bin/true diff HEAD",
    "GIT_PAGER=cat git log -1",
    "GIT_EXTERNAL_DIFF=true git diff --stat",
    "git push ../mirror.git feat",
    "git fetch ./vendor/lib.git main:vendor-main",
    "git update-ref refs/heads/topic HEAD",
    "echo 'git commit -m x' | bash",
    "git ls-files | python3 -c 'import sys; print(len(sys.stdin.read()))'",
    "awk '{print $1}' log.txt | sort | uniq -c; git status",
    "perl -pe 's/a/b/' x.txt > y.txt && git diff",
    "printf -v ts '%(%F)T' -1; git commit -m \"snapshot $ts\"",
    "read -r name < name.txt; git checkout \"$name\"",
    "trap 'rm -f tmp.txt' EXIT; git status > tmp.txt",
    "export PATH=\"$HOME/.cargo/bin:$PATH\" && cargo build && git status",
    "HOME=$(mktemp -d) git init -q demo",
    "alias gs='git status'; gs",
    "prlimit --nofile=4096 cargo test && git status",
    "setsid -w cargo build; git status",
    "parallel gzip ::: a.log b.log; git status",
    "script -qc 'cargo test' /dev/null | tail -5; git status",
    "sh scripts/check.sh && git status",
    "sqlite3 app.db '.tables'; git status",
    "make --eval 'all: ; @echo ok'; git status",
    // Unit 4: writes that the removed tool-path, managed-settings and
    // ancestor asks caught. The job refuses an unapproved host tool
    // config (S46).
    "echo 'x' >> ~/.cargo/config.toml && git status",
    "cargo build --release && cp target/release/mytool ~/.local/bin/mytool",
    "ln -sf \"$PWD/target/release/mytool\" ~/.local/bin/mytool && git status",
    "chmod +x ~/.local/bin/mytool; git log --oneline -1",
    "printf 'max_width = 100\\n' > ~/.rustfmt.toml && cargo fmt && git diff",
    "cp -r dist/. ~/.local && git status",
    "rm -rf ~/.cargo/registry/cache ~/.cache/uv && git status",
    "mkdir -p ~/.config/rustfmt && cp rustfmt.toml ~/.config/rustfmt/ && git status",
    // A script written by a writer the guard does not model, then run:
    // no bypass marker in the command, so no ask.
    "tee build.sh <<'EOF' >/dev/null\ncargo build\ngit status\nEOF\nbash build.sh",
    "cp ci/check.sh /tmp/c.sh && bash /tmp/c.sh && git status",
];

/// One command for each deny rule (R25), in a form that every wrapper of
/// [`WRAPPERS`] can carry: plain words, no quotes.
const DENY_RULES: &[&str] = &[
    "git commit --no-verify -m x",
    "git commit -anm x",
    "git -c core.hooksPath=/dev/null commit -m x",
    "env GIT_CONFIG_COUNT=0 git commit -m x",
    "env -i git commit -m x",
    "rm -rf $XDG_STATE_HOME/tollgate/records",
    "tollgate uninstall",
    "git branch -f main HEAD~1",
    "git update-ref refs/heads/main HEAD~1",
    "git send-pack origin main",
];

/// One command for each ask rule (R26), in the same form.
const ASK_RULES: &[&str] = &[
    "git config core.hooksPath hooks",
    "cp x.json .claude/settings.json",
    "touch .git/hooks/pre-commit",
    "git branch -m old new",
];

/// What the walker follows: `{}` is the command.
const WRAPPERS: &[&str] = &[
    "{}",
    "sh -c '{}'",
    "env {}",
    "true && {}",
    "( {} )",
    "echo x | xargs {}",
    "find . -name x -exec {} \\;",
    "uv run {}",
    "cat > s.sh <<'EOF'\n{}\nEOF\nbash s.sh",
    "cat > s.sh <<EOF\ncd $PWD\n{}\nEOF\nbash s.sh",
];

/// More spellings of the deny rules.
const DENY: &[&str] = &[
    "TOLLGATE_INLINE_CAP=1 git commit --no-verify -m x; ls",
    "env -S 'git commit -n -m x'",
    "sudo git commit -m x",
    "bash -c 'git commit --no-verify -m x'",
    "sh <<'EOF'\ngit commit -n -m x\nEOF",
    "echo 'git commit -n -m x' | bash",
    "git fetch . feat:refs/remotes/origin/main",
    "git push . feat:main",
    "echo x > $XDG_STATE_HOME/tollgate/x",
    "sed -i s/a/b/ $XDG_STATE_HOME/tollgate/install.json",
    "bash scripts/bad.sh",
    // A script path made absolute from the cwd.
    "bash \"$PWD/scripts/bad.sh\"",
    "bash ${PWD}/scripts/bad.sh",
    "bash $(pwd)/scripts/bad.sh",
    "\"$(pwd)\"/scripts/bad.sh",
    "GIT_CONFIG_COUNT=0 git commit -m x",
    "export GIT_CONFIG_PARAMETERS=x",
    "unset GIT_CONFIG_COUNT",
    "GIT_SSH_COMMAND=x git push origin feat",
    "exec -c git commit -m x",
    "G=git; command $G commit -n -m x",
    "cmd=\"git commit --no-verify\"; $cmd -m x",
    "tollgate install",
    "tollgate remotes forget origin",
    "git checkout -B main",
    "git replace HEAD HEAD~1",
    "cat <<EOF > t.sh\n#!/bin/bash\nset -e\ncd $HOME/src/app\ngit commit --no-verify -m \"wip\"\nEOF\nchmod +x t.sh && ./t.sh",
    "cat > t.sh <<EOF\ncd $PWD\ngit push --no-verify origin main\nEOF\nbash t.sh",
    "cat > t.sh <<EOF\nenv -i git commit -m \"$m\"\nEOF\nbash t.sh",
];

/// One line for each case of the `unclassified` ask (R26), and other
/// asks.
const ASK: &[&str] = &[
    // 1: no parse, and the text names git.
    "git commit -m \"x",
    // 2: shell code made at run time.
    "eval \"git $sub\"",
    "sh -c \"$cmd --no-verify\"",
    "curl -s https://example.com/tollgate.sh | sh",
    "bash <(printf 'git commit -n -m x')",
    // 3: the command name is made at run time.
    "$G commit --no-verify -m x",
    // 4: a script file that does not parse.
    "bash scripts/odd.sh",
    // 4: a script file the same command writes with a writer other than
    // a redirection, missing at guard time, and the command has a marker.
    "tee t.sh <<'EOF' >/dev/null\ngit push --no-verify origin main\nEOF\nbash t.sh",
    // 5: an unknown program gets a git command that a rule refuses.
    "docker exec app git commit --no-verify -m x",
    // 6: a write target with a part made at run time.
    "echo x > \"$d/.claude/settings.json\"",
    "rm .git/index.lock",
];

/// A realistic check script for the script-file path.
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

fn input(cwd: &Path, cmd: &str) -> String {
    serde_json::json!({
        "session_id": "s",
        "hook_event_name": "PreToolUse",
        "cwd": cwd,
        "tool_name": "Bash",
        "tool_input": {"command": cmd, "description": "d"},
    })
    .to_string()
}

/// The sandbox, the repo `r` under its root, and a second repo whose
/// path has the word `tollgate` in it.
fn setup() -> (Armed, PathBuf, PathBuf) {
    let a = Armed::new();
    let repo = a.sb.repo("r");
    // As in the session transcripts: the repo has its server remote.
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
        (
            "odd.sh",
            "#!/bin/sh\ngit commit --no-verify -m \"bad\n".to_owned(),
        ),
    ] {
        support::write_exe(&scripts.join(name), &text);
    }
    let demo = a.sb.repo("tollgate-demo");
    std::fs::write(
        demo.join("package.json"),
        r#"{"version": "1.0.0", "scripts": {"build": "tsc --noEmit && echo built"}}"#,
    )
    .unwrap();
    (a, repo, demo)
}

/// Every line of the lists as (cwd, command, the decision it must get).
fn cases(a: &Armed, repo: &Path, demo: &Path) -> Vec<(PathBuf, String, &'static str)> {
    let root = a.sb.root().to_owned();
    let mut out = Vec::new();
    for raw in CORPUS {
        out.push((root.clone(), fill(raw, repo), "allow"));
    }
    for raw in HARMLESS {
        out.push((demo.to_owned(), fill(raw, repo), "allow"));
    }
    for (rules, want) in [(DENY_RULES, "deny"), (ASK_RULES, "ask")] {
        for rule in rules {
            for w in WRAPPERS {
                out.push((demo.to_owned(), w.replace("{}", rule), want));
            }
        }
    }
    for raw in DENY {
        out.push((root.clone(), fill(raw, repo), "deny"));
    }
    for raw in ASK {
        out.push((root.clone(), fill(raw, repo), "ask"));
    }
    out
}

/// The guard's decision on `cmd`: `allow`, `ask` or `deny`. An allowed
/// command is unchanged except for the cap prefix.
fn decision(a: &Armed, cwd: &Path, cmd: &str) -> &'static str {
    let (code, out, err) = a.guard_raw(&input(cwd, cmd), &[]);
    if code == Some(2) {
        assert!(err.starts_with("tollgate guard: denied:"), "{cmd}: {err}");
        assert_eq!(err.trim().lines().count(), 1, "one line: {err}");
        return "deny";
    }
    assert_eq!(code, Some(0), "{cmd}: {err}");
    if out.trim().is_empty() {
        return "allow";
    }
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let h = &v["hookSpecificOutput"];
    if let Some(u) = h["updatedInput"]["command"].as_str() {
        assert_eq!(u, format!("{CAP}{cmd}"), "the guard changed the command");
    }
    match h["permissionDecision"].as_str() {
        Some("ask") => "ask",
        None | Some("allow") => "allow",
        Some(other) => panic!("{cmd}: decision {other}"),
    }
}

/// The lines whose decision is not the one the lists give.
fn wrong(only: &str) -> (usize, Vec<String>) {
    let (a, repo, demo) = setup();
    let mut bad = Vec::new();
    let mut n = 0;
    for (cwd, cmd, want) in cases(&a, &repo, &demo) {
        if only != want {
            continue;
        }
        n += 1;
        let got = decision(&a, &cwd, &cmd);
        if got != want {
            bad.push(format!("{got}, not {want}: {cmd}"));
        }
    }
    (n, bad)
}

#[test]
fn the_allow_corpus_stays_allowed_and_unchanged() {
    let (n, bad) = wrong("allow");
    assert!(
        bad.is_empty(),
        "{} of {n} harmless commands are not allowed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// No line of the ALLOW lists asks: the ask rate over the corpus is 0.
#[test]
fn the_ask_rate_over_the_corpus_is_zero() {
    let (n, bad) = wrong("allow");
    let asks: Vec<&String> = bad.iter().filter(|b| b.starts_with("ask")).collect();
    assert!(
        asks.is_empty(),
        "{} asks over {n} commands: {asks:#?}",
        asks.len()
    );
}

#[test]
fn each_rule_denies_or_asks_alone_and_through_each_wrapper() {
    for want in ["deny", "ask"] {
        let (n, bad) = wrong(want);
        assert!(
            bad.is_empty(),
            "{} of {n} commands do not {want}:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }
}

/// L19: the guard's p95 over the corpus and the deny and ask lists,
/// script-file parsing included, is under 10 ms of CPU time in a release
/// build (`support::cpu::GUARD_BUDGET`: 20 ms in a debug build) (user +
/// system, as `tests/latency.rs` asserts every L19 budget): wall time
/// depends on how busy the host is, and the whole parallel suite makes it
/// several times longer. The guard's work is sequential, so its CPU time
/// is a lower bound of its wall time. Best of three rounds.
#[test]
fn the_guard_p95_over_the_corpus_is_under_10_ms_l19() {
    let meter = CpuMeter::new();
    let (a, repo, demo) = setup();
    let inputs: Vec<String> = cases(&a, &repo, &demo)
        .iter()
        .map(|(cwd, cmd, _)| input(cwd, cmd))
        .collect();
    // Warm the page cache.
    for i in &inputs {
        a.guard_raw(i, &[]);
    }
    let budget = GUARD_BUDGET;
    let rank = |v: &mut Vec<Duration>, pct: usize| {
        v.sort();
        v[(v.len() * pct / 100).min(v.len() - 1)]
    };
    let mut best: Option<(Duration, Duration, Duration)> = None;
    for _ in 0..3 {
        let mut t: Vec<Sample> = Vec::new();
        for _ in 0..2 {
            for i in &inputs {
                t.push(meter.measure(|| {
                    let (code, _, _) = a.guard_raw(i, &[]);
                    assert!(matches!(code, Some(0 | 2)));
                }));
            }
        }
        let mut cpu: Vec<Duration> = t.iter().map(|s| s.cpu).collect();
        let mut wall: Vec<Duration> = t.iter().map(|s| s.wall).collect();
        let (p50, p95) = (rank(&mut cpu, 50), rank(&mut cpu, 95));
        if best.is_none_or(|(_, c, _)| p95 < c) {
            best = Some((p50, p95, rank(&mut wall, 95)));
        }
    }
    let (p50, cpu, wall) = best.unwrap();
    {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "L19 guard over the corpus ({} commands): cpu p50 {:.2} ms, p95 {:.2} ms; wall p95 {:.2} ms (budget {} ms, asserted on cpu)",
            inputs.len(),
            p50.as_secs_f64() * 1000.0,
            cpu.as_secs_f64() * 1000.0,
            wall.as_secs_f64() * 1000.0,
            budget.as_millis()
        );
    }
    assert!(
        cpu < budget,
        "guard p95 CPU time {cpu:?} (L19: {budget:?}; wall {wall:?})"
    );
}
