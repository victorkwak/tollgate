//! `tollgate run <step>` (R105) and step artefacts (R106) through the real
//! binary with `command` steps.

mod support;

use std::path::{Path, PathBuf};

use support::{Sandbox, job_id};

/// A repo with `tollgate.toml` committed on `main`.
fn repo_with(sb: &Sandbox, name: &str, toml: &str) -> PathBuf {
    let repo = sb.repo(name);
    sb.commit_file(&repo, "tollgate.toml", toml, "policy");
    repo
}

/// Host config with a tiny disk floor and `COUNT` in the job env.
fn host(sb: &Sandbox, extra: &str) -> PathBuf {
    let counter = sb.root().join("count");
    sb.host_config(&format!(
        "[verify]\nmin_free = \"1M\"\n[job.env]\nCOUNT = \"{}\"\n{extra}",
        counter.display()
    ));
    counter
}

/// Lines of the counter file that equal `line`.
fn runs(counter: &Path, line: &str) -> usize {
    std::fs::read_to_string(counter)
        .unwrap_or_default()
        .lines()
        .filter(|l| *l == line)
        .count()
}

/// The job named by `REUSED <step> from <job>`.
fn reused_from(out: &str, step: &str) -> String {
    let needle = format!("REUSED {step} from ");
    let at = out
        .find(&needle)
        .unwrap_or_else(|| panic!("no {needle:?} in:\n{out}"));
    out[at + needle.len()..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

/// The path after `<label>: ` on its own line.
fn path_line(out: &str, label: &str) -> Option<PathBuf> {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{label}: ")))
        .map(PathBuf::from)
}

/// A step that counts its runs; `sh -c` makes run arguments its `$*`.
fn counting(name: &str) -> String {
    format!(
        "[[step]]\nname = \"{name}\"\nkind = \"command\"\nrun = '''sh -c 'echo \"{name}:$*\" >> \"$COUNT\"' {name}'''\n"
    )
}

/// R105: a step run stores a pass; the next identical run returns it with
/// no job, `--rerun` runs it again, and no tree record is written.
#[test]
fn a_step_run_stores_a_pass_that_the_next_run_returns_r105() {
    let sb = Sandbox::new();
    let counter = host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        &format!("version = 1\n{}{}", counting("a"), counting("b")),
    );
    let r = sb.tollgate(&repo, &["run", "a", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    assert_eq!((runs(&counter, "a:"), runs(&counter, "b:")), (1, 0));
    let log = path_line(&r.out, "log").unwrap_or_else(|| panic!("{}", r.out));
    assert!(log.is_absolute() && log.is_file(), "{}", r.out);
    assert_eq!(sb.record_count(), 0, "a step job writes no tree record");
    let r = sb.tollgate(&repo, &["run", "a"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(reused_from(&r.out, "a"), job);
    assert!(r.out.contains("(passed "), "{}", r.out);
    assert_eq!(path_line(&r.out, "log"), Some(log));
    assert_eq!(sb.jobs().len(), 1);
    assert_eq!(runs(&counter, "a:"), 1);
    let r = sb.tollgate(&repo, &["run", "a", "--rerun", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), 2);
    assert_eq!(runs(&counter, "a:"), 2);
    // `tollgate stats` counts them as step jobs.
    let st = sb.tollgate(&repo, &["stats", "--json"]);
    assert_eq!(st.code, Some(0), "{}", st.out);
    let v: serde_json::Value = serde_json::from_str(&st.out).unwrap();
    let steps: u64 = v["repos"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x["jobs_step"].as_u64())
        .sum();
    assert_eq!(steps, 2, "{v:#}");
    // A failing step fails the run and stores nothing.
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"bad\"\nkind = \"command\"\nrun = \"exit 3\"\n",
        "bad",
    );
    let r = sb.tollgate(&repo, &["run", "bad", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("step bad: fail exit 3"), "{}", r.out);
    let r = sb.tollgate(&repo, &["run", "bad", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert_eq!(sb.jobs().len(), 4);
}

/// R105, R101: a step run's pass counts as fresh for a full check of the
/// same tree on a full ref; a full pass of a gate job answers a step run.
#[test]
fn a_full_ref_check_takes_a_step_run_pass_as_fresh_r105_r101() {
    let sb = Sandbox::new();
    let counter = host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        &format!("version = 1\n{}{}", counting("a"), counting("b")),
    );
    let r = sb.tollgate(&repo, &["run", "a", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let step_job = job_id(&r.out);
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "main", "--wait"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out
            .contains(&format!("FRESH a from {step_job} (same tree)")),
        "{}",
        r.out
    );
    assert!(!r.out.contains("REUSED"), "{}", r.out);
    let full_job = job_id(&r.out);
    assert_eq!((runs(&counter, "a:"), runs(&counter, "b:")), (1, 1));
    // The full job's own pass of `b` answers a step run.
    let r = sb.tollgate(&repo, &["run", "b"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(reused_from(&r.out, "b"), full_job);
    assert_eq!(runs(&counter, "b:"), 1);
}

/// R105: arguments narrow a step. A narrowed pass answers only an
/// identical call, never a gate job or a plain run; a tool kind without
/// arguments refuses them.
#[test]
fn narrowed_runs_have_their_own_key_r105() {
    let sb = Sandbox::new();
    let counter = host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        &format!(
            "version = 1\n{}tiers = [\"fast\"]\n[[step]]\nname = \"fmt\"\nkind = \"cargo-fmt\"\ntiers = [\"full\"]\n",
            counting("t")
        ),
    );
    let narrowed = ["run", "t", "--wait", "--", "x y", "z"];
    let r = sb.tollgate(&repo, &narrowed);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    assert_eq!(runs(&counter, "t:x y z"), 1, "shell-quoted args");
    let r = sb.tollgate(&repo, &narrowed);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(reused_from(&r.out, "t"), job);
    assert_eq!(sb.jobs().len(), 1);
    // A gate job does not take the narrowed pass.
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        !r.out.contains("FRESH") && !r.out.contains("REUSED"),
        "{}",
        r.out
    );
    let check_job = job_id(&r.out);
    assert_eq!(runs(&counter, "t:"), 1);
    // A plain run takes the gate job's pass, not the narrowed one.
    let r = sb.tollgate(&repo, &["run", "t"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(reused_from(&r.out, "t"), check_job);
    // Other arguments: their own run.
    let r = sb.tollgate(&repo, &["run", "t", "--wait", "--", "other"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(runs(&counter, "t:other"), 1);
    // gc --all removes the narrowed passes.
    assert!(sb.state().join("runs").read_dir().unwrap().next().is_some());
    let g = sb.tollgate(&sb.root(), &["gc", "--all"]);
    assert_eq!(g.code, Some(0), "{}", g.out);
    assert!(
        sb.state()
            .join("runs")
            .read_dir()
            .map_or(true, |mut d| d.next().is_none()),
        "{}",
        g.out
    );
    let r = sb.tollgate(&repo, &["run", "fmt", "--", "x"]);
    assert_eq!(r.code, Some(2), "{}", r.out);
    assert!(
        r.out.contains("step kind cargo-fmt takes no arguments"),
        "{}",
        r.out
    );
}

/// R105, R88: two calls for the same step on the same inputs share one job.
#[test]
fn concurrent_step_runs_share_one_job_r105_r88() {
    let sb = Sandbox::new();
    let counter = host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"s\"\nkind = \"command\"\nrun = 'sleep 1; echo s >> \"$COUNT\"'\n",
    );
    let outs: Vec<support::Run> = std::thread::scope(|scope| {
        // `--rev`: two `git write-tree` in one worktree race for its index
        // lock, as for `check`.
        let args: &[&str] = &["run", "s", "--rev", "HEAD", "--wait"];
        let a = scope.spawn(|| sb.tollgate(&repo, args));
        let b = scope.spawn(|| sb.tollgate(&repo, args));
        vec![a.join().unwrap(), b.join().unwrap()]
    });
    for r in &outs {
        assert_eq!(r.code, Some(0), "{}", r.out);
    }
    assert_eq!(sb.jobs().len(), 1, "{}\n{}", outs[0].out, outs[1].out);
    assert_eq!(runs(&counter, "s"), 1);
}

/// R105: an unknown step names the steps; `<step>` and `--here` exclude
/// each other.
#[test]
fn an_unknown_step_lists_the_steps_r105() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        &format!("version = 1\n{}{}", counting("a"), counting("b")),
    );
    let r = sb.tollgate(&repo, &["run", "nope"]);
    assert_eq!(r.code, Some(2), "{}", r.out);
    assert!(
        r.out.contains("no step \"nope\"") && r.out.contains("a, b"),
        "{}",
        r.out
    );
    let r = sb.tollgate(&repo, &["run", "a", "--here", "--tier", "fast"]);
    assert_eq!(r.code, Some(2), "{}", r.out);
    assert!(sb.jobs().is_empty());
}

/// R105: unstaged changes get a note that the staged tree runs.
#[test]
fn unstaged_changes_get_a_note_r105() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(&sb, "r", &format!("version = 1\n{}", counting("a")));
    std::fs::write(repo.join("tollgate.toml"), "changed\n").unwrap();
    let r = sb.tollgate(&repo, &["run", "a", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("not staged") && r.out.contains("staged tree"),
        "{}",
        r.out
    );
}

/// The artefact dir of `step` in `job`.
fn artifacts(sb: &Sandbox, job: &str, step: &str) -> PathBuf {
    sb.state()
        .join("jobs")
        .join(job)
        .join("artifacts")
        .join(step)
}

/// R106: artefacts are copied after a pass and after a fail, keeping
/// relative paths, without following symlinks, within the size limit; the
/// human report names them for a failed step; gc removes them with the
/// step logs.
#[test]
fn step_artifacts_are_kept_with_the_job_r106() {
    let sb = Sandbox::new();
    let mark = sb.root().join("mark");
    let outside = sb.root().join("secret.txt");
    std::fs::write(&outside, "secret\n").unwrap();
    host(
        &sb,
        &format!(
            "MARK = \"{}\"\nSECRET = \"{}\"\n",
            mark.display(),
            outside.display()
        ),
    );
    let run = r#"mkdir -p out/sub shots && echo a > out/a.txt && echo b > out/sub/b.txt && ln -s "$SECRET" out/link && echo p > shots/x.png && echo t > shots/x.txt && test -e "$MARK""#;
    let repo = repo_with(
        &sb,
        "r",
        &format!(
            "version = 1\n[[step]]\nname = \"e2e\"\nkind = \"command\"\nrun = '{run}'\nartifacts = [\"out\", \"shots/*.png\"]\n"
        ),
    );
    sb.commit_file(&repo, ".gitignore", "out/\nshots/\n", "ignore");
    // Fail first (no mark): artefacts kept, the report names them.
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    let failed = job_id(&r.out);
    let dir = artifacts(&sb, &failed, "e2e");
    assert!(
        r.out.contains(&format!("artifacts: {}", dir.display())),
        "{}",
        r.out
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("out/a.txt")).unwrap(),
        "a\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("out/sub/b.txt")).unwrap(),
        "b\n"
    );
    assert!(dir.join("shots/x.png").is_file());
    assert!(!dir.join("shots/x.txt").exists());
    assert!(
        dir.join("out/link").symlink_metadata().is_err(),
        "a symlink is not followed or copied"
    );
    // Pass: also kept; the report's step names the dir.
    std::fs::write(&mark, "").unwrap();
    let r = sb.tollgate(&repo, &["run", "e2e", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let passed = job_id(&r.out);
    let dir = artifacts(&sb, &passed, "e2e");
    assert!(dir.join("out/a.txt").is_file());
    assert_eq!(path_line(&r.out, "artifacts"), Some(dir.clone()));
    let rep = sb.report(&passed);
    assert_eq!(
        rep["steps"][0]["artifacts"],
        dir.display().to_string(),
        "{rep}"
    );
    // A stored pass prints the artefact dir too.
    let r = sb.tollgate(&repo, &["run", "e2e"]);
    assert_eq!(
        path_line(&r.out, "artifacts"),
        Some(dir.clone()),
        "{}",
        r.out
    );
    // gc after 14 days removes them with the step logs.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(15 * 86_400);
    for job in [&failed, &passed] {
        let f = std::fs::File::open(sb.state().join("jobs").join(job).join("job.json")).unwrap();
        f.set_modified(old).unwrap();
    }
    let g = sb.tollgate(&sb.root(), &["gc"]);
    assert_eq!(g.code, Some(0), "{}", g.out);
    assert!(!dir.exists(), "{}", g.out);
    assert!(!artifacts(&sb, &failed, "e2e").exists(), "{}", g.out);
}

/// R106: copying stops at the host limit and the step says so.
#[test]
fn step_artifacts_stop_at_the_limit_r106() {
    let sb = Sandbox::new();
    host(&sb, "[job]\nartifacts_max = \"1K\"\n");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"big\"\nkind = \"command\"\nrun = 'mkdir -p out && head -c 800 /dev/zero > out/1.bin && head -c 800 /dev/zero > out/2.bin'\nartifacts = [\"out\"]\n",
    );
    sb.commit_file(&repo, ".gitignore", "out/\n", "ignore");
    let r = sb.tollgate(&repo, &["run", "big", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    let dir = artifacts(&sb, &job, "big");
    let copied = ["out/1.bin", "out/2.bin"]
        .iter()
        .filter(|f| dir.join(f).is_file())
        .count();
    assert_eq!(copied, 1);
    let rep = sb.report(&job);
    let msg = rep["steps"][0]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("artifacts") && msg.contains("limit"), "{rep}");
}

/// R106: artefact paths must stay in the repo.
#[test]
fn artifact_paths_are_validated_r106() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"x\"\nkind = \"command\"\nrun = \"true\"\nartifacts = [\"../up\"]\n",
    );
    let r = sb.tollgate(&repo, &["config", "--check"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("artifacts"), "{}", r.out);
}
