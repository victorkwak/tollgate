//! TypeScript/Bun jobs end to end: real bun, biome and tsc on a generated
//! project, with no network (R45, R46, R59, R79, R80, T25).
//!
//! The tools come from this machine (see `support::tools`); a test skips
//! with a `SKIP` line when one is missing.

mod support;

use std::path::PathBuf;

use support::{Sandbox, job_id, tools};

const POLICY: &str = r#"version = 1

[[setup]]
name = "bun install"
run = "bun install --frozen-lockfile"
cwd = "web"
when = ["web/package.json", "web/bun.lock"]

[[step]]
name = "biome"
kind = "biome"
cwd = "web"

[[step]]
name = "tsc"
kind = "tsc"
cwd = "web"

[[step]]
name = "test"
kind = "bun-test"
cwd = "web"
"#;

struct Project {
    sb: Sandbox,
    repo: PathBuf,
    biome: PathBuf,
}

fn step<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no step {name} in {report}"))
}

/// A repo with a Bun project in `web/` (biome, typescript, `bun test`),
/// its `bun.lock`, and `policy` as `tollgate.toml`, committed on `main`.
fn project(test: &str, policy: Option<&str>) -> Option<Project> {
    let Some(bun) = tools::which("bun") else {
        tools::skip(test, "bun is not on PATH");
        return None;
    };
    let sb = Sandbox::new();
    let Some((biome_pkg, ts_pkg)) = tools::ts_packages(&sb.root().join("pkgs")) else {
        tools::skip(
            test,
            "no cached biome binary (~/.bun/install/cache/@biomejs) or no tsc on PATH",
        );
        return None;
    };
    let repo = sb.root().join("app");
    let web = repo.join("web");
    std::fs::create_dir_all(web.join("vendor")).unwrap();
    std::os::unix::fs::symlink(&biome_pkg, web.join("vendor/biome")).unwrap();
    std::os::unix::fs::symlink(&ts_pkg, web.join("vendor/typescript")).unwrap();
    if let Some(policy) = policy {
        std::fs::write(repo.join("tollgate.toml"), policy).unwrap();
    }
    let files: &[(&str, &str)] = &[
        (".gitignore", "node_modules/\n"),
        (
            "web/package.json",
            r#"{"name":"web","private":true,"scripts":{"test":"bun test"},"devDependencies":{"@biomejs/biome":"file:./vendor/biome","typescript":"file:./vendor/typescript"}}"#,
        ),
        (
            "web/biome.json",
            r#"{"files":{"includes":["**","!vendor"]}}"#,
        ),
        (
            "web/tsconfig.json",
            r#"{"compilerOptions":{"strict":true,"noEmit":true,"target":"es2022","module":"esnext","moduleResolution":"bundler","types":[]},"include":["src"],"exclude":["src/**/*.test.ts"]}"#,
        ),
        (
            "web/src/a.ts",
            "export const one = (x: number): number => x + 1;\n",
        ),
        (
            "web/src/a.test.ts",
            "import { expect, test } from \"bun:test\";\nimport { one } from \"./a\";\n\ntest(\"one\", () => {\n\texpect(one(1)).toBe(2);\n});\n",
        ),
    ];
    for (p, text) in files {
        let path = repo.join(p);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    sb.git(&repo, &["init", "-q"]);
    let env = sb.env();
    let offline = tools::offline_env(&sb.root());
    let biome = biome_pkg.join("biome");
    tools::run(&biome, &["format", "--write", "."], &web, &env, &offline);
    tools::run(&bun, &["install"], &web, &env, &offline);
    assert!(web.join("bun.lock").is_file());
    sb.git(&repo, &["add", "-A"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "web"]);
    sb.host_config(&format!(
        "[verify]\nmin_free = \"1M\"\n{}",
        tools::job_config(&[&bun])
    ));
    Some(Project { sb, repo, biome })
}

impl Project {
    fn write(&self, path: &str, text: &str) {
        let p = self.repo.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        self.sb.git(&self.repo, &["add", path]);
    }

    fn check(&self, args: &[&str]) -> (Option<i32>, String, serde_json::Value) {
        let r = self.sb.tollgate(&self.repo, args);
        let job = job_id(&r.out);
        (r.code, r.out, self.sb.report(&job))
    }
}

fn command(report: &serde_json::Value, name: &str) -> String {
    step(report, name)["command"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn bun_project_full_then_fast_lints_only_changed_files_r59_r46_t25() {
    let Some(p) = project("bun_project_full_then_fast", Some(POLICY)) else {
        return;
    };
    // Full: setup installs node_modules in the checkout (R45), every step
    // runs on the whole root with the project's own tools (R46).
    let (code, out, report) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(0), "{out}\n{report}");
    for s in ["biome", "tsc", "test"] {
        assert_eq!(step(&report, s)["status"], "pass", "{s}: {report}");
    }
    let biome = command(&report, "biome");
    assert!(
        biome.contains("/web/node_modules/.bin/biome check --files-ignore-unknown=true --no-errors-on-unmatched"),
        "{biome}"
    );
    assert!(
        !biome.contains(" -- "),
        "full lints the whole root: {biome}"
    );
    assert!(command(&report, "tsc").ends_with("/web/node_modules/.bin/tsc --noEmit"));
    assert_eq!(command(&report, "test"), "bun run test");
    let job = report["job_id"].as_str().unwrap();
    let log = std::fs::read_to_string(p.sb.state().join("jobs").join(job).join("job.log")).unwrap();
    assert!(log.contains("setup \"bun install\": ran"), "{log}");

    // Fast on a type error: tsc checks the whole root and fails; biome lints
    // only the changed file (R59); the record keeps that file list (R80).
    p.write(
        "web/src/a.ts",
        "export const one = (x: number): number => x + 1;\nexport const bad: number = \"one\";\n",
    );
    let (code, out, report) = p.check(&["check", "--wait"]);
    assert_eq!(code, Some(1), "{out}");
    assert_eq!(report["tier"], "fast");
    assert_eq!(step(&report, "tsc")["status"], "fail", "{report}");
    assert!(
        out.contains("TS2322"),
        "tsc output in the report tail: {out}"
    );
    assert_eq!(step(&report, "biome")["status"], "pass", "{report}");
    assert!(
        command(&report, "biome").ends_with(" -- src/a.ts"),
        "{report}"
    );
    assert_eq!(
        step(&report, "biome")["scope"],
        serde_json::json!({"files": {"files": ["web/src/a.ts"]}})
    );
    assert_eq!(
        report["selection"]["subset"]["files"]["biome"],
        serde_json::json!(["web/src/a.ts"]),
        "{report}"
    );

    // A file biome rejects fails biome; a failing bun test fails the test
    // step.
    p.write(
        "web/src/a.ts",
        "export const one = (x: number): number => x + 1;\n",
    );
    p.write("web/src/b.ts", "export const b={x:1}\n");
    p.write(
        "web/src/b.test.ts",
        "import { expect, test } from \"bun:test\";\n\ntest(\"b\", () => {\n\texpect(1).toBe(2);\n});\n",
    );
    let (code, out, report) = p.check(&["check", "--wait"]);
    assert_eq!(code, Some(1), "{out}");
    assert_eq!(step(&report, "biome")["status"], "fail", "{report}");
    assert_eq!(step(&report, "tsc")["status"], "pass", "{report}");
    assert_eq!(step(&report, "test")["status"], "fail", "{report}");
    let log = std::fs::read_to_string(
        p.sb.state()
            .join("jobs")
            .join(report["job_id"].as_str().unwrap())
            .join("job.log"),
    )
    .unwrap();
    assert!(
        log.contains("setup \"bun install\": up to date"),
        "the sticky fast checkout keeps node_modules (L15): {log}"
    );
    let files = &step(&report, "biome")["scope"]["files"]["files"];
    assert_eq!(
        files,
        &serde_json::json!(["web/src/b.test.ts", "web/src/b.ts"])
    );
    // The project's own biome agrees on the file it rejected.
    let own = std::process::Command::new(&p.biome)
        .args(["check", "src/b.ts"])
        .current_dir(p.repo.join("web"))
        .output()
        .unwrap();
    assert!(!own.status.success());
}

/// R59: a solution-style tsconfig.json (`"files": []` plus `references`,
/// as the Vite TypeScript templates ship) makes `tsc --noEmit` check no
/// file at all. The step builds the references with `tsc -b`, so a type
/// error in a referenced project fails it.
#[test]
fn a_solution_style_tsconfig_checks_its_references_r59() {
    let Some(p) = project(
        "a_solution_style_tsconfig_checks_its_references",
        Some(POLICY),
    ) else {
        return;
    };
    p.write(
        "web/tsconfig.json",
        "// solution\n{\n  \"files\": [],\n  \"references\": [{ \"path\": \"./tsconfig.app.json\" },],\n}\n",
    );
    p.write(
        "web/tsconfig.app.json",
        r#"{"compilerOptions":{"strict":true,"noEmit":true,"target":"es2022","module":"esnext","moduleResolution":"bundler","types":[],"tsBuildInfoFile":"./node_modules/.tmp/app.tsbuildinfo"},"include":["src"],"exclude":["src/**/*.test.ts"]}"#,
    );
    p.write(
        "web/src/a.ts",
        "export const one = (x: number): number => x + 1;\nexport const bad: number = \"one\";\n",
    );
    // biome checks the new files too: write them as it formats them.
    let web = p.repo.join("web");
    let env = p.sb.env();
    let offline = tools::offline_env(&p.sb.root());
    tools::run(&p.biome, &["format", "--write", "."], &web, &env, &offline);
    p.sb.git(&p.repo, &["add", "-A"]);
    let (code, out, report) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(1), "{out}\n{report}");
    assert_eq!(step(&report, "biome")["status"], "pass", "{report}");
    assert_eq!(step(&report, "tsc")["status"], "fail", "{report}");
    assert!(out.contains("TS2322"), "{out}");
    assert!(
        command(&report, "tsc").ends_with("/web/node_modules/.bin/tsc -b --force"),
        "{report}"
    );
    // Fixed: the build passes; its tsbuildinfo goes to node_modules, which
    // .gitignore lists, so the checkout stays clean (R42).
    p.write(
        "web/src/a.ts",
        "export const one = (x: number): number => x + 1;\n",
    );
    let (code, out, report) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(0), "{out}\n{report}");
    assert_eq!(step(&report, "tsc")["status"], "pass", "{report}");
}

#[test]
fn changes_outside_the_root_skip_its_steps_and_docs_pass_r59_r61() {
    let Some(p) = project("changes_outside_the_root_skip_its_steps", Some(POLICY)) else {
        return;
    };
    let (code, out, _) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(0), "{out}");
    p.write("scripts/run.sh", "echo hi\n");
    let (code, out, report) = p.check(&["check", "--wait"]);
    assert_eq!(code, Some(0), "{out}");
    for s in ["biome", "tsc", "test"] {
        assert_eq!(step(&report, s)["status"], "skipped", "{s}: {report}");
        assert_eq!(step(&report, s)["message"], "no change under its root");
    }
    // R61: a root README is docs-only; one inside the TS root is code.
    p.sb.git(&p.repo, &["reset", "-q", "--hard"]);
    p.write("README.md", "# app\n");
    let (code, out, report) = p.check(&["check", "--wait"]);
    assert_eq!(code, Some(0), "{out}");
    for s in ["biome", "tsc", "test"] {
        assert_eq!(
            step(&report, s)["message"],
            "docs-only change (R61)",
            "{report}"
        );
    }
    p.write("web/NOTES.md", "# notes\n");
    let (code, out, report) = p.check(&["check", "--wait"]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(step(&report, "tsc")["status"], "pass", "{report}");
    assert_eq!(
        step(&report, "biome")["scope"]["files"]["files"],
        serde_json::json!(["web/NOTES.md"]),
        "{report}"
    );
}

#[test]
fn a_missing_project_tool_is_a_setup_error_r46() {
    // No bun needed: without the setup step there is no node_modules.
    let sb = Sandbox::new();
    sb.host_config("[verify]\nmin_free = \"1M\"\n");
    let repo = sb.repo("app");
    sb.commit_file(&repo, "web/package.json", "{\"name\":\"web\"}\n", "web");
    sb.commit_file(&repo, "web/bun.lock", "{}\n", "lock");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"lint\"\nkind = \"biome\"\ncwd = \"web\"\n",
        "policy",
    );
    let r = sb.tollgate(&repo, &["check", "--tier", "full", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    let report = sb.report(&job_id(&r.out));
    assert_eq!(report["verdict"], "error");
    assert_eq!(report["cause"], "setup");
    assert!(
        r.out
            .contains("node_modules/.bin/biome is missing under web"),
        "{}",
        r.out
    );
    assert_eq!(step(&report, "lint")["status"], "error");
}

#[test]
fn detection_installs_and_checks_a_bun_root_t25_r65_r45_r47() {
    let Some(p) = project("detection_installs_and_checks_a_bun_root", None) else {
        return;
    };
    // No tollgate.toml: detection names the setup and the steps (R65).
    let eff = p.sb.tollgate(&p.repo, &["config", "--effective"]);
    assert_eq!(eff.code, Some(0), "{}", eff.out);
    for needle in [
        "# source: detection (R65)",
        "name = \"web bun install\"",
        "run = \"bun install --frozen-lockfile\"",
        "kind = \"biome\"",
        "kind = \"tsc\"",
        "kind = \"bun-test\"",
    ] {
        assert!(eff.out.contains(needle), "{needle:?} in\n{}", eff.out);
    }
    let (code, out, report) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(0), "{out}\n{report}");
    for s in ["web biome", "web tsc", "web bun test"] {
        assert_eq!(step(&report, s)["status"], "pass", "{s}: {report}");
    }
    let job = report["job_id"].as_str().unwrap();
    let log = std::fs::read_to_string(p.sb.state().join("jobs").join(job).join("job.log")).unwrap();
    assert!(log.contains("setup \"web bun install\": ran"), "T25: {log}");

    // CI mode in a fresh clone: the setup runs there too (R45, R47).
    let ci = p.sb.root().join("ci");
    p.sb.git(&p.sb.root(), &["clone", "-q", "app", "ci"]);
    assert!(!ci.join("web/node_modules").exists());
    let r = p.sb.tollgate_with(
        &ci,
        &["run", "--tier", "full", "--here", "--report", "junit"],
        &[],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(ci.join("web/node_modules/.bin/biome").is_file());
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ci.join("tollgate-report/report.json")).unwrap())
            .unwrap();
    assert_eq!(report["verdict"], "pass", "{report}");
    // R47, R73: the JUnit report has a case per step.
    let junit = std::fs::read_to_string(ci.join("tollgate-report/junit.xml")).unwrap();
    for s in ["web biome", "web tsc", "web bun test"] {
        assert!(
            junit.contains(&format!("<testcase name=\"{s}\" classname=\"tollgate\"")),
            "{s}: {junit}"
        );
    }
    assert!(junit.contains("failures=\"0\" errors=\"0\""), "{junit}");
}

/// L2, R65, D5: with no tollgate.toml, a branch cannot drop detected steps.
/// Detection also runs on the policy commit, and its steps stay: a branch
/// that deletes the `test` script still runs `bun test`, which then fails
/// as a setup error, not as a silent pass.
#[test]
fn a_branch_cannot_drop_detected_steps_l2_r65() {
    let Some(p) = project("a_branch_cannot_drop_detected_steps", None) else {
        return;
    };
    p.sb.git(&p.repo, &["checkout", "-q", "-b", "feat"]);
    let web = p.repo.join("web");
    std::fs::write(
        web.join("package.json"),
        r#"{"name":"web","private":true,"devDependencies":{"@biomejs/biome":"file:./vendor/biome","typescript":"file:./vendor/typescript"}}"#,
    )
    .unwrap();
    let env = p.sb.env();
    let offline = tools::offline_env(&p.sb.root());
    tools::run(&p.biome, &["format", "--write", "."], &web, &env, &offline);
    p.sb.git(&p.repo, &["add", "-A"]);
    p.sb.git(
        &p.repo,
        &["commit", "-q", "--no-verify", "-m", "drop tests"],
    );
    let (code, out, report) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(1), "{out}\n{report}");
    let test = step(&report, "web bun test");
    assert_eq!(test["status"], "error", "{report}");
    assert!(
        test["message"]
            .as_str()
            .unwrap_or_default()
            .contains("test"),
        "{report}"
    );
    for s in ["web biome", "web tsc"] {
        assert_eq!(step(&report, s)["status"], "pass", "{s}: {report}");
    }
    let warnings = report["warnings"].to_string();
    assert!(
        warnings.contains("web bun test") && warnings.contains("policy commit"),
        "{report}"
    );
    // On main itself (the policy commit is the tree), nothing changes.
    p.sb.git(&p.repo, &["checkout", "-q", "main"]);
    let (code, out, _) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(0), "{out}");
}
