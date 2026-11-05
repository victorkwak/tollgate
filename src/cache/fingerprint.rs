//! Fingerprint computation (R74).
//!
//! Keys: `tollgate` (version), `git`, `rustc`, `cargo`, `cargo-nextest`
//! (Rust roots), `bun` (TypeScript roots), `uv` (Python roots), `uname`
//! (`<sysname> <machine>`), `host-config`, `effective-config`, `job-env`,
//! `env-file:<path>` per step env file, `image:<resource>` per configured
//! image of a resource a step takes. A tool not on the job `PATH` is
//! `absent`.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::path::Path;
use std::process::{Command, Stdio};

use super::Fingerprint;
use super::toolcache::{Probe, ProbeError, ToolCache};
use crate::ids::ResourceName;
use crate::runner::env::{EnvFile, JobEnv};

/// `git --version`.
pub const GIT: Probe = Probe {
    id: "git",
    program: "git",
    args: &["--version"],
};
/// `rustc -vV`.
pub const RUSTC: Probe = Probe {
    id: "rustc",
    program: "rustc",
    args: &["-vV"],
};
/// `cargo --version`.
pub const CARGO: Probe = Probe {
    id: "cargo",
    program: "cargo",
    args: &["--version"],
};
/// `cargo nextest --version`, run as `cargo-nextest nextest --version` so the
/// identity is the nextest binary, not the cargo proxy.
pub const NEXTEST: Probe = Probe {
    id: "cargo-nextest",
    program: "cargo-nextest",
    args: &["nextest", "--version"],
};
/// `bun --version`.
pub const BUN: Probe = Probe {
    id: "bun",
    program: "bun",
    args: &["--version"],
};
/// `uv --version`.
pub const UV: Probe = Probe {
    id: "uv",
    program: "uv",
    args: &["--version"],
};

/// Which kinds of roots the tree has (R57, R59, R60).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Roots {
    /// A Cargo workspace or package.
    pub rust: bool,
    /// A Bun project.
    pub typescript: bool,
    /// A Python project.
    pub python: bool,
}

/// Everything a fingerprint is made of.
#[derive(Debug, Clone, Copy)]
pub struct FingerprintInputs<'a> {
    /// Root kinds in the tree.
    pub roots: Roots,
    /// The base job environment (R52).
    pub job_env: &'a JobEnv,
    /// Where tools are probed (the verify checkout): rust-toolchain files.
    pub cwd: &'a Path,
    /// blake3 of the host config file.
    pub host_config_hash: &'a str,
    /// Hash of the effective repo config (R65).
    pub effective_config_hash: &'a str,
    /// Env files of the steps that run.
    pub env_files: &'a [EnvFile],
    /// Configured images of the resources the steps take.
    pub images: &'a BTreeMap<ResourceName, String>,
}

/// Error while computing a fingerprint.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    /// A tool probe failed.
    #[error("tool probe: {0}")]
    Probe(#[from] ProbeError),
    /// An image id could not be read. R34: verdict `error`, cause `docker`,
    /// no record.
    #[error("docker image {image}: {message}")]
    Docker {
        /// Image.
        image: String,
        /// Why.
        message: String,
    },
}

/// `<sysname> <machine>` from `uname(2)`, as `uname -sm` prints it.
#[must_use]
pub fn uname_sm() -> String {
    // SAFETY: `utsname` is plain old data; zeroed is a valid value, and
    // `uname` fills it. The fields are NUL-terminated on success.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `u` is a valid, writable `utsname`.
    if unsafe { libc::uname(&raw mut u) } != 0 {
        return format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    }
    // SAFETY: on success both fields hold NUL-terminated strings.
    let field = |f: &[libc::c_char]| {
        unsafe { CStr::from_ptr(f.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    format!("{} {}", field(&u.sysname), field(&u.machine))
}

/// `docker image inspect --format {{.Id}} <image>` with the job environment.
pub fn docker_image_id(image: &str, env: &JobEnv) -> Result<String, FingerprintError> {
    let err = |message: String| FingerprintError::Docker {
        image: image.to_owned(),
        message,
    };
    let mut cmd = Command::new("docker");
    env.apply(&mut cmd)
        .args(["image", "inspect", "--format", "{{.Id}}", "--", image])
        .stdin(Stdio::null());
    let out = cmd.output().map_err(|e| err(e.to_string()))?;
    if !out.status.success() {
        return Err(err(String::from_utf8_lossy(&out.stderr).trim().to_owned()));
    }
    let id = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if id.is_empty() {
        return Err(err("empty image id".into()));
    }
    Ok(id)
}

/// Computes the fingerprint (R74). Tool versions come from `tools` (R75).
pub fn compute(
    inputs: &FingerprintInputs<'_>,
    tools: &mut ToolCache,
) -> Result<Fingerprint, FingerprintError> {
    let mut fp = Fingerprint::new();
    fp.insert("tollgate", crate::VERSION);
    let mut probes = vec![GIT];
    if inputs.roots.rust {
        probes.extend([RUSTC, CARGO, NEXTEST]);
    }
    if inputs.roots.typescript {
        probes.push(BUN);
    }
    if inputs.roots.python {
        probes.push(UV);
    }
    for p in &probes {
        let r = tools.probe(p, inputs.job_env, inputs.cwd)?;
        fp.insert(p.id, r.fingerprint_value());
    }
    fp.insert("uname", uname_sm());
    fp.insert("host-config", inputs.host_config_hash);
    fp.insert("effective-config", inputs.effective_config_hash);
    fp.insert("job-env", inputs.job_env.fingerprint_hash());
    for f in inputs.env_files {
        fp.insert(format!("env-file:{}", f.path.display()), f.hash.clone());
    }
    for (resource, image) in inputs.images {
        fp.insert(
            format!("image:{resource}"),
            docker_image_id(image, inputs.job_env)?,
        );
    }
    Ok(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uname_matches_the_uname_command() {
        let out = Command::new("uname").arg("-sm").output().unwrap();
        assert_eq!(uname_sm(), String::from_utf8_lossy(&out.stdout).trim());
    }
}
