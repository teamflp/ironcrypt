//! Resolve secrets (passphrases) without putting them on the argv.
//!
//! Preference order:
//! 1. `IRONCRYPT_PASSPHRASE` env
//! 2. `IRONCRYPT_PASSPHRASE_FILE` (contents of file, trimmed)
//! 3. `IRONCRYPT_PASSPHRASE_FD` (read from file descriptor; Unix)
//! 4. `IRONCRYPT_PASSPHRASE_STDIN=1` (one line from stdin)
//! 5. explicit CLI / API value (discouraged in Payment — visible in `ps`)
//! 6. with [`resolve_passphrase_or_prompt`]: interactive TTY (CLI + `rpassword`)

use crate::IronCryptError;
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal};
use zeroize::Zeroizing;

/// Env var holding the passphrase directly.
pub const PASSPHRASE_ENV: &str = "IRONCRYPT_PASSPHRASE";
/// Env var pointing at a file that contains the passphrase.
pub const PASSPHRASE_FILE_ENV: &str = "IRONCRYPT_PASSPHRASE_FILE";
/// Env var with a file-descriptor number to read the passphrase from (Unix).
pub const PASSPHRASE_FD_ENV: &str = "IRONCRYPT_PASSPHRASE_FD";
/// When set to `1`/`true`, read one line from stdin (for pipes / heredocs).
pub const PASSPHRASE_STDIN_ENV: &str = "IRONCRYPT_PASSPHRASE_STDIN";

/// Resolve a passphrase, preferring env / file / fd / stdin over `cli_value`.
///
/// Returns `None` when nothing is configured. The returned string is wrapped in
/// [`Zeroizing`] so it is wiped on drop.
pub fn resolve_passphrase(
    cli_value: Option<String>,
) -> Result<Option<Zeroizing<String>>, IronCryptError> {
    resolve_passphrase_inner(cli_value, false)
}

/// Like [`resolve_passphrase`], but if nothing else is set and stdin is a TTY,
/// prompt interactively (CLI builds only).
pub fn resolve_passphrase_or_prompt(
    cli_value: Option<String>,
) -> Result<Option<Zeroizing<String>>, IronCryptError> {
    resolve_passphrase_inner(cli_value, true)
}

fn resolve_passphrase_inner(
    cli_value: Option<String>,
    prompt_tty: bool,
) -> Result<Option<Zeroizing<String>>, IronCryptError> {
    if let Ok(v) = env::var(PASSPHRASE_ENV) {
        if !v.is_empty() {
            warn_ignore_cli(cli_value.is_some(), PASSPHRASE_ENV);
            return Ok(Some(Zeroizing::new(v)));
        }
    }

    if let Ok(path) = env::var(PASSPHRASE_FILE_ENV) {
        if !path.is_empty() {
            warn_ignore_cli(cli_value.is_some(), PASSPHRASE_FILE_ENV);
            return Ok(Some(read_passphrase_file(&path)?));
        }
    }

    if let Ok(fd_str) = env::var(PASSPHRASE_FD_ENV) {
        if !fd_str.is_empty() {
            warn_ignore_cli(cli_value.is_some(), PASSPHRASE_FD_ENV);
            return Ok(Some(read_passphrase_fd(&fd_str)?));
        }
    }

    if stdin_passphrase_requested() {
        warn_ignore_cli(cli_value.is_some(), PASSPHRASE_STDIN_ENV);
        return Ok(Some(read_passphrase_stdin_line()?));
    }

    if let Some(v) = cli_value {
        if cfg!(feature = "payment") {
            tracing::warn!(
                "--passphrase on the command line is discouraged under Payment \
                 (visible in process listings); prefer {PASSPHRASE_ENV}, \
                 {PASSPHRASE_FILE_ENV}, {PASSPHRASE_FD_ENV}, or TTY prompt"
            );
        }
        if v.is_empty() {
            return Ok(None);
        }
        return Ok(Some(Zeroizing::new(v)));
    }

    if prompt_tty {
        return read_passphrase_tty_optional();
    }

    Ok(None)
}

fn warn_ignore_cli(had_cli: bool, source: &str) {
    if had_cli {
        tracing::warn!("ignoring --passphrase: {source} is set (preferred for Payment)");
    }
}

fn stdin_passphrase_requested() -> bool {
    matches!(
        env::var(PASSPHRASE_STDIN_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn read_passphrase_file(path: &str) -> Result<Zeroizing<String>, IronCryptError> {
    let raw = fs::read_to_string(path).map_err(|e| {
        IronCryptError::ConfigurationError(format!(
            "failed to read {PASSPHRASE_FILE_ENV} ({path}): {e}"
        ))
    })?;
    let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(IronCryptError::ConfigurationError(format!(
            "{PASSPHRASE_FILE_ENV} file {path} is empty"
        )));
    }
    Ok(Zeroizing::new(trimmed))
}

fn read_passphrase_fd(fd_str: &str) -> Result<Zeroizing<String>, IronCryptError> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::fd::FromRawFd;

        let fd: i32 = fd_str.parse().map_err(|_| {
            IronCryptError::ConfigurationError(format!(
                "{PASSPHRASE_FD_ENV} must be an integer file descriptor, got '{fd_str}'"
            ))
        })?;
        if fd < 0 {
            return Err(IronCryptError::ConfigurationError(format!(
                "{PASSPHRASE_FD_ENV} must be >= 0"
            )));
        }
        // SAFETY: caller-provided FD; we only read and do not close it.
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let mut raw = String::new();
        file.read_to_string(&mut raw).map_err(|e| {
            IronCryptError::ConfigurationError(format!("failed to read passphrase FD {fd}: {e}"))
        })?;
        std::mem::forget(file);
        let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            return Err(IronCryptError::ConfigurationError(format!(
                "passphrase FD {fd} produced an empty secret"
            )));
        }
        Ok(Zeroizing::new(trimmed))
    }
    #[cfg(not(unix))]
    {
        let _ = fd_str;
        Err(IronCryptError::UnsupportedOperation(format!(
            "{PASSPHRASE_FD_ENV} is only supported on Unix"
        )))
    }
}

fn read_passphrase_stdin_line() -> Result<Zeroizing<String>, IronCryptError> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).map_err(|e| {
        IronCryptError::ConfigurationError(format!("failed to read passphrase from stdin: {e}"))
    })?;
    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(IronCryptError::ConfigurationError(
            "stdin passphrase was empty".into(),
        ));
    }
    Ok(Zeroizing::new(trimmed))
}

fn read_passphrase_tty_optional() -> Result<Option<Zeroizing<String>>, IronCryptError> {
    if !io::stdin().is_terminal() {
        return Ok(None);
    }
    #[cfg(feature = "cli")]
    {
        let s = rpassword::prompt_password("Passphrase (echo hidden): ").map_err(|e| {
            IronCryptError::ConfigurationError(format!("TTY passphrase prompt failed: {e}"))
        })?;
        if s.is_empty() {
            return Ok(None);
        }
        return Ok(Some(Zeroizing::new(s)));
    }
    #[cfg(not(feature = "cli"))]
    {
        Ok(None)
    }
}

/// Borrow the passphrase as `Option<&str>` for existing APIs.
pub fn passphrase_as_str(p: &Option<Zeroizing<String>>) -> Option<&str> {
    p.as_ref().map(|s| s.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn prefers_env_over_cli() {
        let _g = ENV_LOCK.lock().unwrap();
        env::set_var(PASSPHRASE_ENV, "from-env");
        env::remove_var(PASSPHRASE_FILE_ENV);
        env::remove_var(PASSPHRASE_FD_ENV);
        env::remove_var(PASSPHRASE_STDIN_ENV);
        let got = resolve_passphrase(Some("from-cli".into())).unwrap().unwrap();
        assert_eq!(got.as_str(), "from-env");
        env::remove_var(PASSPHRASE_ENV);
    }

    #[test]
    fn prefers_file_over_cli() {
        let _g = ENV_LOCK.lock().unwrap();
        env::remove_var(PASSPHRASE_ENV);
        env::remove_var(PASSPHRASE_FD_ENV);
        env::remove_var(PASSPHRASE_STDIN_ENV);
        let path = env::temp_dir().join(format!("ironcrypt-pass-test-{}", std::process::id()));
        fs::write(&path, "from-file\n").unwrap();
        env::set_var(PASSPHRASE_FILE_ENV, path.to_str().unwrap());
        let got = resolve_passphrase(Some("from-cli".into())).unwrap().unwrap();
        assert_eq!(got.as_str(), "from-file");
        env::remove_var(PASSPHRASE_FILE_ENV);
        let _ = fs::remove_file(&path);
    }
}
