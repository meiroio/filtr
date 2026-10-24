use std::{path::Path, process::Command};

fn command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_filtr"));
    command.current_dir(directory).env_clear();
    command
}

#[test]
fn missing_dotenv_is_optional_and_parent_directories_are_not_searched() {
    let directory = tempfile::tempdir().unwrap();
    assert!(
        command(directory.path())
            .arg("--help")
            .output()
            .unwrap()
            .status
            .success()
    );
    std::fs::write(
        directory.path().join(".env"),
        "MALFORMED='private-unclosed-value",
    )
    .unwrap();
    let child = directory.path().join("child");
    std::fs::create_dir(&child).unwrap();
    assert!(
        command(&child)
            .arg("--help")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn malformed_dotenv_errors_never_expose_its_contents() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(".env"),
        "ANTHROPIC_API_KEY='private-unclosed-value",
    )
    .unwrap();
    let output = command(directory.path()).arg("--help").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot load .env"));
    assert!(!stderr.contains("private-unclosed-value"));
    assert!(!stderr.contains("ANTHROPIC_API_KEY"));
}

#[test]
fn precedence_is_cli_then_process_environment_then_dotenv() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(".env"), format!(
        "FILTR_UPSTREAM='file-value'\nFILTR_ADMIN_TOKEN={}\nANTHROPIC_API_KEY=private-test-key\n", "ab".repeat(64)
    )).unwrap();
    for (environment, cli, expected) in [
        (None, None, "file-value"),
        (Some("environment-value"), None, "environment-value"),
        (Some("environment-value"), Some("cli-value"), "cli-value"),
    ] {
        let mut process = command(directory.path());
        if let Some(value) = environment {
            process.env("FILTR_UPSTREAM", value);
        }
        if let Some(value) = cli {
            process.args(["--upstream", value]);
        }
        let output = process.output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("invalid value '{expected}'")),
            "unexpected precedence error"
        );
        assert!(!stderr.contains("private-test-key"));
    }
}
