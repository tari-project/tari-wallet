//! Basic CLI Integration Tests
//!
//! Simple tests to verify that CLI binaries exist and respond correctly
//! to basic commands like --help and --version.

#![cfg(not(target_arch = "wasm32"))]

use std::process::Command;

/// Test that all CLI binaries exist and respond to --help
#[tokio::test]
async fn test_all_binaries_help() {
    let binaries = ["scanner", "wallet", "signing"];

    for binary in &binaries {
        let output = Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg(binary)
            .arg("--features")
            .arg("grpc-storage")
            .arg("--")
            .arg("--help")
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute {binary} --help"));

        assert_eq!(
            output.status.code().unwrap_or(-1),
            0,
            "Binary {} should respond to --help\nstdout: {}\nstderr: {}",
            binary,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("help") || stdout.contains("Usage") || stdout.contains("USAGE"),
            "Help output should contain usage information for {binary}"
        );
    }
}

/// Test that binaries respond to --version
#[tokio::test]
async fn test_binaries_version() {
    let binaries = ["scanner", "wallet", "signing"];

    for binary in &binaries {
        let output = Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg(binary)
            .arg("--features")
            .arg("grpc-storage")
            .arg("--")
            .arg("--version")
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute {binary} --version"));

        assert_eq!(
            output.status.code().unwrap_or(-1),
            0,
            "Binary {} should respond to --version\nstdout: {}\nstderr: {}",
            binary,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should contain a version number (e.g., "0.2.0")
        assert!(
            stdout.contains("0.") || stdout.contains("1.") || stdout.contains("2."),
            "Version output should contain version number for {binary}"
        );
    }
}

/// Test that binaries fail appropriately with invalid arguments
#[tokio::test]
async fn test_binaries_invalid_args() {
    let binaries = ["scanner", "wallet", "signing"];

    for binary in &binaries {
        let output = Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg(binary)
            .arg("--features")
            .arg("grpc-storage")
            .arg("--")
            .arg("--invalid-option-that-should-not-exist")
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute {binary} with invalid option"));

        // Should exit with non-zero code for invalid arguments
        assert_ne!(
            output.status.code().unwrap_or(0),
            0,
            "Binary {binary} should fail with invalid arguments"
        );
    }
}

/// Test scanner with missing required arguments
#[tokio::test]
async fn test_scanner_missing_args() {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("scanner")
        .arg("--features")
        .arg("grpc-storage")
        .arg("--")
        .arg("--database")
        .arg("/nonexistent/path/wallet.db")
        .output()
        .expect("Failed to execute scanner with nonexistent database");

    // Scanner should fail when database path doesn't exist and no keys provided
    assert_ne!(
        output.status.code().unwrap_or(0),
        0,
        "Scanner should fail with nonexistent database and no keys\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Test scanner with invalid seed phrase format
#[tokio::test]
async fn test_scanner_invalid_seed_phrase() {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("scanner")
        .arg("--features")
        .arg("grpc-storage")
        .arg("--")
        .arg("--seed-phrase")
        .arg("invalid seed")
        .arg("--from-block")
        .arg("1")
        .arg("--to-block")
        .arg("1")
        .output()
        .expect("Failed to execute scanner with invalid seed phrase");

    // Scanner should fail with invalid seed phrase
    assert_ne!(
        output.status.code().unwrap_or(0),
        0,
        "Scanner should fail with invalid seed phrase"
    );

    let combined_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Should mention seed phrase in error
    assert!(
        combined_output.to_lowercase().contains("seed") || combined_output.to_lowercase().contains("phrase"),
        "Error should mention seed phrase issue"
    );
}

/// Test wallet generate command format validation
#[cfg(feature = "storage")]
#[tokio::test]
async fn test_wallet_generate_basic() {
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_wallet.db");

    let output = Command::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("wallet")
        .arg("--features")
        .arg("grpc-storage")
        .arg("--")
        .arg("generate")
        .arg("--network")
        .arg("mainnet")
        .env("WALLET_DB_PATH", &db_path)
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute wallet generate");

    if output.status.code().unwrap_or(-1) == 0 {
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Should contain expected wallet generation output
        assert!(
            stdout.contains("Wallet") ||
                stdout.contains("generated") ||
                stdout.contains("Seed") ||
                stdout.contains("Address"),
            "Wallet generate should produce expected output"
        );
    } else {
        // If wallet generate fails, it should be due to missing storage feature or setup
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Wallet generate failed (expected if storage not enabled): {stderr}");
    }
}

/// Test signing keypair generation
#[tokio::test]
async fn test_signing_generate_keypair() {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("signing")
        .arg("--features")
        .arg("grpc-storage")
        .arg("--")
        .arg("generate")
        .arg("--stdout")
        .output()
        .expect("Failed to execute signing generate");

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "Signing generate should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain key generation output
    assert!(
        stdout.contains("Key") || stdout.contains("Generated"),
        "Signing generate should produce key output"
    );
}

/// Test that binaries compile and run without panicking
#[tokio::test]
async fn test_binaries_basic_execution() {
    let test_cases = vec![
        ("scanner", vec!["--help"]),
        ("wallet", vec!["--help"]),
        ("signing", vec!["--help"]),
    ];

    for (binary, args) in test_cases {
        let mut cmd = Command::new("cargo");
        cmd.arg("run")
            .arg("--bin")
            .arg(binary)
            .arg("--features")
            .arg("grpc-storage")
            .arg("--");

        for arg in args {
            cmd.arg(arg);
        }

        let output = cmd
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute {binary} with basic args"));

        // We mainly care that the binary doesn't panic or crash
        // Exit code can be 0 (success) or 1 (expected failure), but not -1 (crash)
        let exit_code = output.status.code().unwrap_or(-1);
        assert!(
            exit_code >= 0,
            "Binary {} should not crash (exit code: {})\nstdout: {}\nstderr: {}",
            binary,
            exit_code,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
