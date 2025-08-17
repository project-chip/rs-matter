use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Development tasks for rs-matter ConnectedHomeIP integration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Setup ConnectedHomeIP environment for integration testing
    ItestSetup {
        /// ConnectedHomeIP repository reference (branch/tag/commit)
        #[arg(long, default_value = "master")]
        connectedhomeip_ref: String,
        /// Force rebuild even if cached
        #[arg(long)]
        force_rebuild: bool,
    },
    /// Build rs-matter examples
    Build {
        /// Build profile (debug or release)
        #[arg(long, default_value = "debug")]
        profile: String,
        /// Additional cargo features
        #[arg(long)]
        features: Vec<String>,
    },
    /// Run ConnectedHomeIP YAML integration tests
    Itest {
        /// Test names to run (if empty, runs all enabled tests)
        tests: Vec<String>,
        /// Build profile to use for rs-matter examples
        #[arg(long, default_value = "debug")]
        profile: String,
        /// Timeout for each test in seconds
        #[arg(long, default_value = "120")]
        timeout: u64,
        /// Skip building rs-matter (assume it's already built)
        #[arg(long)]
        skip_build: bool,
    },
}

const DEFAULT_FEATURES: &[&str] = &["log"];

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::ItestSetup { connectedhomeip_ref, force_rebuild } => {
            setup_connectedhomeip(connectedhomeip_ref, *force_rebuild)
        }
        Commands::Build { profile, features } => {
            build_rs_matter(profile, features)
        }
        Commands::Itest { tests, profile, timeout, skip_build } => {
            run_integration_tests(tests, profile, *timeout, *skip_build)
        }
    }
}

fn detect_host_platform() -> Result<String> {
    use std::env;
    
    let os = env::consts::OS;
    let platform = match os {
        "linux" => "linux",
        "macos" => "darwin", 
        _ => return Err(anyhow!("Unsupported platform for ConnectedHomeIP integration tests: {}", os)),
    };
    
    Ok(platform.to_string())
}

fn setup_connectedhomeip(connectedhomeip_ref: &str, force_rebuild: bool) -> Result<()> {
    let project_root = get_project_root()?;
    let connectedhomeip_dir = project_root.join(".build/itest/connectedhomeip");

    println!("Setting up ConnectedHomeIP environment...");

    // Check system dependencies
    check_system_dependencies()?;

    // Clone or update ConnectedHomeIP repository
    if !connectedhomeip_dir.exists() {
        println!("Cloning ConnectedHomeIP repository (shallow clone)...");
        // Ensure parent directories exist
        if let Some(parent) = connectedhomeip_dir.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create parent directories for ConnectedHomeIP")?;
        }
        run_command(
            Command::new("git")
                .args(&["clone", "--depth=1", 
                       "https://github.com/project-chip/connectedhomeip.git"])
                .arg(&connectedhomeip_dir)
        )?;
    } else {
        println!("ConnectedHomeIP repository already exists");
        if force_rebuild {
            println!("Force rebuild requested, cleaning build artifacts...");
            let out_dir = connectedhomeip_dir.join("out");
            if out_dir.exists() {
                std::fs::remove_dir_all(&out_dir)
                    .context("Failed to remove existing out directory")?;
            }
        }
    }

    // Checkout the specified reference
    println!("Checking out reference: {}", connectedhomeip_ref);
    run_command(
        Command::new("git")
            .args(&["checkout", connectedhomeip_ref])
            .current_dir(&connectedhomeip_dir)
    )?;

    // Detect host platform for selective submodule initialization
    let platform = detect_host_platform()?;
    println!("Detected platform: {}", platform);
    
    // Initialize submodules selectively for host platform only
    println!("Initializing submodules for platform: {}...", platform);
    run_command(
        Command::new("python3")
            .args(&["scripts/checkout_submodules.py", "--shallow", "--platform", &platform])
            .current_dir(&connectedhomeip_dir)
    )?;

    // Setup Python environment
    setup_python_environment(&connectedhomeip_dir)?;

    // Build chip-tool if not cached or force rebuild
    let chip_tool_path = connectedhomeip_dir.join("out/host/chip-tool");
    if !chip_tool_path.exists() || force_rebuild {
        build_chip_tool(&connectedhomeip_dir)?;
    } else {
        println!("Using existing chip-tool build");
    }

    println!("ConnectedHomeIP environment setup completed successfully!");
    Ok(())
}

fn build_rs_matter(profile: &str, additional_features: &[String]) -> Result<()> {
    let project_root = get_project_root()?;
    let examples_dir = project_root.join("examples");

    println!("Building rs-matter examples...");

    let mut features = DEFAULT_FEATURES.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    features.extend_from_slice(additional_features);
    let features_str = features.join(",");

    let mut cmd = Command::new("cargo");
    cmd.args(&["build", "--bin", "chip_tool_tests"])
        .arg("--features").arg(&features_str)
        .current_dir(&examples_dir);

    if profile == "release" {
        cmd.arg("--release");
    }

    run_command(&mut cmd)?;
    println!("rs-matter examples built successfully!");
    Ok(())
}

fn run_integration_tests(
    tests: &[String],
    profile: &str,
    timeout: u64,
    skip_build: bool,
) -> Result<()> {
    let project_root = get_project_root()?;
    let connectedhomeip_dir = project_root.join(".build/itest/connectedhomeip");

    // Verify ConnectedHomeIP is set up
    if !connectedhomeip_dir.exists() {
        return Err(anyhow!(
            "ConnectedHomeIP not found. Run 'cargo xtask itest-setup' first."
        ));
    }

    let chip_tool_path = connectedhomeip_dir.join("out/host/chip-tool");
    if !chip_tool_path.exists() {
        return Err(anyhow!(
            "chip-tool not found. Run 'cargo xtask itest-setup' first."
        ));
    }

    // Build rs-matter if requested
    if !skip_build {
        build_rs_matter(profile, &[])?;
    }

    // Determine which tests to run
    let tests_to_run = if tests.is_empty() {
        get_enabled_tests()
    } else {
        tests.to_vec()
    };

    if tests_to_run.is_empty() {
        println!("No tests specified and no default tests enabled.");
        return Ok(());
    }

    println!("Running integration tests: {:?}", tests_to_run);

    // Setup environment variables
    let rs_matter_data = tempfile::tempdir()
        .context("Failed to create temporary directory for rs-matter data")?;
    
    // Clean up any existing data
    if rs_matter_data.path().exists() {
        std::fs::remove_dir_all(rs_matter_data.path())
            .context("Failed to clean rs-matter data directory")?;
    }

    let profile_dir = if profile == "release" { "release" } else { "debug" };
    let chip_tool_tests_path = project_root
        .join("target")
        .join(profile_dir)
        .join("chip_tool_tests");

    // Run each test
    for test_name in tests_to_run {
        println!("\n=== Running test: {} ===", test_name);
        run_yaml_test(&connectedhomeip_dir, &test_name, &chip_tool_tests_path, timeout)?;
    }

    println!("\nAll integration tests completed successfully!");
    Ok(())
}

fn run_yaml_test(
    connectedhomeip_dir: &Path,
    test_name: &str,
    chip_tool_tests_path: &Path,
    timeout: u64,
) -> Result<()> {
    let script_path = connectedhomeip_dir.join("scripts/run_in_build_env.sh");
    let test_suite_path = connectedhomeip_dir.join("scripts/tests/run_test_suite.py");
    let chip_tool_path = connectedhomeip_dir.join("out/host/chip-tool");

    let test_command = format!(
        "{} --log-level warn --target {} --runner chip_tool_python --chip-tool {} run --iterations 1 --test-timeout-seconds {} --all-clusters-app {} --lock-app {}",
        test_suite_path.display(),
        test_name,
        chip_tool_path.display(),
        timeout,
        chip_tool_tests_path.display(),
        chip_tool_tests_path.display()
    );

    let mut cmd = Command::new(&script_path);
    cmd.arg(&test_command)
        .current_dir(connectedhomeip_dir)
        .env("CHIP_HOME", connectedhomeip_dir);

    run_command(&mut cmd)?;
    Ok(())
}

fn get_enabled_tests() -> Vec<String> {
    // Default enabled tests (can be made configurable via config file)
    vec!["TestAttributesById".to_string()]
}

fn check_system_dependencies() -> Result<()> {
    let dependencies = &["git", "python3", "pip3"];
    
    for dep in dependencies {
        if which::which(dep).is_err() {
            return Err(anyhow!("Required dependency '{}' not found in PATH", dep));
        }
    }
    
    println!("System dependencies check passed");
    Ok(())
}

fn setup_python_environment(connectedhomeip_dir: &Path) -> Result<()> {
    println!("Setting up Python environment...");
    
    let venv_dir = connectedhomeip_dir.join("venv");
    
    // Create virtual environment if it doesn't exist
    if !venv_dir.exists() {
        run_command(
            Command::new("python3")
                .args(&["-m", "venv", "venv"])
                .current_dir(connectedhomeip_dir)
        )?;
    }

    // Install requirements
    let requirements_path = connectedhomeip_dir.join("scripts/requirements.txt");
    if requirements_path.exists() {
        let pip_path = venv_dir.join("bin/pip");
        run_command(
            Command::new(&pip_path)
                .args(&["install", "--upgrade", "pip", "wheel"])
                .current_dir(connectedhomeip_dir)
        )?;
        
        run_command(
            Command::new(&pip_path)
                .args(&["install", "-r", "scripts/requirements.txt"])
                .current_dir(connectedhomeip_dir)
        )?;
    }

    Ok(())
}

fn build_chip_tool(connectedhomeip_dir: &Path) -> Result<()> {
    println!("Building chip-tool...");
    
    // Source the activation script and build
    let activate_script = connectedhomeip_dir.join("scripts/activate.sh");
    
    let build_script = format!(
        r#"
        source "{}" &&
        gn gen out/host --args='target_os="linux" target_cpu="x64" is_debug=false' &&
        ninja -C out/host chip-tool
        "#,
        activate_script.display()
    );

    run_command(
        Command::new("bash")
            .args(&["-c", &build_script])
            .current_dir(connectedhomeip_dir)
    )?;

    Ok(())
}

fn get_project_root() -> Result<PathBuf> {
    let current_dir = env::current_dir().context("Failed to get current directory")?;
    
    // Look for Cargo.toml with workspace definition
    let mut dir = current_dir.as_path();
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml)
                .context("Failed to read Cargo.toml")?;
            if content.contains("[workspace]") {
                return Ok(dir.to_path_buf());
            }
        }
        
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
    
    Err(anyhow!("Could not find project root"))
}

fn run_command(cmd: &mut Command) -> Result<()> {
    println!("Running: {:?}", cmd);
    
    let status = cmd
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("Failed to execute command: {:?}", cmd))?;

    if !status.success() {
        return Err(anyhow!("Command failed with status: {}", status));
    }

    Ok(())
}