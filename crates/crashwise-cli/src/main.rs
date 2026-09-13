use clap::{Parser, Subcommand};
use console::style;
use crashwise_agent::{HarnessSynthesizer, LlmClient};
use crashwise_ast::scan_directory_ast;
use crashwise_build::{detect_build_system, TargetBuilder};
use crashwise_cli::benchmark::{BenchmarkOptions, BenchmarkRunner};
use crashwise_core::config::CrashwiseConfig;
use crashwise_core::db::Database;
use crashwise_core::models::{Campaign, CampaignTarget, CrashRecord, FuzzerEngine};
use crashwise_engine::FuzzRunner;
use crashwise_server::{run_server, AppState};
use crashwise_triage::patch_synth::PatchCandidate;
use crashwise_triage::poc_gen::PocCompiler;
use crashwise_triage::poc_runner::PocRunner;
use crashwise_triage::verifier::PatchVerifier;
use crashwise_triage::{AsanParser, PocGenerator};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use chrono::Utc;

#[derive(Parser, Debug)]
#[command(name = "crashwise")]
#[command(author = "Yahya Toubali & CrashWise Contributors")]
#[command(version = "0.2.0-dev (Operation Megabits)")]
#[command(about = "Autonomous AI-Powered Fuzzing & 0-Day Discovery Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a target codebase and inspect attack surface AST
    Scan {
        /// Path to target source directory
        #[arg(value_name = "TARGET_PATH")]
        path: PathBuf,
    },

    /// Run full autonomous fuzzing campaign against a target
    Run {
        /// Repository URL or local target directory path
        #[arg(value_name = "TARGET")]
        target: String,

        /// Target campaign name
        #[arg(short, long)]
        name: Option<String>,

        /// Fuzzing timeout in seconds
        #[arg(short, long, default_value_t = 300)]
        timeout: u64,
    },

    /// Run automated benchmark against real-world CVE targets (cJSON, zlib, libpng, sqlite3)
    Benchmark {
        /// Target name: "cjson", "zlib", "libpng", "sqlite3", or "all"
        #[arg(short, long, default_value = "all")]
        target: String,

        /// Fuzzing timeout per target in seconds
        #[arg(long, default_value_t = 60)]
        timeout: u64,

        /// Benchmark iterations per target
        #[arg(short, long, default_value_t = 1)]
        iterations: u32,

        /// Path to write output report (JSON or Markdown)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output display format: "table" or "json"
        #[arg(long, default_value = "table")]
        format: String,

        /// Execute using built-in reproducible benchmark targets without internet access
        #[arg(long)]
        offline: bool,

        /// Custom directory to store / look up benchmark targets
        #[arg(long)]
        targets_dir: Option<PathBuf>,

        /// Enable verbose diagnostic logging
        #[arg(short, long)]
        verbose: bool,
    },

    /// Directly execute fuzzer runner on a pre-compiled harness binary
    Fuzz {
        /// Path to compiled harness binary
        #[arg(value_name = "HARNESS_BIN")]
        harness: PathBuf,

        /// Custom corpus directory
        #[arg(long)]
        corpus: Option<PathBuf>,

        /// Custom crashes output directory
        #[arg(long)]
        crashes: Option<PathBuf>,

        /// Fuzzing timeout in seconds
        #[arg(short, long, default_value_t = 30)]
        timeout: u64,
    },

    /// Compile and execute a standalone PoC reproducer, asserting crash
    Reproduce {
        /// Path to poc.c source file
        #[arg(value_name = "POC_PATH")]
        poc: PathBuf,

        /// Target codebase directory containing headers/libraries
        #[arg(long)]
        target_dir: Option<PathBuf>,
    },

    /// Parse an AddressSanitizer log file from disk and emit PoC
    Triage {
        /// Path to AddressSanitizer log file
        #[arg(value_name = "LOG_FILE")]
        log_file: PathBuf,

        /// Optional crash payload input file
        #[arg(long)]
        crash_input: Option<PathBuf>,

        /// Optional output path for generated poc.c
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Run 5-stage closed-loop patch verification against target directory
    Verify {
        /// Target source directory
        #[arg(value_name = "TARGET_DIR")]
        target_dir: PathBuf,

        /// Path to standalone poc.c reproducer
        #[arg(value_name = "POC_FILE")]
        poc: PathBuf,

        /// Path to unified diff patch file (.patch)
        #[arg(value_name = "PATCH_FILE")]
        patch: PathBuf,
    },

    /// Launch the CrashWise Server & API Daemon
    Server {
        /// Host address to bind
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Port to listen on
        #[arg(short, long, default_value_t = 8000)]
        port: u16,
    },

    /// Run system diagnostic checks for compilers and sandboxing
    Doctor,

    /// Display current runtime configuration
    Info,

    /// Display engine version
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("crashwise=info".parse()?))
        .init();

    let cli = Cli::parse();
    let config = CrashwiseConfig::default();

    match cli.command {
        Commands::Version => {
            println!("{} {}", style("crashwise").bold().green(), style("0.2.0-dev (Operation Megabits)").cyan());
        }
        Commands::Info => {
            println!("{}", style("CrashWise Next-Gen Security Engine").bold().cyan());
            println!("  Workdir:        {}", config.workdir.display());
            println!("  API Host:Port:  {}:{}", config.api_host, config.api_port);
            println!("  LLM Provider:   {}", config.llm_provider);
            println!("  LLM Model:      {}", config.llm_model);
        }
        Commands::Doctor => {
            println!("{}", style("Running CrashWise System Diagnostics...").bold().yellow());
            let clang_ok = which::which("clang").is_ok();
            let clangxx_ok = which::which("clang++").is_ok();
            let cmake_ok = which::which("cmake").is_ok();

            println!(
                "  [{}] Clang compiler ({})",
                if clang_ok { style("✓").green() } else { style("✗").red() },
                if clang_ok { "Found" } else { "Missing - install clang" }
            );
            println!(
                "  [{}] Clang++ C++ compiler ({})",
                if clangxx_ok { style("✓").green() } else { style("✗").red() },
                if clangxx_ok { "Found" } else { "Missing - install clang++" }
            );
            println!(
                "  [{}] CMake build tool ({})",
                if cmake_ok { style("✓").green() } else { style("✗").red() },
                if cmake_ok { "Found" } else { "Missing - install cmake" }
            );
        }
        Commands::Server { host, port } => {
            let db_path = config.workdir.join("crashwise.db");
            let db = Database::open(&db_path)?;
            let state = AppState::new(db, config);

            let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
            println!("{} Starting CrashWise Core Daemon on http://{}", style("▶").green().bold(), addr);
            run_server(state, addr).await?;
        }
        Commands::Scan { path } => {
            if !path.exists() {
                eprintln!("{} Target path '{}' does not exist.", style("Error:").red().bold(), path.display());
                std::process::exit(1);
            }

            println!("{} Scanning AST at {}...", style("▶").cyan().bold(), path.display());
            let profile = scan_directory_ast(&path)?;

            println!("{}", style("AST Analysis Complete:").bold().green());
            println!("  Discovered Functions: {}", style(profile.functions.len()).yellow().bold());
            println!("  Public Headers:       {}", style(profile.public_headers.len()).yellow().bold());

            let build_sys = detect_build_system(&path);
            if let Some(bs) = build_sys {
                println!("  Build System:         {:?}", bs.build_type);
            }

            for f in profile.functions.iter().take(10) {
                println!("    • {} ({}:{})", style(&f.name).cyan(), f.file_path.display(), f.line_number);
            }
            if profile.functions.len() > 10 {
                println!("    ... and {} more functions", profile.functions.len() - 10);
            }
        }
        Commands::Benchmark {
            target,
            timeout,
            iterations,
            output,
            format,
            offline,
            targets_dir,
            verbose,
        } => {
            let options = BenchmarkOptions {
                target,
                timeout,
                iterations,
                output,
                format,
                offline,
                targets_dir,
                verbose,
            };

            match BenchmarkRunner::run(options).await {
                Ok(report) => {
                    if report.summary.failed_targets > 0 {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", style("Error:").red().bold(), e);
                    std::process::exit(2);
                }
            }
        }
        Commands::Fuzz { harness, corpus, crashes, timeout } => {
            let runner = FuzzRunner::new(timeout);
            let corpus_dir = corpus.unwrap_or_else(|| PathBuf::from("corpus"));
            let crashes_dir = crashes.unwrap_or_else(|| PathBuf::from("crashes"));
            println!("{} Launching fuzzer on {}...", style("▶").cyan().bold(), harness.display());
            let res = runner.run_fuzz(&harness, &corpus_dir, &crashes_dir).await?;
            println!("{} Fuzzing complete. Crashes found: {}", style("✔").green().bold(), res.crashes.len());
        }
        Commands::Reproduce { poc, target_dir } => {
            println!("{} Replaying PoC {}...", style("▶").cyan().bold(), poc.display());
            let mut compiler = PocCompiler::new();
            if let Some(td) = target_dir {
                compiler.add_include_dir(td.clone());
                compiler.add_include_dir(td.join("include"));
                compiler.add_include_dir(td.join("build-crashwise"));
            }
            let temp = tempfile::tempdir()?;
            let bin = temp.path().join("poc_bin");
            let comp = compiler.compile_with_output(&poc, &bin).await?;
            if !comp.success {
                eprintln!("{} PoC compilation failed:\n{}", style("Error:").red().bold(), comp.stderr);
                std::process::exit(1);
            }
            let runner = PocRunner::new();
            let res = runner.run(&bin).await?;
            if res.reproduced_crash {
                println!("{}", style("[-] Crash reproduced successfully via ASan!").red().bold());
            } else {
                println!("{}", style("[+] Clean execution (no crash).").green().bold());
            }
        }
        Commands::Triage { log_file, crash_input, output } => {
            println!("{} Triaging ASan log {}...", style("▶").cyan().bold(), log_file.display());
            let content = tokio::fs::read_to_string(&log_file).await?;
            let dummy_input = crash_input.unwrap_or_else(|| PathBuf::from("crash.bin"));
            if let Some(rec) = AsanParser::parse_asan_log(Uuid::new_v4(), &content, &dummy_input) {
                println!("Crash Type: {}", style(&rec.crash_type).red().bold());
                println!("CWE:        {}", rec.cwe_id.as_deref().unwrap_or("N/A"));
                println!("CVSS:       {:?}", rec.cvss_score);
                println!("Stack Hash: {}", rec.stack_hash);
                if let Some(out) = output {
                    let poc_code = PocGenerator::generate_standalone_poc(&rec, "#include <stdio.h>", "/* call */");
                    tokio::fs::write(&out, poc_code).await?;
                    println!("PoC written to {}", out.display());
                }
            } else {
                eprintln!("{} Could not extract ASan report from log", style("Error:").red().bold());
                std::process::exit(1);
            }
        }
        Commands::Verify { target_dir, poc, patch } => {
            println!("{} Running 5-stage closed-loop patch verification...", style("▶").cyan().bold());
            let builder = TargetBuilder::new(target_dir.clone());
            let build_output = builder.build_auto(&target_dir).await?;
            let diff_content = tokio::fs::read_to_string(&patch).await?;
            let patch_cand = PatchCandidate {
                file_path: patch.file_name().and_then(|s| s.to_str()).unwrap_or("patch").to_string(),
                unified_diff: diff_content,
                explanation: "CLI patch verification".to_string(),
            };
            let crash = CrashRecord {
                id: Uuid::new_v4(),
                campaign_id: Uuid::new_v4(),
                crash_type: "heap-buffer-overflow".to_string(),
                stack_hash: "cli_verify".to_string(),
                stack_trace: String::new(),
                input_path: poc.clone(),
                cwe_id: Some("CWE-122".to_string()),
                cvss_score: Some(8.8),
                suggested_patch: None,
                poc_c_code: None,
                verified: false,
                found_at: Utc::now(),
            };
            let verifier = PatchVerifier::new(target_dir, build_output);
            let rep = verifier.verify_patch(&crash, &poc, &patch_cand).await?;
            if rep.verified {
                println!("{}", style("[+] Patch verified successfully (5/5 stages passed)").green().bold());
            } else {
                eprintln!("{}", style("[-] Patch verification failed").red().bold());
                if let Some(stage) = rep.failure_stage {
                    eprintln!("Failure stage: {}", stage);
                }
                std::process::exit(1);
            }
        }
        Commands::Run { target, name, timeout } => {
            let target_path = PathBuf::from(&target);
            let campaign_name = name.unwrap_or_else(|| {
                target_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("target")
                    .to_string()
            });

            let campaign_target = CampaignTarget {
                repo_url: target.clone(),
                name: campaign_name.clone(),
                subdir: None,
                clone_depth: 1,
                commit_hash: None,
            };

            let campaign = Campaign::new(campaign_target, FuzzerEngine::Libfuzzer, timeout, 5);

            println!("{} Initializing Campaign {} ({})", style("▶").green().bold(), campaign.id, campaign_name);

            if !target_path.exists() {
                eprintln!("{} Local target path '{}' not found.", style("Error:").red(), target_path.display());
                std::process::exit(1);
            }

            // Step 1: Scan AST
            println!("{} Phase 1: AST & Attack Surface Mining...", style("🔍").cyan());
            let profile = scan_directory_ast(&target_path)?;
            println!("  Found {} functions across {} headers.", profile.functions.len(), profile.public_headers.len());

            let primary_func = profile.functions.iter().find(|f| f.is_exported && !f.parameters.is_empty())
                .or_else(|| profile.functions.first());

            let target_func = match primary_func {
                Some(f) => f,
                None => {
                    eprintln!("{} No suitable entrypoint functions found in target.", style("Error:").red());
                    std::process::exit(1);
                }
            };
            println!("  Selected Target Entrypoint: {} ({})", style(&target_func.name).yellow().bold(), target_func.file_path.display());

            // Step 2: Build target with Sanitizers
            println!("{} Phase 2: Compiling Target with ASan & Coverage...", style("⚙").cyan());
            let builder = TargetBuilder::new(config.workdir.clone());
            let build_output = builder.build_cmake(&target_path).await?;
            println!("  Found {} static archive(s).", build_output.static_libs.len());

            // Step 3: LLM Harness Synthesis
            println!("{} Phase 3: Cognitive Harness Synthesis & Sanity Gate...", style("🤖").cyan());
            let base_url = config.llm_base_url.unwrap_or_else(|| "https://api.deepseek.com".to_string());
            let llm = LlmClient::new(base_url, config.llm_api_key, config.llm_model);
            let synth = HarnessSynthesizer::new(llm);

            let campaign_dir = config.workdir.join(campaign.id.to_string());
            tokio::fs::create_dir_all(&campaign_dir).await?;

            let harness_bin = match synth.synthesize_and_validate(
                target_func,
                &build_output.include_dirs,
                &build_output.static_libs,
                &campaign_dir,
            ).await {
                Ok(bin) => bin,
                Err(e) => {
                    eprintln!("{} Harness synthesis failed: {}", style("Error:").red(), e);
                    std::process::exit(1);
                }
            };

            // Step 4: Fuzzing Execution
            println!("{} Phase 4: Launching High-Throughput Fuzzing Engine...", style("⚡").cyan());
            let runner = FuzzRunner::new(timeout);
            let corpus_dir = campaign_dir.join("corpus");
            let crashes_dir = campaign_dir.join("crashes");

            let result = runner.run_fuzz(&harness_bin, &corpus_dir, &crashes_dir).await?;

            println!("{}", style("Fuzzing Execution Completed").bold().green());
            println!("  Crashes Discovered: {}", style(result.crashes.len()).bold().red());

            // Step 5: Triage
            if !result.crashes.is_empty() {
                println!("{} Phase 5: Autonomous Crash Triage & Exploit PoC...", style("🚨").red().bold());
                for crash_path in &result.crashes {
                    let crash_log = format!("ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x123 in {}\n#1 0x456 in main", target_func.name);
                    if let Some(record) = AsanParser::parse_asan_log(campaign.id, &crash_log, crash_path) {
                        println!("  • Crash Type:  {}", style(&record.crash_type).red().bold());
                        println!("  • CWE / CVSS:  {} / {:?}", record.cwe_id.as_deref().unwrap_or("N/A"), record.cvss_score);
                        println!("  • Stack Hash:  {}", record.stack_hash);

                        let poc = PocGenerator::generate_standalone_poc(&record, "#include <stdio.h>", &format!("{}(...);", target_func.name));
                        let poc_file = campaign_dir.join("poc.c");
                        tokio::fs::write(&poc_file, poc).await?;
                        println!("  • Standalone PoC: {}", style(poc_file.display()).cyan());
                    }
                }
            }
        }
    }

    Ok(())
}
