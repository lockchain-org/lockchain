//! Lockchain command-line interface: provisioning, maintenance, and unlock tooling.

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use lockchain_core::{
    config::{
        bootstrap_template, bootstrap_template_with, LockchainConfig, Policy, DEFAULT_CONFIG_PATH,
    },
    keyfile::write_raw_key_file,
    logging, perf,
    provider::{DatasetKeyDescriptor, KeyState, LuksKeyProvider, ProviderKind},
    workflow::{
        self, bootstrap_plan, discover_topology, BootstrapOptions, BootstrapPlan,
        BootstrapTopology, ForgeMode, ProvisionOptions, WorkflowLevel, WorkflowReport,
    },
    LockchainService, UnlockOptions,
};
use lockchain_luks::SystemLuksProvider;
use lockchain_zfs::SystemZfsProvider;
use log::warn;
use rpassword::prompt_password;
use schemars::schema_for;
use serde_json::to_string_pretty;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

mod tui;

const PLACEHOLDER_LABEL: &str = "REPLACE_WITH_USB_LABEL";

fn load_cli_config(path: &Path) -> Result<LockchainConfig> {
    let config = LockchainConfig::load_or_bootstrap(path)
        .with_context(|| format!("failed to load configuration from {}", path.display()))?;

    if config.path != path {
        println!(
            "Using bootstrap configuration at {} (override LOCKCHAIN_CONFIG to replace).",
            config.path.display()
        );
    }

    Ok(config)
}

/// Top-level command-line options shared by every subcommand.
#[derive(Parser, Debug)]
#[command(
    name = "lockchain",
    version,
    about = "Key management utilities for LockChain deployments (ZFS + LUKS provider selection)."
)]
struct Cli {
    /// Path to the Lockchain configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

/// Subcommands covering the full lifecycle of a Lockchain deployment.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Provision a USB token with raw key material and refresh initramfs assets.
    Init {
        /// Target dataset; defaults to the first entry in policy.datasets.
        dataset: Option<String>,

        /// USB block device (e.g. /dev/sdb1). When omitted, autodetect via label/UUID.
        #[arg(long)]
        device: Option<String>,

        /// Mountpoint used during provisioning.
        #[arg(long)]
        mount: Option<PathBuf>,

        /// Filename to write inside the mounted token (default: key.hex).
        #[arg(long)]
        filename: Option<String>,

        /// Optional fallback passphrase material to configure immediately.
        #[arg(long)]
        passphrase: Option<String>,

        /// Perform a non-destructive safety check instead of wiping the token.
        #[arg(long)]
        safe: bool,

        /// Force a wipe even in safe mode.
        #[arg(long)]
        force_wipe: bool,

        /// Skip initramfs rebuild after provisioning.
        #[arg(long)]
        no_rebuild: bool,
    },

    /// Run diagnostics and remediation to keep the environment healthy.
    #[command(alias = "self-heal", alias = "doctor")]
    Tuning,

    /// Adjust persisted Lockchain configuration defaults.
    Settings {
        /// Override the managed dataset list (comma separated for multiple datasets).
        #[arg(long)]
        dataset: Option<String>,

        /// Set the USB device label used to locate the token automatically.
        #[arg(long)]
        label: Option<String>,

        /// Set the USB device UUID used to locate the token automatically.
        #[arg(long)]
        uuid: Option<String>,

        /// Clear stored USB selectors (label/uuid) from the configuration.
        #[arg(long)]
        reset_usb: bool,
    },

    /// Unlock an encrypted dataset (and its descendants).
    Unlock {
        /// Target dataset; defaults to the first entry in policy.datasets.
        dataset: Option<String>,

        /// Require USB key material and skip fallback handling.
        #[arg(long)]
        strict_usb: bool,

        /// Provide a fallback passphrase directly on the command line.
        #[arg(long)]
        passphrase: Option<String>,

        /// Prompt interactively for the fallback passphrase.
        #[arg(long)]
        prompt_passphrase: bool,

        /// Provide raw key material via file (32-byte binary).
        #[arg(long)]
        key_file: Option<PathBuf>,
    },

    /// Profile unlock timings and append them to the performance log.
    ProfileUnlock {
        /// Target dataset; defaults to the first entry in policy.datasets.
        dataset: Option<String>,

        /// Require USB key material and skip fallback handling.
        #[arg(long)]
        strict_usb: bool,

        /// Provide a fallback passphrase directly on the command line.
        #[arg(long)]
        passphrase: Option<String>,

        /// Prompt interactively for the fallback passphrase.
        #[arg(long)]
        prompt_passphrase: bool,

        /// Provide raw key material via file (32-byte binary).
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Attach a short note to the log entry (e.g. baseline, cold-boot).
        #[arg(long)]
        note: Option<String>,
    },

    /// Perform a self-test using an ephemeral ZFS pool.
    SelfTest {
        /// Dataset to validate; defaults to the first entry in policy.datasets.
        dataset: Option<String>,

        /// Require the USB token and skip fallback handling during the drill.
        #[arg(long)]
        strict_usb: bool,
    },

    /// Reinstall mount/unlock systemd units and ensure services are enabled.
    Repair,

    /// Show keystatus information for a dataset (or all managed datasets).
    Status {
        /// Dataset to inspect; defaults to all configured datasets.
        dataset: Option<String>,
    },

    /// List the managed datasets and their current key status.
    ListKeys,

    /// Launch the interactive TUI unlocker.
    Tui,

    /// Validate a configuration file or emit the config schema.
    Validate {
        /// Path to the configuration file to validate.
        #[arg(short = 'f', long, default_value = DEFAULT_CONFIG_PATH)]
        file: PathBuf,

        /// Output the JSON schema instead of validating a file.
        #[arg(long)]
        schema: bool,
    },

    /// Bootstrap helpers for installers and provisioning scripts.
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommands,
    },

    /// Derive the fallback key and write it to disk (emergency only).
    Breakglass {
        /// Dataset to target; defaults to the first entry in policy.datasets.
        dataset: Option<String>,

        /// File path to write the derived key material to.
        #[arg(short, long)]
        output: PathBuf,

        /// Provide the emergency passphrase directly.
        #[arg(long)]
        passphrase: Option<String>,

        /// Skip interactive confirmations.
        #[arg(long)]
        force: bool,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum BootstrapCommands {
    /// Emit the bootstrap configuration template.
    Template {
        /// One or more datasets to pre-populate in the template.
        #[arg(long = "dataset", value_delimiter = ',', num_args = 0..)]
        datasets: Vec<String>,

        /// Pre-populate the USB device label.
        #[arg(long)]
        usb_label: Option<String>,

        /// Pre-populate the USB device UUID.
        #[arg(long)]
        usb_uuid: Option<String>,
    },

    /// Discover pools, datasets, and removable USB candidates.
    Discover {
        /// Output format for discovery results.
        #[arg(long, value_enum, default_value = "plain")]
        format: DiscoverFormat,
    },

    /// Render a first-time bootstrap plan with shell commands.
    Plan {
        /// Target dataset(s); repeat or provide a comma-delimited list.
        #[arg(long = "dataset", value_delimiter = ',', num_args = 1..)]
        datasets: Vec<String>,

        /// Path to the lockchain configuration file to generate.
        #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        /// Service user that will own lockchain processes.
        #[arg(long, default_value = "lockchain")]
        user: String,

        /// Directory containing compiled binaries and installer assets.
        #[arg(long, default_value = ".")]
        artifacts: PathBuf,

        /// Destination directory for executable binaries.
        #[arg(long = "bin-dir", default_value = "/usr/local/bin")]
        bin_dir: PathBuf,

        /// Destination directory for systemd unit files.
        #[arg(long = "systemd-dir", default_value = "/etc/systemd/system")]
        systemd_dir: PathBuf,

        /// Source directory for systemd unit templates (relative to artifacts by default).
        #[arg(long = "systemd-source", default_value = "packaging/systemd")]
        systemd_source: PathBuf,

        /// Override the USB label in the bootstrap plan.
        #[arg(long)]
        usb_label: Option<String>,

        /// Pre-populate the USB device path used by formatting steps.
        #[arg(long = "usb-device")]
        usb_device: Option<String>,

        /// Override the USB UUID in the bootstrap plan.
        #[arg(long)]
        usb_uuid: Option<String>,

        /// Runtime mountpoint for key material.
        #[arg(long = "key-mount", default_value = "/run/lockchain")]
        key_mount: PathBuf,

        /// Filename to stage on the USB key (default: key.raw).
        #[arg(long = "key-filename", default_value = "key.raw")]
        key_filename: String,

        /// Output format for the bootstrap plan.
        #[arg(long, value_enum, default_value = "json")]
        format: PlanFormat,

        /// Pretty-print JSON output.
        #[arg(long)]
        pretty: bool,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum DiscoverFormat {
    Plain,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
enum PlanFormat {
    Json,
    Plain,
}

/// Entry point: parse arguments and surface errors with an exit code.
fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// Dispatch to the requested subcommand and map results into rich output.
fn run() -> Result<()> {
    logging::init("info");
    let cli = Cli::parse();
    let config_path = cli.config.clone();

    match cli.command {
        Commands::Init {
            dataset,
            device,
            mount,
            filename,
            passphrase,
            safe,
            force_wipe,
            no_rebuild,
        } => {
            workflow::ensure_privilege_support().map_err(anyhow::Error::new)?;
            let mut config = load_cli_config(&config_path)?;
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            ensure!(
                matches!(provider_kind, ProviderKind::Zfs),
                "init is only supported for provider=zfs today"
            );
            let provider = SystemZfsProvider::from_config(&config)?;
            let target = resolve_dataset(dataset, &config.policy)?;
            let options = ProvisionOptions {
                usb_device: device,
                mountpoint: mount,
                key_filename: filename,
                passphrase,
                force_wipe,
                rebuild_initramfs: !no_rebuild,
            };
            let mode = if safe {
                ForgeMode::Safe
            } else {
                ForgeMode::Standard
            };
            let report = workflow::forge_key(&mut config, &provider, &target, mode, options)
                .map_err(anyhow::Error::new)?;
            print_report(report);
            return Ok(());
        }
        Commands::Tuning => {
            workflow::ensure_privilege_support().map_err(anyhow::Error::new)?;
            let config = load_cli_config(&config_path)?;
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            ensure!(
                matches!(provider_kind, ProviderKind::Zfs),
                "tuning is only supported for provider=zfs today"
            );
            let provider = SystemZfsProvider::from_config(&config)?;
            let mut report = workflow::tune(&config, provider).map_err(anyhow::Error::new)?;
            report.title = "Tuning sequence".into();
            print_report(report);
            return Ok(());
        }
        Commands::Settings {
            dataset,
            label,
            uuid,
            reset_usb,
        } => {
            let mut config = load_cli_config(&config_path)?;
            let mut events = Vec::new();
            let mut changed = false;

            if let Some(value) = dataset {
                let datasets: Vec<String> = value
                    .split(',')
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty())
                    .collect();
                if !datasets.is_empty() {
                    for dataset in &datasets {
                        ensure!(
                            dataset.contains('/'),
                            "dataset entries must look like pool/dataset (received `{dataset}`)"
                        );
                    }
                    config.policy.datasets = datasets.clone();
                    events.push(format!("Datasets updated: {}", datasets.join(", ")));
                    changed = true;
                }
            }

            if let Some(value) = label {
                let trimmed = value.trim().to_string();
                if !trimmed.is_empty() {
                    ensure!(
                        !trimmed.eq_ignore_ascii_case(PLACEHOLDER_LABEL),
                        "replace the placeholder USB label with the value reported by `lsblk -o LABEL`"
                    );
                    config.usb.device_label = Some(trimmed.clone());
                    config.usb.device_uuid = None;
                    events.push(format!("USB device label set to {trimmed}"));
                    changed = true;
                }
            }

            if let Some(value) = uuid {
                let trimmed = value.trim().to_string();
                if !trimmed.is_empty() {
                    ensure!(
                        trimmed
                            .chars()
                            .all(|ch| ch.is_ascii_hexdigit() || matches!(ch, '-' | '_')),
                        "USB device UUID should contain hexadecimal characters (and optional hyphens/underscores)"
                    );
                    config.usb.device_uuid = Some(trimmed.clone());
                    config.usb.device_label = None;
                    events.push(format!("USB device UUID set to {trimmed}"));
                    changed = true;
                }
            }

            if reset_usb {
                config.usb.device_label = None;
                config.usb.device_uuid = None;
                events.push("Cleared stored USB selectors.".to_string());
                changed = true;
            }

            if !changed {
                println!(
                    "No settings were changed. Use --dataset, --label, or --uuid to update values."
                );
                print_settings_snapshot(&config);
                println!("Tip: run `lockchain tuning` after adjusting settings to validate the new configuration.");
                return Ok(());
            }

            ensure!(
                config
                    .usb
                    .device_label
                    .as_ref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false)
                    || config
                        .usb
                        .device_uuid
                        .as_ref()
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false),
                "configuration must include either a USB label or UUID"
            );

            config.save()?;
            for line in events {
                println!("• {line}");
            }
            println!("Configuration saved to {}", config.path.display());
            print_settings_snapshot(&config);
            println!("Tip: run `lockchain tuning` after adjusting settings to validate the new configuration.");
            return Ok(());
        }
        Commands::Validate { file, schema } => {
            if schema {
                let schema = schema_for!(LockchainConfig);
                println!("{}", to_string_pretty(&schema)?);
                return Ok(());
            }

            let cfg = LockchainConfig::load(&file)
                .with_context(|| format!("failed to load configuration from {}", file.display()))?;

            let issues = cfg.validate();
            if issues.is_empty() {
                match cfg.provider.kind {
                    ProviderKind::Zfs => {
                        println!(
                            "Configuration valid (provider=zfs, {} datasets).",
                            cfg.policy.datasets.len()
                        );
                    }
                    ProviderKind::Luks => {
                        println!(
                            "Configuration valid (provider=luks, {} mappings).",
                            cfg.policy.mappings.len()
                        );
                    }
                    ProviderKind::Auto => {
                        println!(
                            "Configuration valid (provider=auto, {} datasets, {} mappings).",
                            cfg.policy.datasets.len(),
                            cfg.policy.mappings.len()
                        );
                    }
                }
            } else {
                eprintln!("Configuration validation failed:");
                for issue in issues {
                    eprintln!("  - {issue}");
                }
                std::process::exit(1);
            }
            return Ok(());
        }
        Commands::Bootstrap { command } => {
            match command {
                BootstrapCommands::Template {
                    datasets,
                    usb_label,
                    usb_uuid,
                } => {
                    let mut selected = datasets
                        .into_iter()
                        .map(|entry| entry.trim().to_string())
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>();
                    selected.sort();
                    selected.dedup();

                    let payload = if selected.is_empty()
                        && usb_label
                            .as_deref()
                            .map(|s| s.trim().is_empty())
                            .unwrap_or(true)
                        && usb_uuid
                            .as_deref()
                            .map(|s| s.trim().is_empty())
                            .unwrap_or(true)
                    {
                        bootstrap_template()
                    } else {
                        bootstrap_template_with(
                            &selected,
                            usb_label.as_deref(),
                            usb_uuid.as_deref(),
                        )
                    };
                    print!("{payload}");
                }
                BootstrapCommands::Discover { format } => {
                    let topology = discover_topology().map_err(anyhow::Error::new)?;
                    match format {
                        DiscoverFormat::Json => {
                            println!("{}", serde_json::to_string_pretty(&topology)?);
                        }
                        DiscoverFormat::Plain => {
                            print_topology_plain(&topology);
                        }
                    }
                }
                BootstrapCommands::Plan {
                    datasets,
                    config,
                    user,
                    artifacts,
                    bin_dir,
                    systemd_dir,
                    systemd_source,
                    usb_label,
                    usb_device,
                    usb_uuid,
                    key_mount,
                    key_filename,
                    format,
                    pretty,
                } => {
                    let options = BootstrapOptions {
                        datasets: datasets
                            .into_iter()
                            .map(|entry| entry.trim().to_string())
                            .filter(|value| !value.is_empty())
                            .collect(),
                        config_path: config,
                        service_user: user,
                        artifact_dir: artifacts,
                        binary_dir: bin_dir,
                        systemd_dir,
                        systemd_source,
                        usb_label,
                        usb_device,
                        usb_uuid,
                        key_mountpoint: key_mount,
                        key_filename,
                    };

                    let plan = bootstrap_plan(&options).map_err(anyhow::Error::new)?;
                    match format {
                        PlanFormat::Json => {
                            if pretty {
                                println!("{}", serde_json::to_string_pretty(&plan)?);
                            } else {
                                println!("{}", serde_json::to_string(&plan)?);
                            }
                        }
                        PlanFormat::Plain => {
                            print_plan_plain(&plan);
                        }
                    }
                }
            }
            return Ok(());
        }
        Commands::Breakglass {
            dataset,
            output,
            passphrase,
            force,
        } => {
            let config = Arc::new(load_cli_config(&config_path)?);
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            ensure!(
                matches!(provider_kind, ProviderKind::Zfs),
                "breakglass is only supported for provider=zfs today"
            );
            let provider = SystemZfsProvider::from_config(&config)?;
            let service = LockchainService::new(config.clone(), provider);

            let target = resolve_dataset(dataset, &config.policy)?;
            if !config.fallback.enabled {
                bail!("fallback recovery is not enabled in this configuration");
            }
            if config.fallback.passphrase_salt.is_none() || config.fallback.passphrase_xor.is_none()
            {
                bail!("fallback configuration is incomplete (salt/xor missing)");
            }

            if !force {
                println!("*** BREAK-GLASS RECOVERY ***");
                println!(
                    "This will derive the raw key for dataset `{}` and write it to {}.",
                    target,
                    output.display()
                );
                println!("Type the dataset name to continue or press Enter to abort:");
                print!("> ");
                io::stdout().flush().ok();
                let mut confirm_dataset = String::new();
                io::stdin().read_line(&mut confirm_dataset)?;
                if confirm_dataset.trim() != target {
                    println!("Break-glass aborted.");
                    return Ok(());
                }

                println!("Type BREAKGLASS to confirm this emergency action:");
                print!("> ");
                io::stdout().flush().ok();
                let mut confirm_phrase = String::new();
                io::stdin().read_line(&mut confirm_phrase)?;
                if confirm_phrase.trim() != "BREAKGLASS" {
                    println!("Break-glass aborted.");
                    return Ok(());
                }
            }

            let passphrase = match passphrase {
                Some(p) => p,
                None => prompt_password(format!("Emergency passphrase for {target}: "))?,
            };

            let key = service.derive_fallback_key(passphrase.as_bytes())?;
            write_raw_key_file(&output, &key)?;

            warn!(
                "[LC4000] break-glass recovery invoked for dataset {target}, output {}",
                output.display()
            );
            println!(
                "Emergency key material written to {} (permissions set to 0400). Remember to securely delete this file when finished.",
                output.display()
            );
            return Ok(());
        }
        Commands::SelfTest {
            dataset,
            strict_usb,
        } => {
            workflow::ensure_privilege_support().map_err(anyhow::Error::new)?;
            let config = load_cli_config(&config_path)?;
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            ensure!(
                matches!(provider_kind, ProviderKind::Zfs),
                "self-test is only supported for provider=zfs today"
            );
            let provider = SystemZfsProvider::from_config(&config)?;
            let target = resolve_dataset(dataset, &config.policy)?;
            let report = workflow::self_test(&config, provider, &target, strict_usb)
                .map_err(anyhow::Error::new)?;
            print_report(report);
            return Ok(());
        }
        Commands::Repair => {
            workflow::ensure_privilege_support().map_err(anyhow::Error::new)?;
            let config = load_cli_config(&config_path)?;
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            ensure!(
                matches!(provider_kind, ProviderKind::Zfs),
                "repair is only supported for provider=zfs today"
            );
            let provider = SystemZfsProvider::from_config(&config)?;
            let mut report = workflow::tune(&config, provider).map_err(anyhow::Error::new)?;
            report.title = "Tuning sequence".into();
            print_report(report);
            println!(
                "Tune steps executed automatically after diagnostics; no separate repair command is required."
            );
            return Ok(());
        }
        Commands::Unlock {
            dataset,
            strict_usb,
            passphrase,
            prompt_passphrase,
            key_file,
        } => {
            let config = Arc::new(load_cli_config(&config_path)?);
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            let target = resolve_target(dataset, &config, provider_kind)?;
            let options =
                build_unlock_options(strict_usb, passphrase, prompt_passphrase, key_file, &target)?;

            match provider_kind {
                ProviderKind::Zfs => {
                    let provider = SystemZfsProvider::from_config(&config)?;
                    let service = LockchainService::new(config.clone(), provider);
                    let report = service.unlock_with_retry(&target, options)?;
                    if report.already_unlocked {
                        println!(
                            "Dataset {} (root {}) already has an available key.",
                            target, report.encryption_root
                        );
                    } else {
                        println!(
                            "Unlocked encryption root {} via dataset {}.",
                            report.encryption_root, target
                        );
                        for ds in report.unlocked {
                            println!("  - {ds}");
                        }
                    }
                }
                ProviderKind::Luks => {
                    let provider = LuksKeyProvider::new(SystemLuksProvider::from_config(&config)?);
                    let service = LockchainService::new(config.clone(), provider);
                    let report = service.unlock_with_retry(&target, options)?;
                    if report.already_unlocked {
                        println!("Mapping {} is already active.", target);
                    } else {
                        println!("Unlocked mapping {}.", target);
                    }
                }
                ProviderKind::Auto => {
                    unreachable!("resolve_provider_kind must return a concrete kind")
                }
            }
        }
        Commands::ProfileUnlock {
            dataset,
            strict_usb,
            passphrase,
            prompt_passphrase,
            key_file,
            note,
        } => {
            let config = Arc::new(load_cli_config(&config_path)?);
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            let target = resolve_target(dataset, &config, provider_kind)?;
            let options =
                build_unlock_options(strict_usb, passphrase, prompt_passphrase, key_file, &target)?;

            let started = Instant::now();
            let result = match provider_kind {
                ProviderKind::Zfs => {
                    let provider = SystemZfsProvider::from_config(&config)?;
                    let service = LockchainService::new(config.clone(), provider);
                    service.unlock_with_retry(&target, options)
                }
                ProviderKind::Luks => {
                    let provider = LuksKeyProvider::new(SystemLuksProvider::from_config(&config)?);
                    let service = LockchainService::new(config.clone(), provider);
                    service.unlock_with_retry(&target, options)
                }
                ProviderKind::Auto => {
                    unreachable!("resolve_provider_kind must return a concrete kind")
                }
            };
            let elapsed = started.elapsed();
            let success = result.is_ok();

            let record = perf::record_unlock_timing(
                &target,
                elapsed,
                success,
                note.filter(|s| !s.trim().is_empty()),
            )
            .context("failed to record unlock timing")?;

            match result {
                Ok(report) => {
                    match provider_kind {
                        ProviderKind::Zfs => {
                            if report.already_unlocked {
                                println!(
                                    "Dataset {} (root {}) already has an available key.",
                                    target, report.encryption_root
                                );
                            } else {
                                println!(
                                    "Unlocked encryption root {} via dataset {}.",
                                    report.encryption_root, target
                                );
                                for ds in report.unlocked {
                                    println!("  - {ds}");
                                }
                            }
                        }
                        ProviderKind::Luks => {
                            if report.already_unlocked {
                                println!("Mapping {} is already active.", target);
                            } else {
                                println!("Unlocked mapping {}.", target);
                            }
                        }
                        ProviderKind::Auto => {
                            unreachable!("resolve_provider_kind must return a concrete kind")
                        }
                    }
                    println!(
                        "Unlock profiled in {} ms (baseline {} ms, delta {:+} ms).",
                        record.entry.duration_ms, record.entry.baseline_ms, record.entry.delta_ms
                    );
                }
                Err(err) => {
                    println!("Unlock attempt failed: {err}");
                }
            }

            if record.baseline_created {
                println!(
                    "Captured baseline for {} at {}.",
                    target,
                    record.baseline_path.display()
                );
            }
            println!("Log written to {}", record.log_path.display());

            if !success {
                bail!("profiling run did not complete successfully");
            }
        }
        Commands::Status { dataset } => {
            let config = Arc::new(load_cli_config(&config_path)?);
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            let targets: Vec<String> = match dataset {
                Some(ds) => vec![ds],
                None => config.targets_for(provider_kind).to_vec(),
            };

            match provider_kind {
                ProviderKind::Zfs => {
                    let provider = SystemZfsProvider::from_config(&config)?;
                    let service = LockchainService::new(config.clone(), provider);
                    for target in targets {
                        let status = service.status(&target)?;
                        if status.root_locked {
                            println!(
                                "{} (root {}) is LOCKED.",
                                status.dataset, status.encryption_root
                            );
                            if status.locked_descendants.is_empty() {
                                println!("  No locked descendants reported.");
                            } else {
                                println!("  Locked descendants:");
                                for child in status.locked_descendants {
                                    println!("    - {child}");
                                }
                            }
                        } else {
                            println!(
                                "{} (root {}) is unlocked.",
                                status.dataset, status.encryption_root
                            );
                        }
                    }
                }
                ProviderKind::Luks => {
                    let provider = LuksKeyProvider::new(SystemLuksProvider::from_config(&config)?);
                    let service = LockchainService::new(config.clone(), provider);
                    for target in targets {
                        let status = service.status(&target)?;
                        if status.root_locked {
                            println!("Mapping {} is INACTIVE.", status.dataset);
                        } else {
                            println!("Mapping {} is active.", status.dataset);
                        }
                    }
                }
                ProviderKind::Auto => {
                    unreachable!("resolve_provider_kind must return a concrete kind")
                }
            }
        }
        Commands::ListKeys => {
            let config = Arc::new(load_cli_config(&config_path)?);
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            let snapshot = match provider_kind {
                ProviderKind::Zfs => {
                    let provider = SystemZfsProvider::from_config(&config)?;
                    let service = LockchainService::new(config.clone(), provider);
                    service.list_keys()?
                }
                ProviderKind::Luks => {
                    let provider = LuksKeyProvider::new(SystemLuksProvider::from_config(&config)?);
                    let service = LockchainService::new(config.clone(), provider);
                    service.list_keys()?
                }
                ProviderKind::Auto => {
                    unreachable!("resolve_provider_kind must return a concrete kind")
                }
            };
            print_key_table(provider_kind, snapshot);
        }
        Commands::Tui => {
            let config = Arc::new(load_cli_config(&config_path)?);
            let provider_kind = config.resolve_provider_kind().map_err(anyhow::Error::new)?;
            ensure!(
                matches!(provider_kind, ProviderKind::Zfs),
                "tui is only supported for provider=zfs today"
            );
            let provider = SystemZfsProvider::from_config(&config)?;
            let service = LockchainService::new(config.clone(), provider);
            tui::launch(config, service)?;
        }
    }

    Ok(())
}

fn print_topology_plain(topology: &BootstrapTopology) {
    for pool in &topology.pools {
        println!(
            "POOL\t{}\t{}\t{}\t{}\t{}",
            pool.name,
            pool.size.as_deref().unwrap_or("-"),
            pool.alloc.as_deref().unwrap_or("-"),
            pool.free.as_deref().unwrap_or("-"),
            pool.health.as_deref().unwrap_or("-"),
        );
    }

    for dataset in &topology.datasets {
        println!(
            "DATASET\t{}\t{}\t{}\t{}\t{}",
            dataset.name,
            dataset.encryption_root.as_deref().unwrap_or("-"),
            dataset.keystatus.as_deref().unwrap_or("-"),
            dataset.mountpoint.as_deref().unwrap_or("-"),
            if dataset.encrypted {
                "encrypted"
            } else {
                "unencrypted"
            }
        );
    }

    for usb in &topology.usb {
        println!(
            "USB\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            usb.device,
            usb.disk,
            usb.label.as_deref().unwrap_or("-"),
            usb.size.as_deref().unwrap_or("-"),
            usb.model.as_deref().unwrap_or("-"),
            usb.serial.as_deref().unwrap_or("-"),
            usb.transport.as_deref().unwrap_or("-"),
            usb.mountpoint.as_deref().unwrap_or("-"),
        );
    }
}

fn print_plan_plain(plan: &BootstrapPlan) {
    println!(
        "datasets:\t{}",
        if plan.datasets.is_empty() {
            "-".into()
        } else {
            plan.datasets.join(", ")
        }
    );
    println!("config_path:\t{}", plan.config_path.display());
    println!("service_user:\t{}", plan.service_user);
    println!("usb_label:\t{}", plan.usb_label.as_deref().unwrap_or("-"));
    println!("usb_uuid:\t{}", plan.usb_uuid.as_deref().unwrap_or("-"));
    println!("key_mountpoint:\t{}", plan.key_mountpoint.display());
    println!("key_filename:\t{}", plan.key_filename);

    for step in &plan.steps {
        println!("\n[{}] {}", step.id, step.title);
        println!("{}", step.description);
        for command in &step.commands {
            println!(
                "- [{}] {} :: {}",
                if command.requires_root {
                    "root"
                } else {
                    "user"
                },
                command.label,
                command.command
            );
        }
    }
}

/// Emit a short snapshot of the managed configuration defaults.
fn print_settings_snapshot(config: &LockchainConfig) {
    println!("Current Settings");
    println!("  Datasets:");
    if config.policy.datasets.is_empty() {
        println!("    (none configured)");
    } else {
        for dataset in &config.policy.datasets {
            println!("    - {dataset}");
        }
    }
    let selector = config
        .usb
        .device_label
        .as_ref()
        .map(|s| format!("Label: {s}"))
        .or_else(|| {
            config
                .usb
                .device_uuid
                .as_ref()
                .map(|s| format!("UUID: {s}"))
        })
        .unwrap_or_else(|| "    - USB selector not set".to_string());
    println!("  USB selector:");
    if selector.starts_with("Label") || selector.starts_with("UUID") {
        println!("    - {selector}");
    } else {
        println!("{selector}");
    }
    println!("  Key path: {}", config.usb.key_hex_path);
    println!("  Token path: {}", config.usb.device_key_path);
}

/// Pretty-print a workflow report so humans can follow along.
fn print_report(report: WorkflowReport) {
    println!("{}", report.title);
    for event in report.events {
        println!("  [{}] {}", level_tag(event.level), event.message);
    }
}

/// Short tag used when printing workflow severity levels.
fn level_tag(level: WorkflowLevel) -> &'static str {
    match level {
        WorkflowLevel::Info => "INFO",
        WorkflowLevel::Success => "OK",
        WorkflowLevel::Warn => "WARN",
        WorkflowLevel::Error => "ERR",
        WorkflowLevel::Security => "SEC",
    }
}

fn build_unlock_options(
    strict_usb: bool,
    passphrase: Option<String>,
    prompt_passphrase: bool,
    key_file: Option<PathBuf>,
    target: &str,
) -> Result<UnlockOptions> {
    let mut options = UnlockOptions {
        strict_usb,
        ..UnlockOptions::default()
    };

    if let Some(path) = key_file {
        let key_bytes =
            fs::read(&path).with_context(|| format!("read key file {}", path.display()))?;
        ensure!(
            key_bytes.len() == 32,
            "expected a 32-byte raw key in {}, found {} bytes",
            path.display(),
            key_bytes.len()
        );
        options.key_override = Some(key_bytes);
    }

    if let Some(pass) = passphrase {
        options.fallback_passphrase = Some(pass);
    } else if prompt_passphrase {
        let prompt = format!("Fallback passphrase for {}", target);
        let value = prompt_password(prompt)?;
        options.fallback_passphrase = Some(value);
    }

    Ok(options)
}

/// Pick a dataset from CLI input or fall back to the first policy entry.
fn resolve_dataset(dataset: Option<String>, policy: &Policy) -> Result<String> {
    if let Some(ds) = dataset {
        return Ok(ds);
    }
    policy
        .datasets
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no datasets configured in policy.datasets"))
}

/// Pick a provider-aware target from CLI input or fall back to the first policy entry.
fn resolve_target(
    target: Option<String>,
    config: &LockchainConfig,
    provider: ProviderKind,
) -> Result<String> {
    if let Some(value) = target {
        return Ok(value);
    }

    match provider {
        ProviderKind::Zfs => config
            .policy
            .datasets
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no datasets configured in policy.datasets")),
        ProviderKind::Luks => config
            .policy
            .mappings
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no mappings configured in policy.mappings")),
        ProviderKind::Auto => Err(anyhow::anyhow!(
            "provider.kind=auto cannot be used without resolving to a concrete provider"
        )),
    }
}

/// Render a simple table describing current key status across datasets.
fn print_key_table(provider: ProviderKind, snapshot: Vec<DatasetKeyDescriptor>) {
    let label = match provider {
        ProviderKind::Zfs => "DATASET",
        ProviderKind::Luks => "MAPPING",
        ProviderKind::Auto => "TARGET",
    };
    println!("{:<32} {:<32} STATUS", label, "ENCRYPTION ROOT");
    for entry in snapshot {
        let status = match entry.state {
            KeyState::Available => "available".to_string(),
            KeyState::Unavailable => "locked".to_string(),
            KeyState::Unknown(value) => value,
        };
        println!(
            "{:<32} {:<32} {}",
            entry.dataset, entry.encryption_root, status
        );
    }
}
