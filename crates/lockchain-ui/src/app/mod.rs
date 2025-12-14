//! Application wiring for the LockChain Control Deck.

mod icon;
mod style;
mod view;

use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Local};
use iced::font::{Family, Weight};
use iced::window;
use iced::{application, Error as IcedError, Font, Size, Task, Theme};
use lockchain_core::config::{looks_like_dataset_name, LockchainConfig, DEFAULT_CONFIG_PATH};
use lockchain_core::perf;
use lockchain_core::workflow::{
    self, ensure_privilege_support, ForgeMode, ProvisionOptions, RecoveryInput, WorkflowEvent,
    WorkflowLevel, WorkflowReport,
};
use lockchain_zfs::SystemZfsProvider;
use log::{info, warn};
use regex::Regex;
use tokio::time as tokio_time;

static BOOTSTRAP_NOTICE: OnceLock<()> = OnceLock::new();
const PLACEHOLDER_LABEL: &str = "REPLACE_WITH_USB_LABEL";
const TERMINAL_HISTORY_LIMIT: usize = 200;
const TERMINAL_FLUSH_INTERVAL_MS: u64 = 450;
const FORGE_ANIMATION_INTERVAL_MS: u64 = 90;
const FORGE_VISIBILITY_WINDOW_SECS: u64 = 8;
const FORGE_REVEAL_STEP: f32 = 0.24;
const FORGE_HIDE_STEP: f32 = 0.16;
const FONT_FAMILY_UI: &str = "Orbitron";
const FONT_FAMILY_MONO: &str = "Hack";
const MISSION_PERSIST_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProgressState {
    Idle,
    Running,
    Success,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissionPhase {
    Hidden,
    Active { started_at: Instant },
    Completed { finished_at: Instant },
    Failed { finished_at: Instant },
}

/// Default UI font (Orbitron) bundled with the interface.
pub(super) const FONT_UI_REGULAR: Font = Font {
    family: Family::Name(FONT_FAMILY_UI),
    weight: Weight::Medium,
    ..Font::DEFAULT
};

/// Bold weight variant for UI headings and button labels.
pub(super) const FONT_UI_BOLD: Font = Font {
    family: Family::Name(FONT_FAMILY_UI),
    weight: Weight::Bold,
    ..Font::DEFAULT
};

/// Monospaced font for console, logs, and terminal input.
pub(super) const FONT_MONO_REGULAR: Font = Font {
    family: Family::Name(FONT_FAMILY_MONO),
    ..Font::MONOSPACE
};

/// Bold monospaced variant used for emphasized terminal output.
pub(super) const FONT_MONO_BOLD: Font = Font {
    family: Family::Name(FONT_FAMILY_MONO),
    weight: Weight::Bold,
    ..Font::MONOSPACE
};

/// Launch the Iced application with the Lockchain-specific theme and state.
pub fn run() -> iced::Result {
    configure_runtime_environment();
    lockchain_core::logging::init("info");
    run_with_render_profiles()
}

fn run_with_render_profiles() -> iced::Result {
    for (index, profile) in RENDER_PROFILES.iter().enumerate() {
        if index > 0 {
            warn!("Falling back to render profile `{}`.", profile.name);
        } else {
            info!(
                "Launching Control Deck with render profile `{}`.",
                profile.name
            );
        }
        apply_render_profile(profile);
        match run_control_deck() {
            Ok(()) => return Ok(()),
            Err(err) if is_surface_timeout(&err) && index + 1 < RENDER_PROFILES.len() => {
                warn!(
                    "Render profile `{}` hit a surface timeout; trying next fallback.",
                    profile.name
                );
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("render profile loop must return before exhausting profiles");
}

fn run_control_deck() -> iced::Result {
    application(
        "LockChain Control Deck",
        LockchainUi::update,
        LockchainUi::view,
    )
    // Bundle Orbitron (UI) and Hack (console) for offline aesthetics.
    .default_font(FONT_UI_REGULAR)
    .font(include_bytes!("../../assets/fonts/Orbitron-Regular.ttf"))
    .font(include_bytes!("../../assets/fonts/Orbitron-Bold.ttf"))
    .font(include_bytes!("../../assets/fonts/Hack-Regular.ttf"))
    .font(include_bytes!("../../assets/fonts/Hack-Bold.ttf"))
    .antialiasing(true)
    .window(window::Settings {
        size: Size::new(1280.0, 768.0),
        ..window::Settings::default()
    })
    .theme(LockchainUi::theme)
    .run_with(LockchainUi::init)
}

fn configure_runtime_environment() {
    use std::env;

    if env::var_os("ICED_PRESENT_MODE").is_none() {
        env::set_var("ICED_PRESENT_MODE", "fifo");
    }
    if env::var_os("WGPU_POWER_PREF").is_none() {
        env::set_var("WGPU_POWER_PREF", "low_power");
    }
    if env::var_os("RUST_LOG").is_none() {
        env::set_var(
            "RUST_LOG",
            "info,sctk_adwaita::buttons=error,wgpu_hal::vulkan::conv=error",
        );
    }
}

fn apply_render_profile(profile: &RenderProfile) {
    for (key, value) in profile.env {
        std::env::set_var(key, value);
    }
}

fn is_surface_timeout(err: &IcedError) -> bool {
    err.to_string().contains("Timeout when presenting surface")
}

struct RenderProfile {
    name: &'static str,
    env: &'static [(&'static str, &'static str)],
}

const RENDER_PROFILES: &[RenderProfile] = &[
    RenderProfile {
        name: "default",
        env: &[],
    },
    RenderProfile {
        name: "fallback-adapter",
        env: &[
            ("WGPU_FORCE_FALLBACK_ADAPTER", "1"),
            ("ICED_PRESENT_MODE", "fifo"),
            ("WGPU_POWER_PREF", "low_power"),
        ],
    },
    RenderProfile {
        name: "gl-backend",
        env: &[
            ("WGPU_FORCE_FALLBACK_ADAPTER", "1"),
            ("ICED_PRESENT_MODE", "fifo"),
            ("WGPU_BACKEND", "gl"),
            ("WGPU_POWER_PREF", "low_power"),
        ],
    },
];

/// Actions the operator can trigger from the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directive {
    NewKey,
    NewKeySafe,
    SelfTest,
    RecoverKey,
    Tune,
    Settings,
}

/// Glyphs rendered on directive tiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectiveGlyph {
    Key,
    Shield,
    Test,
    Recover,
    Tune,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgressContext {
    Directive(Directive),
    Uninstall,
}

#[derive(Debug, Clone)]
struct SafeForgeSession {
    dataset: Option<String>,
    device: Option<String>,
    mount: Option<PathBuf>,
    filename: Option<String>,
    passphrase: Option<String>,
    rebuild: Option<bool>,
    confirm_wipe: bool,
    confirm_format: bool,
    confirm_commit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafePromptKind {
    Dataset,
    Device,
    ConfirmWipe,
    ConfirmFormat,
    ConfirmCommit,
    Completed,
}

impl SafeForgeSession {
    fn new() -> Self {
        Self {
            dataset: None,
            device: None,
            mount: None,
            filename: None,
            passphrase: None,
            rebuild: None,
            confirm_wipe: false,
            confirm_format: false,
            confirm_commit: false,
        }
    }

    fn ready(&self) -> bool {
        self.dataset.is_some()
            && self.device.is_some()
            && self.confirm_wipe
            && self.confirm_format
            && self.confirm_commit
    }

    fn next_prompt_kind(&self) -> SafePromptKind {
        if self.dataset.is_none() {
            SafePromptKind::Dataset
        } else if self.device.is_none() {
            SafePromptKind::Device
        } else if !self.confirm_wipe {
            SafePromptKind::ConfirmWipe
        } else if !self.confirm_format {
            SafePromptKind::ConfirmFormat
        } else if !self.confirm_commit {
            SafePromptKind::ConfirmCommit
        } else {
            SafePromptKind::Completed
        }
    }

    fn next_prompt(&self) -> String {
        match self.next_prompt_kind() {
            SafePromptKind::Dataset => {
                "Enter the dataset to forge (e.g. rpool). Type cancel to restart.".into()
            }
            SafePromptKind::Device => {
                "Enter the USB device (e.g. /dev/sdX1), auto to detect, or #<index> from the device list. Type cancel to restart."
                    .into()
            }
            SafePromptKind::ConfirmWipe => {
                "Type wipe to confirm the media wipe once backups are secured.".into()
            }
            SafePromptKind::ConfirmFormat => {
                "Type format to confirm filesystem creation.".into()
            }
            SafePromptKind::ConfirmCommit => {
                "Type commit to authorise key generation and configuration updates.".into()
            }
            SafePromptKind::Completed => {
                "All confirmations captured; press Execute again to forge the key.".into()
            }
        }
    }

    fn as_command_args(&self) -> String {
        let mut parts = Vec::new();
        if let Some(dataset) = &self.dataset {
            parts.push(format!("dataset={dataset}"));
        }
        if let Some(device) = &self.device {
            parts.push(format!("device={device}"));
        }
        if let Some(mount) = &self.mount {
            parts.push(format!("mount={}", mount.display()));
        }
        if let Some(filename) = &self.filename {
            parts.push(format!("filename={filename}"));
        }
        if let Some(passphrase) = &self.passphrase {
            parts.push(format!("passphrase={passphrase}"));
        }
        if let Some(rebuild) = self.rebuild {
            parts.push(format!(
                "rebuild={}",
                if rebuild { "true" } else { "false" }
            ));
        }
        parts.push("force=true".into());
        parts.join(" ")
    }
}

#[derive(Debug, Clone)]
struct RecoveryOverlay {
    secret_hex: String,
}

/// Metadata used to render directive tiles.
#[derive(Debug, Clone, Copy)]
struct DirectiveMeta {
    directive: Directive,
    tooltip: &'static str,
    glyph: DirectiveGlyph,
}

const DIRECTIVES: &[DirectiveMeta] = &[
    DirectiveMeta {
        directive: Directive::NewKey,
        tooltip: "Forge fresh USB key material and write it to the LockChain USB token.",
        glyph: DirectiveGlyph::Key,
    },
    DirectiveMeta {
        directive: Directive::NewKeySafe,
        tooltip: "Forging workflow with confirmation prompts and guard rails for safer operation.",
        glyph: DirectiveGlyph::Shield,
    },
    DirectiveMeta {
        directive: Directive::SelfTest,
        tooltip: "Run an end-to-end unlock drill against a temporary dataset and verify state.",
        glyph: DirectiveGlyph::Test,
    },
    DirectiveMeta {
        directive: Directive::RecoverKey,
        tooltip: "Derive fallback key material from the configured passphrase and export it.",
        glyph: DirectiveGlyph::Recover,
    },
    DirectiveMeta {
        directive: Directive::Tune,
        tooltip: "Full diagnostics, remediation, and system tuning in one pass.",
        glyph: DirectiveGlyph::Tune,
    },
];

/// Visual severity mapping for workflow events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivityLevel {
    Info,
    Success,
    Warn,
    Error,
    Security,
}

impl From<WorkflowLevel> for ActivityLevel {
    fn from(level: WorkflowLevel) -> Self {
        match level {
            WorkflowLevel::Info => ActivityLevel::Info,
            WorkflowLevel::Success => ActivityLevel::Success,
            WorkflowLevel::Warn => ActivityLevel::Warn,
            WorkflowLevel::Error => ActivityLevel::Error,
            WorkflowLevel::Security => ActivityLevel::Security,
        }
    }
}

/// Severity bucket for terminal transcript entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TerminalLevel {
    Input,
    Prompt,
    Info,
    Success,
    Warning,
    Error,
    Security,
}

impl From<WorkflowLevel> for TerminalLevel {
    fn from(level: WorkflowLevel) -> Self {
        match level {
            WorkflowLevel::Info => TerminalLevel::Info,
            WorkflowLevel::Success => TerminalLevel::Success,
            WorkflowLevel::Warn => TerminalLevel::Warning,
            WorkflowLevel::Error => TerminalLevel::Error,
            WorkflowLevel::Security => TerminalLevel::Security,
        }
    }
}

/// Line rendered inside the emulated terminal console.
#[derive(Debug, Clone)]
pub(super) struct TerminalLine {
    pub(super) level: TerminalLevel,
    pub(super) message: String,
    pub(super) timestamp: DateTime<Local>,
}

/// Application state backing the UI, including current directive and logs.
#[derive(Debug)]
struct LockchainUi {
    config_path: PathBuf,
    config: LockchainConfig,
    active_directive: Directive,
    last_announced_directive: Option<Directive>,
    terminal_input: String,
    terminal_lines: VecDeque<TerminalLine>,
    terminal_queue: VecDeque<TerminalLine>,
    terminal_flush_active: bool,
    exporting_logs: bool,
    forge_phase: f32,
    forge_tick_active: bool,
    executing: bool,
    pending_directive: Option<Directive>,
    status_line: String,
    total_events: usize,
    key_present: bool,
    settings_open: bool,
    settings_dataset: String,
    settings_label: String,
    settings_uuid: String,
    settings_error: Option<String>,
    settings_return: Option<Directive>,
    settings_passphrase: String,
    uninstall_open: bool,
    last_activity: Instant,
    forge_reveal: f32,
    progress_state: ProgressState,
    progress_context: Option<ProgressContext>,
    progress_ratio: f32,
    progress_count: usize,
    progress_expected: usize,
    forge_errors: u32,
    forge_warnings: u32,
    terminal_phase: f32,
    forge_breathe: f32,
    terminal_static_level: f32,
    terminal_static_target: f32,
    terminal_glare_offset: f32,
    terminal_glare_target: f32,
    terminal_glare_span: f32,
    terminal_glare_span_target: f32,
    terminal_rng_state: u32,
    mission_phase: MissionPhase,
    safe_session: Option<SafeForgeSession>,
    recovery_overlay: Option<RecoveryOverlay>,
}

/// Messages produced by Iced interactions and background tasks.
#[derive(Debug, Clone)]
enum Message {
    DirectiveSelected(Directive),
    TerminalChanged(String),
    Execute,
    WorkflowFinished(Result<WorkflowReport, String>),
    TerminalFlush,
    ForgeAnimationTick,
    HelpPressed,
    ClearTerminal,
    DownloadLogs,
    DownloadLogsFinished(Result<PathBuf, String>),
    UninstallPressed,
    UninstallCancel,
    UninstallConfirm,
    UninstallFinished(Result<WorkflowReport, String>),
    OpenSettings,
    SettingsDatasetChanged(String),
    SettingsLabelChanged(String),
    SettingsUuidChanged(String),
    SettingsPassphraseChanged(String),
    SettingsSave,
    SettingsDiscard,
    RecoveryAcknowledge,
}

impl LockchainUi {
    fn has_key_material(config: &LockchainConfig) -> bool {
        let checksum_present = config
            .usb
            .expected_sha256
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        checksum_present || config.key_hex_path().exists()
    }

    fn init() -> (Self, Task<Message>) {
        let requested_path = std::env::var("LOCKCHAIN_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH));

        let mut bootstrap_messages = Vec::new();
        let config = match load_ui_config(&requested_path) {
            Ok(cfg) => {
                if cfg.path != requested_path {
                    bootstrap_messages.push((
                        ActivityLevel::Info,
                        format!(
                            "Bootstrap configuration ready at {} (requested {}).",
                            cfg.path.display(),
                            requested_path.display()
                        ),
                    ));
                }
                cfg
            }
            Err(err) => {
                bootstrap_messages.push((
                    ActivityLevel::Error,
                    format!("Failed to load configuration: {err}"),
                ));
                LockchainConfig::load_or_bootstrap(&requested_path)
                    .expect("unable to bootstrap configuration")
            }
        };

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.subsec_nanos())
            .unwrap_or(0)
            ^ std::process::id();

        let mut ui = Self {
            config_path: config.path.clone(),
            config: config.clone(),
            active_directive: Directive::NewKey,
            last_announced_directive: None,
            terminal_input: String::new(),
            terminal_lines: VecDeque::new(),
            terminal_queue: VecDeque::new(),
            terminal_flush_active: false,
            exporting_logs: false,
            forge_phase: 0.0,
            forge_tick_active: false,
            executing: false,
            pending_directive: None,
            status_line: "Ready".into(),
            total_events: 0,
            key_present: Self::has_key_material(&config),
            settings_open: false,
            settings_dataset: String::new(),
            settings_label: String::new(),
            settings_uuid: String::new(),
            settings_error: None,
            settings_return: None,
            settings_passphrase: String::new(),
            uninstall_open: false,
            last_activity: Instant::now(),
            forge_reveal: 0.0,
            progress_state: ProgressState::Idle,
            progress_context: None,
            progress_ratio: 0.0,
            progress_count: 0,
            progress_expected: 1,
            forge_errors: 0,
            forge_warnings: 0,
            terminal_phase: 0.0,
            forge_breathe: 0.0,
            terminal_static_level: 0.0,
            terminal_static_target: 0.0,
            terminal_glare_offset: 0.38,
            terminal_glare_target: 0.38,
            terminal_glare_span: 0.18,
            terminal_glare_span_target: 0.18,
            terminal_rng_state: seed,
            mission_phase: MissionPhase::Hidden,
            safe_session: None,
            recovery_overlay: None,
        };

        if let Err(err) = ensure_privilege_support() {
            let message = err.to_string();
            ui.push_activity(ActivityLevel::Warn, message.clone());
            ui.push_terminal_line(TerminalLevel::Warning, message.clone());
            ui.status_line = "Review privilege escalation configuration".into();
        }

        ui.push_activity(
            ActivityLevel::Info,
            "Control Deck online. Select a directive to begin.",
        );
        for (level, message) in bootstrap_messages {
            ui.push_activity(level, message);
        }
        ui.populate_settings_fields();
        ui.push_terminal_line(
            TerminalLevel::Info,
            "Control Deck online. Select a directive or press Help for usage tips.",
        );
        ui.announce_directive(ui.active_directive);
        ui.last_activity = Instant::now()
            .checked_sub(Duration::from_secs(FORGE_VISIBILITY_WINDOW_SECS * 2))
            .unwrap_or_else(Instant::now);

        let tasks = vec![ui.trigger_terminal_flush(), ui.trigger_forge_tick()];
        (ui, Task::batch(tasks))
    }

    fn push_terminal_line(&mut self, level: TerminalLevel, message: impl Into<String>) {
        let mut text = message.into();
        if text.trim().is_empty() {
            return;
        }

        if matches!(level, TerminalLevel::Input) {
            let trimmed = text.trim_start();
            if !trimmed.starts_with('>') {
                text = format!("> {trimmed}");
            }
        }

        let timestamp = Local::now();
        self.last_activity = Instant::now();

        self.terminal_queue.push_back(TerminalLine {
            level,
            message: text,
            timestamp,
        });
    }

    fn announce_directive(&mut self, directive: Directive) {
        if self.last_announced_directive == Some(directive) {
            return;
        }
        self.last_announced_directive = Some(directive);
        self.forge_errors = 0;
        self.forge_warnings = 0;
        self.push_terminal_line(
            TerminalLevel::Prompt,
            format!("Directive → {}", directive_title(directive)),
        );
        for (level, line) in self.directive_prompt_lines(directive) {
            self.push_terminal_line(level, line);
        }
    }

    fn compose_command_preview(&self) -> String {
        let directive = directive_title(self.active_directive);
        let trimmed = self.terminal_input.trim();
        if trimmed.is_empty() {
            format!("{directive} [defaults]")
        } else {
            format!("{directive} {}", trimmed)
        }
    }

    fn reset_progress(&mut self) {
        self.progress_context = None;
        self.progress_ratio = 0.0;
        self.progress_count = 0;
        self.progress_expected = 1;
    }

    /// Collect terminal history (including queued lines) into a chronological text log.
    fn exportable_terminal_log(&self) -> String {
        let mut lines: Vec<TerminalLine> = self
            .terminal_lines
            .iter()
            .cloned()
            .chain(self.terminal_queue.iter().cloned())
            .collect();
        lines.sort_by_key(|line| line.timestamp);

        let mut output = String::with_capacity(lines.len() * 64);
        output.push_str("# LockChain UI console log\n");
        for line in lines {
            let level = match line.level {
                TerminalLevel::Input => "INPUT",
                TerminalLevel::Prompt => "PROMPT",
                TerminalLevel::Info => "INFO",
                TerminalLevel::Success => "SUCCESS",
                TerminalLevel::Warning => "WARN",
                TerminalLevel::Error => "ERROR",
                TerminalLevel::Security => "SECURITY",
            };
            let ts = line.timestamp.format("%Y-%m-%d %H:%M:%S");
            output.push_str(&format!("[{ts}] [{level}] {}\n", line.message));
        }
        output
    }

    fn begin_progress(&mut self, context: ProgressContext) {
        self.progress_context = Some(context);
        self.progress_ratio = 0.0;
        self.progress_count = 0;
        self.progress_expected = expected_events_for(context).max(1);
    }

    fn bump_progress(&mut self) {
        if !matches!(self.progress_state, ProgressState::Running) {
            return;
        }
        if self.progress_context.is_none() {
            return;
        }
        if self.progress_expected == 0 {
            self.progress_expected = 1;
        }
        self.progress_count = self.progress_count.saturating_add(1);
        let fraction = (self.progress_count as f32 / self.progress_expected as f32).min(0.95);
        if fraction > self.progress_ratio {
            self.progress_ratio = fraction;
        }
    }

    fn start_safe_mode_session(&mut self) {
        self.safe_session = Some(SafeForgeSession::new());
        self.terminal_input.clear();
    }

    fn prepare_safe_mode_execution(&mut self) -> Result<Option<String>, String> {
        let (kv, free) = parse_kv(&self.terminal_input);
        let trimmed_owned = self.terminal_input.trim().to_string();
        let mut prompt_value = if trimmed_owned.is_empty() {
            None
        } else {
            Some(trimmed_owned)
        };

        if free
            .iter()
            .any(|token| token.eq_ignore_ascii_case("cancel"))
            || kv
                .get("cancel")
                .map(|value| {
                    value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
                })
                .unwrap_or(false)
        {
            self.safe_session = None;
            self.push_terminal_line(TerminalLevel::Info, "Safe mode session reset.");
            self.start_safe_mode_session();
            return Ok(None);
        }

        if self.safe_session.is_none() {
            self.start_safe_mode_session();
            return Ok(None);
        }

        let allowed_keys = [
            "dataset",
            "device",
            "mount",
            "filename",
            "passphrase",
            "rebuild",
            "confirm",
        ];
        for key in kv.keys() {
            if !allowed_keys.contains(&key.as_str()) {
                return Err(format!(
                    "Unknown parameter `{key}`. Expected dataset, device, mount, filename, passphrase, rebuild, or confirm."
                ));
            }
        }

        let mut updated = false;

        if let Some(value) = kv.get("dataset") {
            let dataset = value.trim();
            if !looks_like_dataset_name(dataset) {
                return Err(
                    "dataset must resemble pool/dataset (letters, digits, '-', '_', ':', '.')."
                        .into(),
                );
            }
            if let Some(session) = self.safe_session.as_mut() {
                session.dataset = Some(dataset.to_string());
            }
            self.push_terminal_line(TerminalLevel::Info, format!("Dataset staged: {dataset}"));
            updated = true;
            prompt_value = None;
        }

        if let Some(value) = kv.get("device") {
            let device = value.trim();
            static DEVICE_PATH_RE: OnceLock<Regex> = OnceLock::new();
            let regex = DEVICE_PATH_RE.get_or_init(|| {
                Regex::new(r"^/dev/[-A-Za-z0-9_./]+$").expect("valid device regex")
            });
            if !regex.is_match(device)
                && !device.eq_ignore_ascii_case("auto")
                && !device.starts_with('#')
                && !device.eq_ignore_ascii_case("list")
            {
                return Err("device must be an absolute /dev/ path (e.g. /dev/sdX1), auto, list, or #<index>.".into());
            }
            if let Some(session) = self.safe_session.as_mut() {
                session.device = Some(device.to_string());
            }
            self.push_terminal_line(TerminalLevel::Info, format!("USB device locked: {device}"));
            updated = true;
            prompt_value = None;
        }

        if let Some(value) = kv.get("mount") {
            let mount = PathBuf::from(value.trim());
            if !mount.is_absolute() {
                return Err("mount must be an absolute path (e.g. /run/lockchain).".into());
            }
            if let Some(session) = self.safe_session.as_mut() {
                session.mount = Some(mount.clone());
            }
            self.push_terminal_line(
                TerminalLevel::Info,
                format!("Mountpoint staged: {}", mount.display()),
            );
            updated = true;
            prompt_value = None;
        }

        if let Some(value) = kv.get("filename") {
            let name = value.trim();
            if name.is_empty() || name.contains('/') {
                return Err("filename should be a plain name without directory separators.".into());
            }
            if let Some(session) = self.safe_session.as_mut() {
                session.filename = Some(name.to_string());
            }
            self.push_terminal_line(TerminalLevel::Info, format!("Key filename set to {name}"));
            updated = true;
            prompt_value = None;
        }

        if let Some(value) = kv.get("passphrase") {
            let passphrase = value.trim();
            if passphrase.is_empty() {
                return Err("passphrase cannot be empty.".into());
            }
            if let Some(session) = self.safe_session.as_mut() {
                session.passphrase = Some(passphrase.to_string());
            }
            self.push_terminal_line(
                TerminalLevel::Info,
                "Fallback passphrase will be configured for recovery.",
            );
            updated = true;
            prompt_value = None;
        }

        if let Some(value) = kv.get("rebuild") {
            let rebuild = parse_bool(value);
            if let Some(session) = self.safe_session.as_mut() {
                session.rebuild = Some(rebuild);
            }
            self.push_terminal_line(
                TerminalLevel::Info,
                if rebuild {
                    "Initramfs rebuild will run after forging."
                } else {
                    "Initramfs rebuild skipped per rebuild=false."
                },
            );
            updated = true;
            prompt_value = None;
        }

        if let Some(value) = kv.get("confirm") {
            let confirm = value.trim().to_ascii_lowercase();
            match confirm.as_str() {
                "wipe" | "format" | "commit" => {
                    self.apply_confirmation(&confirm)?;
                    updated = true;
                    prompt_value = None;
                }
                other => {
                    return Err(format!(
                        "Unknown confirmation `{other}`. Expected wipe, format, or commit."
                    ));
                }
            }
        }

        if kv.is_empty() && !free.is_empty() {
            let tokens = free.clone();
            if let Some(command) = tokens.first().map(|s| s.to_ascii_lowercase()) {
                match command.as_str() {
                    "mount" => {
                        if tokens.len() < 2 {
                            return Err(
                                "Provide a path after `mount` (e.g. mount /run/lockchain).".into(),
                            );
                        }
                        let path = tokens[1..].join(" ");
                        let mount = PathBuf::from(path.trim());
                        if !mount.is_absolute() {
                            return Err(
                                "mount must be an absolute path (e.g. /run/lockchain).".into()
                            );
                        }
                        if let Some(session) = self.safe_session.as_mut() {
                            session.mount = Some(mount.clone());
                        }
                        self.push_terminal_line(
                            TerminalLevel::Info,
                            format!("Mountpoint staged: {}", mount.display()),
                        );
                        updated = true;
                        prompt_value = None;
                    }
                    "filename" => {
                        if tokens.len() < 2 {
                            return Err(
                                "Provide a filename after `filename` (e.g. filename key.raw)."
                                    .into(),
                            );
                        }
                        let name = tokens[1..].join(" ").trim().to_string();
                        if name.is_empty() || name.contains('/') {
                            return Err(
                                "filename should be a plain name without directory separators."
                                    .into(),
                            );
                        }
                        if let Some(session) = self.safe_session.as_mut() {
                            session.filename = Some(name.clone());
                        }
                        self.push_terminal_line(
                            TerminalLevel::Info,
                            format!("Key filename set to {name}"),
                        );
                        updated = true;
                        prompt_value = None;
                    }
                    "passphrase" => {
                        if tokens.len() < 2 {
                            return Err(
                                "Provide the recovery passphrase after `passphrase`.".into()
                            );
                        }
                        let phrase = tokens[1..].join(" ");
                        if phrase.trim().is_empty() {
                            return Err("passphrase cannot be empty.".into());
                        }
                        if let Some(session) = self.safe_session.as_mut() {
                            session.passphrase = Some(phrase.trim().to_string());
                        }
                        self.push_terminal_line(
                            TerminalLevel::Info,
                            "Fallback passphrase will be configured for recovery.",
                        );
                        updated = true;
                        prompt_value = None;
                    }
                    "rebuild" => {
                        if tokens.len() < 2 {
                            return Err("Specify true or false after `rebuild`.".into());
                        }
                        let rebuild = parse_bool(tokens[1].as_str());
                        if let Some(session) = self.safe_session.as_mut() {
                            session.rebuild = Some(rebuild);
                        }
                        self.push_terminal_line(
                            TerminalLevel::Info,
                            if rebuild {
                                "Initramfs rebuild will run after forging."
                            } else {
                                "Initramfs rebuild skipped per rebuild=false."
                            },
                        );
                        updated = true;
                        prompt_value = None;
                    }
                    _ => {}
                }
            }
        }

        if let Some(value) = prompt_value.take() {
            let trimmed = value.as_str();
            let prompt_kind = self
                .safe_session
                .as_ref()
                .expect("session initialized")
                .next_prompt_kind();
            match prompt_kind {
                SafePromptKind::Dataset => {
                    if !looks_like_dataset_name(trimmed) {
                        return Err("Dataset must resemble pool/dataset (letters, digits, '-', '_', ':', '.').".into());
                    }
                    if let Some(session) = self.safe_session.as_mut() {
                        session.dataset = Some(trimmed.to_string());
                    }
                    self.push_terminal_line(
                        TerminalLevel::Info,
                        format!("Dataset staged: {trimmed}"),
                    );
                    updated = true;
                }
                SafePromptKind::Device => {
                    if trimmed.eq_ignore_ascii_case("list") {
                        self.terminal_input = "device=list".into();
                        return self.prepare_safe_mode_execution();
                    }
                    if trimmed.eq_ignore_ascii_case("auto") || trimmed.starts_with('#') {
                        if let Some(session) = self.safe_session.as_mut() {
                            session.device = Some(trimmed.to_string());
                        }
                        self.push_terminal_line(
                            TerminalLevel::Info,
                            "USB selection will be resolved automatically.",
                        );
                        updated = true;
                    } else {
                        static DEVICE_PATH_RE: OnceLock<Regex> = OnceLock::new();
                        let regex = DEVICE_PATH_RE.get_or_init(|| {
                            Regex::new(r"^/dev/[-A-Za-z0-9_./]+$").expect("valid device regex")
                        });
                        if !regex.is_match(trimmed) {
                            return Err("Provide a block device path (e.g. /dev/sdX1), auto, list, or #<index>.".into());
                        }
                        if let Some(session) = self.safe_session.as_mut() {
                            session.device = Some(trimmed.to_string());
                        }
                        self.push_terminal_line(
                            TerminalLevel::Info,
                            format!("USB device locked: {trimmed}"),
                        );
                        updated = true;
                    }
                }
                SafePromptKind::ConfirmWipe => {
                    if !trimmed.eq_ignore_ascii_case("wipe") {
                        return Err("Type wipe to confirm the media wipe.".into());
                    }
                    self.apply_confirmation("wipe")?;
                    updated = true;
                }
                SafePromptKind::ConfirmFormat => {
                    if !trimmed.eq_ignore_ascii_case("format") {
                        return Err("Type format to confirm filesystem creation.".into());
                    }
                    self.apply_confirmation("format")?;
                    updated = true;
                }
                SafePromptKind::ConfirmCommit => {
                    if !trimmed.eq_ignore_ascii_case("commit") {
                        return Err(
                            "Type commit to authorise key generation and configuration updates."
                                .into(),
                        );
                    }
                    self.apply_confirmation("commit")?;
                    updated = true;
                }
                SafePromptKind::Completed => {}
            }
        }

        if !updated && !kv.is_empty() {
            return Err("No safe-mode parameters were updated; review your input.".into());
        }

        if self
            .safe_session
            .as_ref()
            .expect("session initialized")
            .ready()
        {
            let command_args = self
                .safe_session
                .as_ref()
                .expect("session initialized")
                .as_command_args();
            self.safe_session = None;
            self.push_terminal_line(
                TerminalLevel::Success,
                "All confirmations captured. Beginning forge.",
            );
            self.terminal_input = command_args.clone();
            return Ok(Some(command_args));
        }

        if let Some(prompt) = self.safe_session.as_ref().map(|s| s.next_prompt()) {
            self.push_terminal_line(TerminalLevel::Prompt, prompt);
        }
        self.terminal_input.clear();
        Ok(None)
    }

    fn apply_confirmation(&mut self, token: &str) -> Result<(), String> {
        let session = self.safe_session.as_mut().ok_or_else(|| {
            "Safe mode session missing; start safe mode before confirming.".to_string()
        })?;
        match token {
            "wipe" => {
                session.confirm_wipe = true;
                self.push_terminal_line(TerminalLevel::Warning, "Media wipe approved.");
            }
            "format" => {
                session.confirm_format = true;
                self.push_terminal_line(TerminalLevel::Warning, "Filesystem format approved.");
            }
            "commit" => {
                session.confirm_commit = true;
                self.push_terminal_line(TerminalLevel::Warning, "Final forge commit approved.");
            }
            other => {
                return Err(format!(
                    "Unknown confirmation `{other}`. Expected wipe, format, or commit."
                ));
            }
        }
        Ok(())
    }

    fn forge_should_be_visible(&self) -> bool {
        if self.executing {
            return true;
        }
        match self.mission_phase {
            MissionPhase::Hidden => false,
            MissionPhase::Active { .. } => true,
            MissionPhase::Completed { finished_at } | MissionPhase::Failed { finished_at } => {
                finished_at.elapsed() < Duration::from_secs(MISSION_PERSIST_SECS)
            }
        }
    }

    /// Fast linear congruential RNG used for CRT flicker variation.
    fn next_terminal_random(&mut self) -> f32 {
        self.terminal_rng_state = self
            .terminal_rng_state
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        let sample = (self.terminal_rng_state >> 8) as f32;
        sample / ((u32::MAX >> 8) as f32)
    }

    fn trigger_terminal_flush(&mut self) -> Task<Message> {
        if self.terminal_flush_active || self.terminal_queue.is_empty() {
            Task::none()
        } else {
            self.terminal_flush_active = true;
            let delay = Duration::from_millis(TERMINAL_FLUSH_INTERVAL_MS);
            Task::future(async move {
                tokio_time::sleep(delay).await;
                Message::TerminalFlush
            })
        }
    }

    fn trigger_forge_tick(&mut self) -> Task<Message> {
        if self.forge_tick_active {
            Task::none()
        } else {
            self.forge_tick_active = true;
            let delay = Duration::from_millis(FORGE_ANIMATION_INTERVAL_MS);
            Task::future(async move {
                tokio_time::sleep(delay).await;
                Message::ForgeAnimationTick
            })
        }
    }

    fn finalize(&mut self, mut tasks: Vec<Task<Message>>) -> Task<Message> {
        tasks.push(self.trigger_terminal_flush());
        tasks.push(self.trigger_forge_tick());
        Task::batch(tasks)
    }

    fn directive_prompt_lines(&self, directive: Directive) -> Vec<(TerminalLevel, String)> {
        let mut lines = Vec::new();
        match directive {
            Directive::NewKey | Directive::NewKeySafe => {
                if self.config.policy.datasets.is_empty() {
                    lines.push((
                        TerminalLevel::Warning,
                        "No datasets configured. Open Settings to add pool/dataset entries."
                            .to_string(),
                    ));
                }
            }
            Directive::SelfTest => {
                if !self.key_present {
                    lines.push((
                        TerminalLevel::Warning,
                        "Self-Test unavailable until a LockChain key has been forged.".to_string(),
                    ));
                }
            }
            Directive::RecoverKey | Directive::Tune | Directive::Settings => {}
        }
        lines.push((
            TerminalLevel::Prompt,
            self.directive_prompt_message(directive),
        ));
        lines
    }

    fn directive_prompt_message(&self, directive: Directive) -> String {
        match directive {
            Directive::NewKey => {
                "Enter a dataset path or press Execute to use defaults; device=list/#/auto overrides USB selection.".into()
            }
            Directive::NewKeySafe => {
                "Safe mode ready. Enter the dataset to forge (e.g. rpool); type cancel anytime to restart.".into()
            }
            Directive::SelfTest => {
                "Press Execute to run the self-test or provide a dataset path to override the configured default.".into()
            }
            Directive::RecoverKey => {
                "Paste the 64-character recovery key or type your configured passphrase, then press Execute to restore.".into()
            }
            Directive::Tune => {
                "Press Execute to run the tuning sequence; no additional parameters are required.".into()
            }
            Directive::Settings => {
                "Use the Settings button to edit datasets and USB selectors; press Save to persist changes.".into()
            }
        }
    }

    fn directive_help_lines(&self, directive: Directive) -> Vec<(TerminalLevel, String)> {
        let mut lines = Vec::new();
        match directive {
            Directive::NewKey | Directive::NewKeySafe => {
                if self.config.policy.datasets.is_empty() {
                    lines.push((
                        TerminalLevel::Warning,
                        "No datasets configured. Open Settings to add pool/dataset entries."
                            .to_string(),
                    ));
                } else {
                    lines.push((
                        TerminalLevel::Info,
                        format!(
                            "Default target dataset(s): {}.",
                            self.config.policy.datasets.join(", ")
                        ),
                    ));
                }
                lines.push((
                    TerminalLevel::Info,
                    "Type a dataset path to override defaults, or comma-separate for multiple roots.".to_string(),
                ));
                lines.push((
                    TerminalLevel::Info,
                    "Type `list` to scan removable media, `#<index>` to choose, or `auto` to let LockChain select.".to_string(),
                ));
                if matches!(directive, Directive::NewKeySafe) {
                    lines.push((
                        TerminalLevel::Info,
                        "Safe mode walks through dataset → device → wipe → format → commit with confirmations.".to_string(),
                    ));
                    lines.push((
                        TerminalLevel::Info,
                        "Optional commands: mount /run/lockchain · filename lockchain.key · passphrase (then your secret) · rebuild false.".to_string(),
                    ));
                } else {
                    lines.push((
                        TerminalLevel::Info,
                        "Optional commands: mount /run/lockchain · filename lockchain.key · passphrase <secret> · rebuild false.".to_string(),
                    ));
                }
            }
            Directive::SelfTest => {
                if !self.key_present {
                    lines.push((
                        TerminalLevel::Warning,
                        "Forge or attach a LockChain key before running the self-test sequence."
                            .to_string(),
                    ));
                }
                lines.push((
                    TerminalLevel::Info,
                    "Runs a disposable forge/unlock cycle for validation; dataset=<path> overrides the default.".to_string(),
                ));
                lines.push((
                    TerminalLevel::Info,
                    "Add strict=true to require the configured USB selector before unlocking."
                        .to_string(),
                ));
            }
            Directive::RecoverKey => {
                lines.push((
                    TerminalLevel::Info,
                    "Paste the 64-character recovery key; whitespace is ignored automatically."
                        .to_string(),
                ));
                lines.push((
                    TerminalLevel::Info,
                    "Alternatively, type passphrase <secret> [output=/path] to derive the key material using the configured passphrase.".to_string(),
                ));
            }
            Directive::Tune => {
                lines.push((
                    TerminalLevel::Info,
                    "Validates dracut integration, audits systemd units, and refreshes USB selectors to keep services aligned.".to_string(),
                ));
            }
            Directive::Settings => {
                lines.push((
                    TerminalLevel::Info,
                    "Edit dataset defaults, USB label/UUID, or reset selectors; Save writes the configuration.".to_string(),
                ));
            }
        }
        lines
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::DirectiveSelected(directive) => {
                if self.settings_open || self.uninstall_open || self.executing {
                    return self.finalize(vec![]);
                }
                self.last_activity = Instant::now();
                if !self.executing {
                    self.progress_state = ProgressState::Idle;
                    self.forge_errors = 0;
                    self.forge_warnings = 0;
                    self.forge_breathe = 0.0;
                    self.mission_phase = MissionPhase::Hidden;
                    self.forge_reveal = 0.0;
                    self.reset_progress();
                }
                let start_safe = directive == Directive::NewKeySafe && self.safe_session.is_none();
                if directive != Directive::NewKeySafe {
                    self.safe_session = None;
                }
                self.recovery_overlay = None;
                if self.active_directive != directive {
                    self.active_directive = directive;
                    self.status_line = directive_title(directive).into();
                    self.announce_directive(directive);
                } else {
                    self.status_line = directive_title(directive).into();
                }
                if start_safe {
                    self.start_safe_mode_session();
                }
                self.finalize(vec![])
            }
            Message::TerminalChanged(value) => {
                self.terminal_input = value;
                self.last_activity = Instant::now();
                self.finalize(vec![])
            }
            Message::OpenSettings => {
                if self.executing || self.uninstall_open {
                    return self.finalize(vec![]);
                }
                self.settings_return = Some(self.active_directive);
                self.settings_open = true;
                self.settings_error = None;
                self.populate_settings_fields();
                self.active_directive = Directive::Settings;
                self.progress_state = ProgressState::Idle;
                self.mission_phase = MissionPhase::Hidden;
                self.forge_reveal = 0.0;
                self.reset_progress();
                self.status_line = "Settings".into();
                self.push_terminal_line(
                    TerminalLevel::Prompt,
                    "Settings overlay opened. Update datasets, label, or UUID, then press Save.",
                );
                self.finalize(vec![])
            }
            Message::UninstallPressed => {
                if self.executing || self.settings_open {
                    return self.finalize(vec![]);
                }
                self.uninstall_open = true;
                self.status_line = "Confirm uninstall".into();
                self.push_terminal_line(
                    TerminalLevel::Warning,
                    "Uninstall requested. Confirm to remove services or Cancel to abort.",
                );
                self.finalize(vec![])
            }
            Message::UninstallCancel => {
                self.uninstall_open = false;
                self.status_line = directive_title(self.active_directive).into();
                self.push_terminal_line(TerminalLevel::Info, "Uninstall cancelled.");
                self.last_announced_directive = None;
                self.announce_directive(self.active_directive);
                if !self.executing {
                    self.progress_state = ProgressState::Idle;
                    self.mission_phase = MissionPhase::Hidden;
                    self.forge_reveal = 0.0;
                    self.reset_progress();
                }
                self.finalize(vec![])
            }
            Message::UninstallConfirm => {
                if self.executing {
                    return self.finalize(vec![]);
                }
                self.uninstall_open = false;
                self.executing = true;
                self.progress_state = ProgressState::Running;
                self.mission_phase = MissionPhase::Active {
                    started_at: Instant::now(),
                };
                self.begin_progress(ProgressContext::Uninstall);
                self.pending_directive = None;
                self.push_activity(
                    ActivityLevel::Warn,
                    "LockChain uninstall initiated. Services and configuration will be removed.",
                );
                self.push_terminal_line(
                    TerminalLevel::Warning,
                    "Removing LockChain services, systemd units, and configuration…",
                );
                self.status_line = "Uninstalling LockChain components".into();
                self.finalize(vec![Task::perform(
                    run_uninstall(self.config_path.clone()),
                    Message::UninstallFinished,
                )])
            }
            Message::UninstallFinished(result) => {
                self.executing = false;
                match result {
                    Ok(report) => {
                        self.progress_state = ProgressState::Success;
                        self.mission_phase = MissionPhase::Completed {
                            finished_at: Instant::now(),
                        };
                        self.push_activity(
                            ActivityLevel::Success,
                            format!("{} complete", report.title),
                        );
                        self.push_terminal_line(
                            TerminalLevel::Success,
                            format!("{} complete", report.title),
                        );
                        self.ingest_events(report.events);
                        self.key_present = false;
                        self.status_line = "LockChain removed".into();
                        self.push_activity(
                            ActivityLevel::Warn,
                            "Reinstall required before executing directives.",
                        );
                        self.push_terminal_line(
                            TerminalLevel::Warning,
                            "LockChain binaries removed. Reinstall before running directives.",
                        );
                    }
                    Err(err) => {
                        self.progress_state = ProgressState::Failed;
                        self.mission_phase = MissionPhase::Failed {
                            finished_at: Instant::now(),
                        };
                        self.push_terminal_line(TerminalLevel::Error, err.clone());
                        self.push_activity(ActivityLevel::Error, err);
                        self.status_line = "Uninstall failed".into();
                    }
                }
                self.finalize(vec![])
            }
            Message::SettingsDatasetChanged(value) => {
                self.settings_dataset = value;
                self.settings_error = None;
                self.finalize(vec![])
            }
            Message::SettingsLabelChanged(value) => {
                self.settings_label = value;
                self.settings_error = None;
                self.finalize(vec![])
            }
            Message::SettingsUuidChanged(value) => {
                self.settings_uuid = value;
                self.settings_error = None;
                self.finalize(vec![])
            }
            Message::SettingsPassphraseChanged(value) => {
                self.settings_passphrase = value;
                self.settings_error = None;
                self.finalize(vec![])
            }
            Message::SettingsSave => {
                if let Err(err) = self.apply_settings() {
                    self.push_terminal_line(
                        TerminalLevel::Error,
                        format!("Settings update failed: {err}"),
                    );
                    self.settings_error = Some(err);
                    return self.finalize(vec![]);
                }
                self.progress_state = ProgressState::Idle;
                self.mission_phase = MissionPhase::Hidden;
                self.forge_reveal = 0.0;
                self.reset_progress();
                if self.active_directive == Directive::NewKeySafe {
                    self.start_safe_mode_session();
                }
                self.finalize(vec![])
            }
            Message::SettingsDiscard => {
                self.settings_open = false;
                self.settings_error = None;
                self.populate_settings_fields();
                self.restore_active_directive();
                self.status_line = directive_title(self.active_directive).into();
                self.push_terminal_line(
                    TerminalLevel::Info,
                    "Settings discarded; retaining current configuration.",
                );
                self.last_announced_directive = None;
                self.announce_directive(self.active_directive);
                self.progress_state = ProgressState::Idle;
                self.mission_phase = MissionPhase::Hidden;
                self.forge_reveal = 0.0;
                self.reset_progress();
                self.finalize(vec![])
            }
            Message::Execute => {
                if self.executing || self.settings_open || self.uninstall_open {
                    return self.finalize(vec![]);
                }
                if self.active_directive == Directive::NewKeySafe {
                    match self.prepare_safe_mode_execution() {
                        Ok(Some(prepared)) => {
                            self.terminal_input = prepared;
                        }
                        Ok(None) => {
                            self.terminal_input.clear();
                            return self.finalize(vec![]);
                        }
                        Err(err) => {
                            self.push_terminal_line(TerminalLevel::Error, err);
                            self.terminal_input.clear();
                            return self.finalize(vec![]);
                        }
                    }
                }
                if !self.action_ready() {
                    let reason = match self.active_directive {
                        Directive::NewKey | Directive::NewKeySafe => {
                            "Configure a dataset and USB selector before forging."
                        }
                        Directive::SelfTest => {
                            "Insert or forge a LockChain key before running the self-test."
                        }
                        Directive::RecoverKey => {
                            "Paste the recovery key or enter a passphrase before restoring."
                        }
                        _ => "Prerequisites not satisfied for this directive.",
                    };
                    self.push_terminal_line(TerminalLevel::Warning, reason.to_string());
                    self.push_activity(ActivityLevel::Warn, reason.to_string());
                    return self.finalize(vec![]);
                }
                self.recovery_overlay = None;
                self.executing = true;
                self.pending_directive = Some(self.active_directive);
                self.progress_state = ProgressState::Running;
                self.mission_phase = MissionPhase::Active {
                    started_at: Instant::now(),
                };
                self.begin_progress(ProgressContext::Directive(self.active_directive));
                self.safe_session = None;
                self.forge_errors = 0;
                self.forge_warnings = 0;
                self.forge_breathe = 0.0;
                let preview = self.compose_command_preview();
                self.push_terminal_line(TerminalLevel::Input, preview);
                self.push_terminal_line(
                    TerminalLevel::Info,
                    format!("Executing {}…", directive_title(self.active_directive)),
                );
                self.status_line = format!("Running {}", directive_title(self.active_directive));
                self.finalize(vec![Task::perform(
                    run_directive(
                        self.config_path.clone(),
                        self.active_directive,
                        self.terminal_input.clone(),
                    ),
                    Message::WorkflowFinished,
                )])
            }
            Message::WorkflowFinished(result) => {
                self.executing = false;
                let directive = self
                    .pending_directive
                    .take()
                    .unwrap_or(self.active_directive);
                let success = match result {
                    Ok(report) => {
                        self.progress_state = ProgressState::Success;
                        self.mission_phase = MissionPhase::Completed {
                            finished_at: Instant::now(),
                        };
                        let summary = format!("{} complete", report.title);
                        self.push_terminal_line(TerminalLevel::Success, summary);
                        self.ingest_events(report.events.clone());
                        if matches!(directive, Directive::NewKey | Directive::NewKeySafe) {
                            self.key_present = true;
                        }
                        if let Some(secret) = report.recovery_key.clone() {
                            self.recovery_overlay = Some(RecoveryOverlay { secret_hex: secret });
                            self.status_line = "Record recovery key".into();
                        } else {
                            self.recovery_overlay = None;
                            self.status_line = "Ready".into();
                        }
                        true
                    }
                    Err(err) => {
                        self.progress_state = ProgressState::Failed;
                        self.mission_phase = MissionPhase::Failed {
                            finished_at: Instant::now(),
                        };
                        self.push_terminal_line(TerminalLevel::Error, err.clone());
                        self.push_activity(ActivityLevel::Error, err);
                        self.status_line = "Attention required".into();
                        self.recovery_overlay = None;
                        false
                    }
                };
                self.progress_ratio = if success { 1.0 } else { 0.0 };
                self.progress_context = None;
                self.progress_count = 0;
                self.progress_expected = 1;
                self.safe_session = None;
                self.reload_config_snapshot();
                if directive == Directive::NewKeySafe && self.recovery_overlay.is_none() {
                    self.start_safe_mode_session();
                    self.push_terminal_line(
                        TerminalLevel::Prompt,
                        self.directive_prompt_message(Directive::NewKeySafe),
                    );
                }
                self.finalize(vec![])
            }
            Message::HelpPressed => {
                self.push_terminal_line(
                    TerminalLevel::Info,
                    help_text(self.active_directive).to_string(),
                );
                for (level, line) in self.directive_help_lines(self.active_directive) {
                    self.push_terminal_line(level, line);
                }
                self.finalize(vec![])
            }
            Message::RecoveryAcknowledge => {
                if self.recovery_overlay.is_some() {
                    self.recovery_overlay = None;
                    self.push_terminal_line(
                        TerminalLevel::Success,
                        "Recovery key acknowledged. Store it securely before continuing.",
                    );
                    if self.active_directive == Directive::NewKeySafe && !self.executing {
                        self.start_safe_mode_session();
                    }
                    if !self.executing {
                        self.status_line = "Ready".into();
                    }
                }
                self.finalize(vec![])
            }
            Message::ClearTerminal => {
                self.terminal_lines.clear();
                self.terminal_queue.clear();
                self.terminal_flush_active = false;
                self.total_events = 0;
                self.forge_errors = 0;
                self.forge_warnings = 0;
                self.status_line = "Terminal cleared".into();
                self.recovery_overlay = None;
                if !self.executing {
                    self.progress_state = ProgressState::Idle;
                    self.mission_phase = MissionPhase::Hidden;
                    self.forge_reveal = 0.0;
                    self.reset_progress();
                    if self.active_directive == Directive::NewKeySafe {
                        self.start_safe_mode_session();
                    } else {
                        self.safe_session = None;
                    }
                    self.last_announced_directive = None;
                    self.announce_directive(self.active_directive);
                }
                self.finalize(vec![])
            }
            Message::DownloadLogs => {
                if self.exporting_logs {
                    return self.finalize(vec![]);
                }
                let log_text = self.exportable_terminal_log();
                self.exporting_logs = true;
                self.status_line = "Bundling logs".into();
                self.push_terminal_line(TerminalLevel::Info, "Preparing performance log bundle…");
                self.finalize(vec![Task::perform(
                    export_logs(log_text),
                    Message::DownloadLogsFinished,
                )])
            }
            Message::DownloadLogsFinished(result) => {
                self.exporting_logs = false;
                match result {
                    Ok(path) => {
                        self.push_terminal_line(
                            TerminalLevel::Success,
                            format!("Logs exported to {}", path.display()),
                        );
                        self.status_line = "Logs ready".into();
                    }
                    Err(err) => {
                        self.push_terminal_line(
                            TerminalLevel::Error,
                            format!("Log export failed: {err}"),
                        );
                        self.status_line = "Log export failed".into();
                    }
                }
                self.finalize(vec![])
            }
            Message::TerminalFlush => {
                if let Some(line) = self.terminal_queue.pop_front() {
                    self.terminal_lines.push_front(line);
                    while self.terminal_lines.len() > TERMINAL_HISTORY_LIMIT {
                        self.terminal_lines.pop_back();
                    }
                }
                self.terminal_flush_active = false;
                self.finalize(vec![])
            }
            Message::ForgeAnimationTick => {
                let delta = if self.executing { 4.0 } else { 1.6 };
                self.forge_phase = (self.forge_phase + delta) % 360.0;
                let flicker_delta = if self.executing { 3.8 } else { 2.0 };
                let jitter_scale = if self.executing { 1.2 } else { 0.8 };
                let phase_jitter = (self.next_terminal_random() - 0.5) * jitter_scale;
                self.terminal_phase =
                    (self.terminal_phase + flicker_delta + phase_jitter).rem_euclid(720.0);
                if (self.terminal_static_level - self.terminal_static_target).abs() < 0.04 {
                    let swing = if self.executing { 0.28 } else { 0.2 };
                    self.terminal_static_target = (self.next_terminal_random() - 0.5) * swing;
                }
                self.terminal_static_level +=
                    (self.terminal_static_target - self.terminal_static_level) * 0.18;
                if (self.terminal_glare_offset - self.terminal_glare_target).abs() < 0.02
                    || self.next_terminal_random() > 0.96
                {
                    self.terminal_glare_target = self.next_terminal_random();
                }
                self.terminal_glare_offset +=
                    (self.terminal_glare_target - self.terminal_glare_offset) * 0.12;
                if (self.terminal_glare_span - self.terminal_glare_span_target).abs() < 0.03
                    || self.next_terminal_random() > 0.97
                {
                    self.terminal_glare_span_target = 0.1 + self.next_terminal_random() * 0.1;
                }
                self.terminal_glare_span +=
                    (self.terminal_glare_span_target - self.terminal_glare_span) * 0.06;
                let target = if self.forge_should_be_visible() {
                    1.0
                } else {
                    0.0
                };
                if target > self.forge_reveal {
                    self.forge_reveal = (self.forge_reveal + FORGE_REVEAL_STEP).min(1.0);
                } else {
                    self.forge_reveal = (self.forge_reveal - FORGE_HIDE_STEP).max(0.0);
                }
                if !self.executing {
                    match self.mission_phase {
                        MissionPhase::Completed { finished_at } => {
                            if finished_at.elapsed() >= Duration::from_secs(MISSION_PERSIST_SECS) {
                                self.mission_phase = MissionPhase::Hidden;
                                self.progress_state = ProgressState::Idle;
                                self.forge_reveal = 0.0;
                            }
                        }
                        MissionPhase::Failed { finished_at } => {
                            if finished_at.elapsed() >= Duration::from_secs(MISSION_PERSIST_SECS) {
                                self.mission_phase = MissionPhase::Hidden;
                                self.progress_state = ProgressState::Idle;
                                self.forge_reveal = 0.0;
                            }
                        }
                        MissionPhase::Active { .. } => {
                            self.mission_phase = MissionPhase::Hidden;
                            self.progress_state = ProgressState::Idle;
                            self.forge_reveal = 0.0;
                        }
                        MissionPhase::Hidden => {}
                    }
                }
                if !self.executing {
                    self.forge_breathe = (self.forge_breathe + 0.05) % (2.0 * std::f32::consts::PI);
                }
                self.forge_tick_active = false;
                self.finalize(vec![])
            }
        }
    }

    fn view(&self) -> iced::Element<'_, Message> {
        view::render(self)
    }

    fn theme(&self) -> Theme {
        Theme::TokyoNight
    }

    fn reload_config_snapshot(&mut self) {
        if let Ok(cfg) = load_ui_config(&self.config_path) {
            self.config_path = cfg.path.clone();
            self.key_present = Self::has_key_material(&cfg);
            self.config = cfg;
        } else {
            self.key_present = false;
        }
        self.populate_settings_fields();
        self.last_announced_directive = None;
        self.announce_directive(self.active_directive);
    }

    fn dataset_ready(&self) -> bool {
        self.config
            .policy
            .datasets
            .iter()
            .any(|ds| !ds.trim().is_empty())
    }

    fn device_ready(&self) -> bool {
        self.config
            .usb
            .device_uuid
            .as_deref()
            .map(|uuid| !uuid.trim().is_empty())
            .unwrap_or(false)
            || self
                .config
                .usb
                .device_label
                .as_deref()
                .map(|label| {
                    let trimmed = label.trim();
                    !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case(PLACEHOLDER_LABEL)
                })
                .unwrap_or(false)
    }

    fn usb_present(&self) -> bool {
        if let Some(uuid) = self
            .config
            .usb
            .device_uuid
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let path = Path::new("/dev/disk/by-uuid").join(uuid);
            if path.exists() {
                return true;
            }
        }

        if let Some(label) = self
            .config
            .usb
            .device_label
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case(PLACEHOLDER_LABEL))
        {
            let path = Path::new("/dev/disk/by-label").join(label);
            if path.exists() {
                return true;
            }
        }

        false
    }

    fn provision_ready(&self) -> bool {
        self.dataset_ready() && self.device_ready()
    }

    fn fallback_ready(&self) -> bool {
        self.config.fallback.enabled
            && self
                .config
                .fallback
                .passphrase_salt
                .as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(false)
            && self
                .config
                .fallback
                .passphrase_xor
                .as_ref()
                .map(|x| !x.is_empty())
                .unwrap_or(false)
    }

    fn directive_ready(&self, directive: Directive) -> bool {
        match directive {
            Directive::NewKey => self.provision_ready(),
            Directive::NewKeySafe => true,
            Directive::SelfTest => self.key_present,
            Directive::RecoverKey => true,
            Directive::Tune | Directive::Settings => true,
        }
    }

    fn action_ready(&self) -> bool {
        self.directive_ready(self.active_directive)
    }

    fn security_state(&self) -> (bool, &'static str) {
        if self.key_present && self.provision_ready() {
            (true, "SECURE")
        } else {
            (false, "FORGING")
        }
    }

    fn populate_settings_fields(&mut self) {
        self.settings_dataset = if self.config.policy.datasets.is_empty() {
            "rpool".to_string()
        } else {
            self.config.policy.datasets.join(", ")
        };
        self.settings_label = self.config.usb.device_label.clone().unwrap_or_default();
        self.settings_uuid = self.config.usb.device_uuid.clone().unwrap_or_default();
        self.settings_passphrase.clear();
        if self.settings_open {
            self.settings_error = None;
        }
    }

    fn restore_active_directive(&mut self) {
        if let Some(previous) = self.settings_return.take() {
            self.active_directive = previous;
        }
    }

    fn apply_settings(&mut self) -> Result<(), String> {
        let dataset_input = self.settings_dataset.trim();
        let datasets: Vec<String> = dataset_input
            .split(|ch| [',', '\n', ';'].contains(&ch))
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect();

        if datasets.is_empty() {
            return Err("Provide at least one ZFS dataset (e.g. rpool).".into());
        }
        if datasets.iter().any(|ds| !looks_like_dataset_name(ds)) {
            return Err(
                "Dataset entries must be valid ZFS dataset names (letters, digits, '_', '-', ':', '.')."
                    .into(),
            );
        }

        let label = self.settings_label.trim();
        let uuid = self.settings_uuid.trim();
        if label.is_empty() && uuid.is_empty() {
            return Err("Set a USB device label or UUID so LockChain can detect the key.".into());
        }
        if label.eq_ignore_ascii_case(PLACEHOLDER_LABEL) {
            return Err(
                "Replace the placeholder USB label with the value reported by `lsblk -o LABEL`."
                    .into(),
            );
        }
        if !uuid.is_empty()
            && !uuid
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() || matches!(ch, '-' | '_'))
        {
            return Err("USB UUID should contain hexadecimal characters (and optional hyphens/underscores).".into());
        }

        self.config.policy.datasets = datasets;
        self.config.usb.device_label = if label.is_empty() {
            None
        } else {
            Some(label.to_string())
        };
        self.config.usb.device_uuid = if uuid.is_empty() {
            None
        } else {
            Some(uuid.to_string())
        };

        // Apply optional fallback passphrase; empty input disables fallback.
        if self.settings_passphrase.is_empty() {
            self.config.fallback.enabled = false;
            self.config.fallback.passphrase_salt = None;
            self.config.fallback.passphrase_xor = None;
        } else if self.settings_passphrase.len() < 8 {
            return Err(
                "Provide a passphrase with at least 8 characters or leave it blank to disable."
                    .into(),
            );
        } else {
            let mut cfg_clone = self.config.clone();
            workflow::update_fallback_passphrase(
                &mut cfg_clone,
                Some(self.settings_passphrase.clone()),
            )
            .map_err(|err| format!("Failed to set fallback passphrase: {err}"))?;
            self.config = cfg_clone;
            self.settings_passphrase.clear();
            self.push_terminal_line(
                TerminalLevel::Security,
                "Fallback passphrase updated; store it securely.",
            );
        }

        self.config
            .save()
            .map_err(|err| format!("Failed to save configuration: {err}"))?;

        self.reload_config_snapshot();
        self.settings_open = false;
        self.settings_error = None;
        self.key_present = self.config.key_hex_path().exists();
        self.status_line = "Settings saved".into();
        self.push_terminal_line(TerminalLevel::Success, "Settings updated and persisted.");
        self.restore_active_directive();
        self.last_announced_directive = None;
        self.announce_directive(self.active_directive);
        self.progress_state = ProgressState::Idle;
        self.mission_phase = MissionPhase::Hidden;
        self.forge_reveal = 0.0;
        self.reset_progress();
        if self.active_directive == Directive::NewKeySafe {
            self.start_safe_mode_session();
        }
        Ok(())
    }

    fn ingest_events(&mut self, events: Vec<WorkflowEvent>) {
        for event in events {
            self.bump_progress();
            let level = event.level;
            let message = event.message;
            let terminal_level = TerminalLevel::from(level);
            match level {
                WorkflowLevel::Info | WorkflowLevel::Success => {
                    self.push_terminal_line(terminal_level, message);
                }
                WorkflowLevel::Warn | WorkflowLevel::Error => {
                    self.push_terminal_line(terminal_level, message.clone());
                    self.push_activity(ActivityLevel::from(level), message);
                    match level {
                        WorkflowLevel::Warn => {
                            self.forge_warnings = self.forge_warnings.saturating_add(1)
                        }
                        WorkflowLevel::Error => {
                            self.forge_errors = self.forge_errors.saturating_add(1)
                        }
                        _ => {}
                    }
                }
                WorkflowLevel::Security => {
                    self.push_terminal_line(terminal_level, message.clone());
                    self.push_activity(ActivityLevel::Security, message);
                }
            }
        }
    }

    fn push_activity(&mut self, _level: ActivityLevel, _message: impl Into<String>) {
        self.total_events = self.total_events.saturating_add(1);
    }
}

fn directive_title(directive: Directive) -> &'static str {
    match directive {
        Directive::NewKey => "New Key",
        Directive::NewKeySafe => "New Key (Safe mode)",
        Directive::SelfTest => "Test Key",
        Directive::RecoverKey => "Restore Key",
        Directive::Tune => "Tuning Tasks",
        Directive::Settings => "Settings",
    }
}

fn help_text(directive: Directive) -> &'static str {
    match directive {
        Directive::NewKey => "Forge a new 32-byte USB key. Type a dataset path to override defaults and use list/#/auto to choose the USB device.",
        Directive::NewKeySafe => "Safe forge collects dataset, device, and confirmations interactively. Respond to prompts with the requested value (dataset path, /dev path or auto/#, then wipe/format/commit).",
        Directive::SelfTest => "Provision a scratch encrypted pool, unlock it with the current key, then tear it down. Provide a dataset path to override defaults and add strict=true to enforce the configured selector.",
        Directive::RecoverKey => "Recreate USB key material by pasting the recovery key or typing the configured passphrase. Optional output=/path overrides /var/lib/lockchain/<dataset>.key.",
        Directive::Tune => "Run the end-to-end tuning suite to refresh LockChain integration.",
        Directive::Settings => "Update defaults: dataset=<pool/dataset>, label=<USB_LABEL>, uuid=<DEVICE_UUID>, reset_usb=true.",
    }
}

fn load_ui_config(path: &Path) -> Result<LockchainConfig, String> {
    let config = LockchainConfig::load_or_bootstrap(path).map_err(|e| e.to_string())?;
    if config.path != path {
        let requested = path.display().to_string();
        let actual = config.path.display().to_string();
        BOOTSTRAP_NOTICE.get_or_init(|| {
            warn!("configuration missing at {requested}; using bootstrap at {actual}");
        });
    }
    Ok(config)
}

fn expected_events_for(context: ProgressContext) -> usize {
    match context {
        ProgressContext::Directive(Directive::NewKey)
        | ProgressContext::Directive(Directive::NewKeySafe) => 12,
        ProgressContext::Directive(Directive::SelfTest) => 14,
        ProgressContext::Directive(Directive::RecoverKey) => 4,
        ProgressContext::Directive(Directive::Tune) => 30,
        ProgressContext::Directive(Directive::Settings) => 4,
        ProgressContext::Uninstall => 18,
    }
}

async fn run_uninstall(config_path: PathBuf) -> Result<WorkflowReport, String> {
    let config = load_ui_config(&config_path)?;
    workflow::uninstall(&config).map_err(|e| e.to_string())
}

async fn run_directive(
    config_path: PathBuf,
    directive: Directive,
    raw_input: String,
) -> Result<WorkflowReport, String> {
    let mut config = load_ui_config(&config_path)?;
    let provider = SystemZfsProvider::from_config(&config).map_err(|err| err.to_string())?;

    let (kv, free) = parse_kv(&raw_input);

    match directive {
        Directive::NewKey | Directive::NewKeySafe => {
            let dataset = resolve_dataset(&config, &kv, &free)?;
            let mode = if matches!(directive, Directive::NewKeySafe) {
                ForgeMode::Safe
            } else {
                ForgeMode::Standard
            };

            let mut options = ProvisionOptions::default();
            if let Some(device) = kv.get("device").map(|s| s.to_string()) {
                options.usb_device = Some(device);
            }
            if let Some(mount) = kv.get("mount").map(PathBuf::from) {
                options.mountpoint = Some(mount);
            }
            if let Some(file) = kv
                .get("filename")
                .or_else(|| kv.get("file"))
                .map(|s| s.to_string())
            {
                options.key_filename = Some(file);
            }
            if let Some(pass) = kv.get("passphrase").map(|s| s.to_string()) {
                options.passphrase = Some(pass);
            }
            if let Some(force) = kv.get("force").map(|v| parse_bool(v)) {
                options.force_wipe = force;
            } else if matches!(mode, ForgeMode::Standard) {
                options.force_wipe = true;
            }
            if let Some(rebuild) = kv.get("rebuild").map(|v| parse_bool(v)) {
                options.rebuild_initramfs = rebuild;
            }

            let mut usb_preface = prepare_usb_selection(&config, &mut options)?;

            let mut report = workflow::forge_key(&mut config, &provider, &dataset, mode, options)
                .map_err(|e| e.to_string())?;

            if !usb_preface.is_empty() {
                usb_preface.extend(report.events.into_iter());
                report.events = usb_preface;
            }

            Ok(report)
        }
        Directive::SelfTest => {
            let dataset = resolve_dataset(&config, &kv, &free)?;
            let strict_usb = kv
                .get("strict_usb")
                .or_else(|| kv.get("strict"))
                .map(|v| parse_bool(v))
                .unwrap_or(false);
            workflow::self_test(&config, provider, &dataset, strict_usb).map_err(|e| e.to_string())
        }
        Directive::RecoverKey => {
            let dataset = resolve_dataset(&config, &kv, &free)?;
            let output = kv
                .get("output")
                .map(PathBuf::from)
                .unwrap_or_else(|| default_recovery_path(&dataset));

            enum RecoverySpec {
                Hex(String),
                Passphrase(String),
            }

            let hex_from_arg = kv
                .get("recovery")
                .or_else(|| kv.get("key"))
                .map(|value| value.to_string());

            let spec = if let Some(secret) = hex_from_arg {
                let cleaned: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
                if cleaned.is_empty() {
                    return Err("Recovery key cannot be empty.".to_string());
                }
                if !cleaned.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    return Err(
                        "Recovery key must only contain hexadecimal characters (0-9, a-f)."
                            .to_string(),
                    );
                }
                RecoverySpec::Hex(cleaned)
            } else {
                let inferred_hex = if !free.is_empty() && !kv.contains_key("passphrase") {
                    let joined: String = free.join("");
                    let cleaned: String = joined.chars().filter(|c| !c.is_whitespace()).collect();
                    if cleaned.len() == 64 && cleaned.chars().all(|ch| ch.is_ascii_hexdigit()) {
                        Some(cleaned)
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(secret) = inferred_hex {
                    RecoverySpec::Hex(secret)
                } else {
                    let phrase = kv
                        .get("passphrase")
                        .map(|s| s.to_string())
                        .or_else(|| {
                            if !free.is_empty() {
                                Some(free.join(" "))
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| {
                            "Paste the recovery key or type the configured passphrase to restore."
                                .to_string()
                        })?;
                    RecoverySpec::Passphrase(phrase)
                }
            };

            match spec {
                RecoverySpec::Hex(secret) => workflow::recover_key(
                    &config,
                    provider,
                    &dataset,
                    RecoveryInput::Hex(&secret),
                    &output,
                )
                .map_err(|e| e.to_string()),
                RecoverySpec::Passphrase(pass) => workflow::recover_key(
                    &config,
                    provider,
                    &dataset,
                    RecoveryInput::Passphrase(pass.as_bytes()),
                    &output,
                )
                .map_err(|e| e.to_string()),
            }
        }
        Directive::Tune => {
            let mut report =
                workflow::tune(&config, provider.clone()).map_err(|e| e.to_string())?;
            report.title = "Tuning sequence".into();
            Ok(report)
        }
        Directive::Settings => {
            let mut events = Vec::new();
            let mut changed = false;

            if let Some(value) = kv
                .get("dataset")
                .or_else(|| kv.get("datasets"))
                .cloned()
                .or_else(|| free.first().cloned())
            {
                let datasets: Vec<String> = value
                    .split(',')
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty())
                    .collect();
                if !datasets.is_empty() {
                    config.policy.datasets = datasets.clone();
                    events.push(wf(
                        WorkflowLevel::Info,
                        format!("Datasets set to {}", datasets.join(", ")),
                    ));
                    changed = true;
                }
            }

            if let Some(value) = kv.get("label") {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    config.usb.device_label = Some(trimmed.to_string());
                    config.usb.device_uuid = None;
                    events.push(wf(
                        WorkflowLevel::Info,
                        format!("USB device label set to {trimmed}"),
                    ));
                    changed = true;
                }
            }

            if let Some(value) = kv.get("uuid") {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    config.usb.device_uuid = Some(trimmed.to_string());
                    config.usb.device_label = None;
                    events.push(wf(
                        WorkflowLevel::Info,
                        format!("USB device UUID set to {trimmed}"),
                    ));
                    changed = true;
                }
            }

            if kv.get("reset_usb").map(|v| parse_bool(v)).unwrap_or(false) {
                config.usb.device_label = None;
                config.usb.device_uuid = None;
                events.push(wf(
                    WorkflowLevel::Info,
                    "Cleared stored USB selectors.".to_string(),
                ));
                changed = true;
            }

            if changed {
                config.save().map_err(|e| e.to_string())?;
                events.push(wf(
                    WorkflowLevel::Success,
                    format!("Configuration saved to {}", config.path.display()),
                ));
                Ok(WorkflowReport {
                    title: "Settings updated".into(),
                    events,
                    recovery_key: None,
                })
            } else {
                let summary = format!(
                    "Current datasets: {} | USB selector: {}",
                    config.policy.datasets.join(", "),
                    config
                        .usb
                        .device_label
                        .clone()
                        .or(config.usb.device_uuid.clone())
                        .unwrap_or_else(|| "not set".to_string())
                );
                Ok(WorkflowReport {
                    title: "Settings review".into(),
                    events: vec![wf(WorkflowLevel::Info, summary)],
                    recovery_key: None,
                })
            }
        }
    }
}

fn prepare_usb_selection(
    config: &LockchainConfig,
    options: &mut ProvisionOptions,
) -> Result<Vec<WorkflowEvent>, String> {
    let mut events = Vec::new();

    if let Some(selector) = options.usb_device.clone() {
        let trimmed = selector.trim();
        if trimmed.eq_ignore_ascii_case("list") {
            let candidates = workflow::discover_usb_candidates().map_err(|err| err.to_string())?;
            return Err(workflow::render_usb_selection_prompt(&candidates));
        }
        if trimmed.eq_ignore_ascii_case("auto") {
            options.usb_device = None;
        } else if let Some(candidate) =
            workflow::usb_candidate_from_selector(trimmed).map_err(|err| err.to_string())?
        {
            options.usb_device = Some(candidate.device.clone());
            let level = if candidate
                .mountpoint
                .as_deref()
                .filter(|mp| !mp.is_empty())
                .is_some()
            {
                WorkflowLevel::Warn
            } else {
                WorkflowLevel::Info
            };
            events.push(wf(level, format!("Selected {}", candidate.describe())));
        }
    }

    let label_missing = config
        .usb
        .device_label
        .as_deref()
        .map(|value| {
            let trimmed = value.trim();
            trimmed.is_empty() || trimmed.eq_ignore_ascii_case(PLACEHOLDER_LABEL)
        })
        .unwrap_or(true);

    let uuid_missing = config
        .usb
        .device_uuid
        .as_deref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true);

    if options.usb_device.is_none() && label_missing && uuid_missing {
        let candidates = workflow::discover_usb_candidates().map_err(|err| err.to_string())?;
        match candidates.len() {
            0 => {
                return Err("No removable USB storage detected. Attach the LockChain token or specify device=/dev/sdX.".into());
            }
            1 => {
                let candidate = &candidates[0];
                options.usb_device = Some(candidate.device.clone());
                let level = if candidate
                    .mountpoint
                    .as_deref()
                    .filter(|mp| !mp.is_empty())
                    .is_some()
                {
                    WorkflowLevel::Warn
                } else {
                    WorkflowLevel::Info
                };
                events.push(wf(level, format!("Auto-selected {}", candidate.describe())));
            }
            _ => {
                return Err(workflow::render_usb_selection_prompt(&candidates));
            }
        }
    }

    Ok(events)
}

async fn export_logs(ui_log: String) -> Result<PathBuf, String> {
    let export_root = std::env::temp_dir().join("lockchain-logs");
    fs::create_dir_all(&export_root).map_err(|err| err.to_string())?;

    let filename = format!(
        "lockchain-ui-logs-{}.txt",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_secs())
            .unwrap_or_default()
    );
    let bundle_path = export_root.join(filename);
    let mut file = std::fs::File::create(&bundle_path).map_err(|err| err.to_string())?;

    writeln!(
        file,
        "# LockChain UI log bundle\n# Saved at {}\n# Directory: {}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        export_root.display()
    )
    .map_err(|err| err.to_string())?;

    writeln!(file, "{ui_log}").map_err(|err| err.to_string())?;

    // Also include performance bundle paths if available, but do not fail if missing.
    if let Ok(perf_path) = perf::bundle_logs(Some(export_root.clone())) {
        writeln!(
            file,
            "\n# Performance bundle staged at {}\n",
            perf_path.display()
        )
        .map_err(|err| err.to_string())?;
    }

    Ok(bundle_path)
}

fn wf(level: WorkflowLevel, message: impl Into<String>) -> WorkflowEvent {
    WorkflowEvent {
        level,
        message: message.into(),
    }
}

fn parse_kv(input: &str) -> (HashMap<String, String>, Vec<String>) {
    let mut map = HashMap::new();
    let mut free = Vec::new();

    for token in input.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            map.insert(key.to_lowercase(), value.to_string());
        } else if let Some((key, value)) = token.split_once(':') {
            map.insert(key.to_lowercase(), value.to_string());
        } else {
            free.push(token.to_string());
        }
    }

    (map, free)
}

fn parse_bool(input: &str) -> bool {
    matches!(
        input.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn resolve_dataset(
    config: &LockchainConfig,
    kv: &HashMap<String, String>,
    free: &[String],
) -> Result<String, String> {
    if let Some(ds) = kv.get("dataset") {
        return Ok(ds.clone());
    }
    if let Some(first) = free.first() {
        if first.contains('/') {
            return Ok(first.clone());
        }
    }
    config
        .policy
        .datasets
        .first()
        .cloned()
        .ok_or_else(|| "No dataset configured; add one to policy.datasets".to_string())
}

fn default_recovery_path(dataset: &str) -> PathBuf {
    let sanitized = dataset.replace('/', "-");
    let timestamp = Local::now().format("%Y%m%d%H%M%S");
    Path::new("/var/lib/lockchain").join(format!("{}_{}.key", sanitized, timestamp))
}

#[cfg(test)]
mod tests;
