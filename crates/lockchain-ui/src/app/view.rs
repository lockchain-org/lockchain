//! Renders the Control Deck UI tree using Iced widgets.

use super::{
    directive_title, icon, style, Directive, DirectiveMeta, LockchainUi, Message, MissionPhase,
    ProgressState, RecoveryOverlay, TerminalLevel, TerminalLine, DIRECTIVES, FONT_MONO_BOLD,
    FONT_MONO_REGULAR, FONT_UI_BOLD, FONT_UI_REGULAR,
};
use iced::alignment::Vertical;
use iced::widget::canvas::{self, gradient, Canvas, Frame, Gradient, LineJoin, Path, Stroke};
use iced::widget::progress_bar;
use iced::widget::svg::Svg;
use iced::widget::tooltip::Position as TooltipPosition;
use iced::widget::{
    button, column, container, row, scrollable, text, text_input, tooltip, Column, Row, Space,
    Stack,
};
use iced::{
    mouse, Alignment, Color, Element, Length, Padding, Point, Rectangle, Renderer, Size, Theme,
};
use iced_aw::Spinner;
use qrcodegen::{QrCode, QrCodeEcc};

const HUD_HEIGHT: f32 = 112.0;
const PAD_ROOT: u16 = 12;
const PAD_CARD_Y: u16 = 12;
const PAD_CARD_X: u16 = 20;
const GAP_SECTION: u16 = 12;
const GAP_GROUP: u16 = 10;
const FONT_BODY: u16 = 13;
const FONT_MICRO: u16 = 11;
const MISSION_PANEL_HEIGHT: f32 = 168.0;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(super) fn render(ui: &LockchainUi) -> Element<'_, Message> {
    // Root renderer: compose header, directive hotbar, panels, visualiser, and footer.
    let column = Column::new()
        .spacing(GAP_SECTION)
        .width(Length::Fill)
        .push(render_header(ui))
        .push(render_directive_bar(ui))
        .push(render_main_content(ui))
        .push(render_mission_report(ui))
        .push(render_footer(ui));

    let base: Element<'_, Message> = container(column)
        .padding(PAD_ROOT)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(style::background())
        .into();

    let mut stack = Stack::new()
        .width(Length::Fill)
        .height(Length::Fill)
        .push(base);

    if ui.settings_open {
        stack = stack.push(render_settings_overlay(ui));
    }
    if ui.uninstall_open {
        stack = stack.push(render_uninstall_overlay());
    }
    if let Some(recovery) = &ui.recovery_overlay {
        stack = stack.push(render_recovery_overlay(recovery));
    }

    stack.into()
}

// Neon header: logo badge, descriptive copy, global status HUD, and controls.
fn render_header(ui: &LockchainUi) -> Element<'_, Message> {
    let copy = column![
        text("CONTROL DECK")
            .size(22)
            .style(text_color(Color::from_rgb8(0x00, 0xd3, 0xf8)))
            .font(FONT_UI_BOLD),
        text("CRYPTOGRAPHIC KEY MANAGEMENT")
            .size(FONT_BODY)
            .style(text_color(Color::from_rgb8(0x5a, 0x6b, 0x8f)))
            .font(FONT_UI_BOLD),
    ]
    .spacing(GAP_GROUP);

    let uninstall = button(
        text("Uninstall")
            .size(FONT_BODY)
            .font(FONT_UI_BOLD)
            .style(text_color(Color::from_rgb8(0x05, 0x08, 0x1f))),
    )
    .padding([8, 18])
    .style(style::danger_button())
    .on_press(Message::UninstallPressed);

    let settings = button(
        text("Settings")
            .size(FONT_BODY)
            .style(text_color(Color::from_rgb8(0x05, 0x08, 0x1f)))
            .font(FONT_UI_BOLD),
    )
    .padding([8, 18])
    .style(style::primary_button())
    .on_press(Message::OpenSettings);

    let left_group = row![copy]
        .spacing(GAP_SECTION)
        .align_y(Vertical::Center)
        .height(Length::Fill);

    let status_pod = container(render_status_cluster(ui))
        .width(Length::Shrink)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Vertical::Center);

    let action_group = row![uninstall, settings]
        .spacing(12)
        .align_y(Vertical::Center)
        .height(Length::Fill);

    let layout = Row::with_children(vec![
        left_group.into(),
        Space::with_width(Length::Fill).into(),
        status_pod.into(),
        Space::with_width(Length::Fill).into(),
        action_group.into(),
    ])
    .spacing(GAP_SECTION)
    .align_y(Vertical::Center)
    .height(Length::Fill);

    container(layout)
        .padding([PAD_CARD_Y, PAD_CARD_X])
        .height(Length::Fixed(HUD_HEIGHT))
        .align_y(Vertical::Center)
        .style(style::header_card())
        .into()
}

// Directive hotbar rendered as evenly spaced tiles.
fn render_directive_bar(ui: &LockchainUi) -> Element<'_, Message> {
    let tiles: Vec<Element<'_, Message>> = DIRECTIVES
        .iter()
        .map(|meta| render_directive_tile(ui, *meta))
        .collect();

    container(
        Row::with_children(tiles)
            .spacing(GAP_SECTION)
            .align_y(Vertical::Center)
            .width(Length::Shrink)
            .height(Length::Fill),
    )
    .padding([PAD_CARD_Y, PAD_CARD_X])
    .height(Length::Fixed(HUD_HEIGHT))
    .align_y(Vertical::Center)
    .width(Length::Fill)
    .align_x(Alignment::Center)
    .style(style::module_bar_card())
    .into()
}

// Individual directive card with icon, caption, and contextual tooltip.
fn render_directive_tile(ui: &LockchainUi, meta: DirectiveMeta) -> Element<'_, Message> {
    let active = ui.active_directive == meta.directive;
    let ready = ui.directive_ready(meta.directive);
    let icon_handle = icon::directive(meta.glyph, Color::from_rgb8(0x00, 0xd3, 0xf8));
    let icon = Svg::new(icon_handle)
        .width(Length::Fixed(32.0))
        .height(Length::Fixed(32.0));

    let label = text(directive_tile_caption(meta.directive))
        .size(13)
        .font(FONT_UI_BOLD)
        .style(text_color(Color::from_rgb8(0xf7, 0xff, 0xff)));

    let pad_inner_y = PAD_CARD_Y.min(12);
    let pad_inner_x = PAD_CARD_X.saturating_sub(2);

    let mut content = column![icon, Space::with_height(Length::Fixed(6.0)), label]
        .spacing(6)
        .align_x(Alignment::Center)
        .width(Length::Fixed(120.0));

    if !ready {
        content = content.push(
            text(readiness_badge(meta.directive))
                .size(11)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0xff, 0xb3, 0x4d))),
        );
    }

    let mut card_button = button(content)
        .padding([pad_inner_y, pad_inner_x])
        .style(style::directive_tile(active, ready));

    if ready {
        card_button = card_button.on_press(Message::DirectiveSelected(meta.directive));
    }

    let tooltip_label = if ready {
        meta.tooltip
    } else {
        readiness_hint(meta.directive)
    };

    let tip = container(
        text(tooltip_label)
            .size(12)
            .font(FONT_UI_REGULAR)
            .style(text_color(Color::from_rgb8(0xe7, 0xff, 0xff))),
    )
    .padding(12)
    .style(style::tooltip_panel());

    tooltip(card_button, tip, TooltipPosition::Bottom)
        .gap(8)
        .padding(6)
        .into()
}

fn directive_tile_caption(directive: Directive) -> &'static str {
    match directive {
        Directive::NewKey => "NEW KEY",
        Directive::NewKeySafe => "SAFE MODE",
        Directive::SelfTest => "SELF-TEST",
        Directive::RecoverKey => "RECOVER",
        Directive::Tune => "TUNING",
        Directive::Settings => "SETTINGS",
    }
}

fn readiness_hint(directive: Directive) -> &'static str {
    match directive {
        Directive::NewKey | Directive::NewKeySafe => {
            "Configure dataset and USB defaults in Settings or follow the safe-mode prompts before forging."
        }
        Directive::SelfTest => "Forge or attach a LockChain key before running the self-test sequence.",
        _ => "Complete prerequisite setup before executing this directive.",
    }
}

fn readiness_badge(directive: Directive) -> &'static str {
    match directive {
        Directive::NewKey | Directive::NewKeySafe => "Configure dataset/USB",
        Directive::SelfTest => "Key required",
        _ => "Setup pending",
    }
}

// Primary terminal section with scrollback, input, and controls.
fn render_main_content(ui: &LockchainUi) -> Element<'_, Message> {
    render_terminal_panel(ui)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn render_terminal_panel(ui: &LockchainUi) -> container::Container<'_, Message> {
    // Neon terminal shell with holographic backdrop, mission report, log, and controls.
    let input = text_input("Enter command or parameters...", &ui.terminal_input)
        .on_input(Message::TerminalChanged)
        .size(FONT_BODY)
        .padding([8, 12])
        .width(Length::Fill)
        .font(FONT_MONO_REGULAR)
        .style(style::text_input());

    let header = column![row![text("COMMAND CHANNEL")
        .size(20)
        .font(FONT_UI_BOLD)
        .style(text_color(Color::from_rgb8(0xff, 0x73, 0xff))),]]
    .spacing(GAP_GROUP);

    let block_pad_x = PAD_CARD_X.saturating_sub(4);

    let command_block = container(
        column![
            text("COMMAND INPUT")
                .size(FONT_BODY)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0x00, 0xff, 0xd7))),
            input,
        ]
        .spacing(GAP_GROUP),
    )
    .padding([PAD_CARD_Y, block_pad_x])
    .style(style::terminal_surface());

    let command_block_element: Element<'_, Message> = command_block.into();
    let actions_element: Element<'_, Message> =
        render_action_row(ui.action_ready(), ui.executing, ui.exporting_logs).into();

    let terminal_content = Column::new()
        .spacing(GAP_SECTION)
        .height(Length::Fill)
        .push(render_terminal_log(ui))
        .push(command_block_element)
        .push(actions_element);

    let card_pad_y = PAD_CARD_Y * 2;

    container(column![header, terminal_content].spacing(GAP_SECTION))
        .padding([card_pad_y, PAD_CARD_X])
        .width(Length::Fill)
        .style(style::terminal_card())
}

// Summary HUD chips showing global resource status.
fn render_status_cluster(ui: &LockchainUi) -> Element<'_, Message> {
    let mut tiles: Vec<Element<'_, Message>> = Vec::with_capacity(3);
    tiles.push(render_status_chip(
        "DATASETS",
        if ui.dataset_ready() {
            "READY"
        } else {
            "MISSING"
        },
        if ui.dataset_ready() {
            Color::from_rgb8(0x00, 0xff, 0x9c)
        } else {
            Color::from_rgb8(0xff, 0x4d, 0x7a)
        },
    ));
    tiles.push(render_status_chip(
        "USB",
        if ui.usb_present() { "READY" } else { "MISSING" },
        if ui.usb_present() {
            Color::from_rgb8(0x00, 0xff, 0x9c)
        } else {
            Color::from_rgb8(0xff, 0x4d, 0x7a)
        },
    ));
    tiles.push(render_status_chip(
        "FALLBACK",
        if ui.fallback_ready() {
            "ENABLED"
        } else {
            "DISABLED"
        },
        if ui.fallback_ready() {
            Color::from_rgb8(0xff, 0x73, 0xff)
        } else {
            Color::from_rgb8(0xff, 0x4d, 0x7a)
        },
    ));
    Row::with_children(tiles)
        .spacing(GAP_SECTION)
        .align_y(Vertical::Center)
        .height(Length::Fill)
        .into()
}

// Collapsible mission report card that animates with forge progress.
fn render_mission_report(ui: &LockchainUi) -> Element<'_, Message> {
    if ui.settings_open || ui.uninstall_open {
        return Space::with_height(Length::Shrink).into();
    }

    if matches!(ui.mission_phase, MissionPhase::Hidden) && !ui.executing {
        return Space::with_height(Length::Shrink).into();
    }

    let reveal = ui.forge_reveal.clamp(0.0, 1.0);
    if reveal <= 0.01 {
        return Space::with_height(Length::Shrink).into();
    }

    let panel: Element<'_, Message> = render_mission_report_panel(ui).into();

    container(panel)
        .width(Length::Fill)
        .height(Length::Fixed(MISSION_PANEL_HEIGHT))
        .padding(Padding {
            top: 0.0,
            right: PAD_CARD_X as f32,
            bottom: 0.0,
            left: PAD_CARD_X as f32,
        })
        .align_y(Vertical::Bottom)
        .into()
}

// Inner mission report layout with progress bar, directive info, and spinner.
fn render_mission_report_panel(ui: &LockchainUi) -> container::Container<'_, Message> {
    let forging = matches!(ui.progress_state, ProgressState::Running);
    let spinner: Element<'_, Message> = if forging {
        Spinner::new()
            .width(Length::Fixed(54.0))
            .height(Length::Fixed(54.0))
            .circle_radius(6.0)
            .into()
    } else {
        container(
            text("◎")
                .size(28)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0x67, 0xd6, 0xff))),
        )
        .width(Length::Fixed(54.0))
        .height(Length::Fixed(54.0))
        .align_x(Alignment::Center)
        .align_y(Vertical::Center)
        .into()
    };

    let metrics = format!(
        "Queue {:02} · Transcript {:02} · Datasets {}",
        ui.terminal_queue.len(),
        ui.terminal_lines.len().min(99),
        if ui.dataset_ready() {
            "READY"
        } else {
            "MISSING"
        }
    );

    let anomaly_summary = format!(
        "Anomalies: {} errors · {} warnings",
        ui.forge_errors, ui.forge_warnings
    );

    let (bar_value, caption_text, status_label, status_color) = match ui.progress_state {
        ProgressState::Idle => (
            0.0,
            String::from("Status: Idle"),
            "IDLE",
            Color::from_rgb8(0x6f, 0xd7, 0xff),
        ),
        ProgressState::Running => {
            let base = if ui.progress_ratio > 0.0 {
                ui.progress_ratio.clamp(0.05, 0.95)
            } else {
                let oscillation = (ui.forge_phase / 32.0).sin() * 0.35 + 0.55;
                oscillation.clamp(0.15, 0.95)
            };
            let caption = if ui.progress_ratio > 0.0 {
                format!("Status: Running ({:>3.0}%)", base * 100.0)
            } else {
                "Status: Running".to_string()
            };
            (base, caption, "RUNNING", Color::from_rgb8(0x00, 0xff, 0x88))
        }
        ProgressState::Success => (
            1.0,
            String::from("Status: Complete"),
            "COMPLETE",
            Color::from_rgb8(0xff, 0xff, 0x73),
        ),
        ProgressState::Failed => (
            0.0,
            String::from("Status: Failed"),
            "FAILED",
            Color::from_rgb8(0xff, 0x55, 0x88),
        ),
    };

    let progress_bar = progress_bar(0.0..=1.0, bar_value.clamp(0.0, 1.0))
        .height(Length::Fixed(16.0))
        .width(Length::Fill)
        .style(style::mission_progress_bar(
            ui.forge_phase,
            ui.progress_state,
        ));

    let progress_caption = container(
        text(caption_text)
            .size(FONT_MICRO)
            .font(FONT_UI_BOLD)
            .style(text_color(Color::from_rgb8(0xff, 0xff, 0xff))),
    )
    .width(Length::Fill)
    .align_x(Alignment::Center)
    .align_y(Vertical::Center)
    .padding([0, 12]);

    let progress_stack = Stack::new()
        .width(Length::Fill)
        .push(
            container(progress_bar)
                .padding([6, 8])
                .style(style::mission_progress_shell(
                    ui.forge_breathe,
                    matches!(ui.progress_state, ProgressState::Success),
                )),
        )
        .push(progress_caption);

    let progress_block = column![
        progress_stack,
        row![text(status_label)
            .size(FONT_MICRO)
            .font(FONT_UI_BOLD)
            .style(text_color(status_color)),]
        .spacing(GAP_GROUP)
        .align_y(Vertical::Center),
    ]
    .spacing(GAP_GROUP);

    let panel = column![
        row![
            text("MISSION REPORT")
                .size(FONT_BODY)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0x00, 0xff, 0xd7))),
            Space::with_width(Length::Fill),
            text(if forging { "ACTIVE" } else { "IDLE" })
                .size(FONT_MICRO)
                .font(FONT_UI_BOLD)
                .style(text_color(if forging {
                    Color::from_rgb8(0x00, 0xff, 0x88)
                } else {
                    Color::from_rgb8(0xff, 0xa8, 0x0a)
                })),
        ]
        .spacing(GAP_GROUP)
        .align_y(Vertical::Center),
        row![
            container(spinner)
                .width(Length::Fixed(72.0))
                .height(Length::Fixed(72.0))
                .align_x(Alignment::Center)
                .align_y(Vertical::Center)
                .style(style::mission_spinner_pod()),
            column![
                text(format!(
                    "Directive: {}",
                    directive_title(ui.active_directive)
                ))
                .size(FONT_BODY)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0x67, 0xd6, 0xff))),
                text(metrics)
                    .size(FONT_MICRO)
                    .font(FONT_UI_REGULAR)
                    .style(text_color(Color::from_rgb8(0x4c, 0x8f, 0xff))),
                text(anomaly_summary)
                    .size(FONT_MICRO)
                    .font(FONT_UI_BOLD)
                    .style(text_color(if ui.forge_errors > 0 {
                        Color::from_rgb8(0xff, 0x55, 0x66)
                    } else if ui.forge_warnings > 0 {
                        Color::from_rgb8(0xff, 0xa8, 0x0a)
                    } else {
                        Color::from_rgb8(0x6f, 0xd7, 0xff)
                    })),
            ]
            .spacing(GAP_GROUP),
        ]
        .spacing(GAP_SECTION)
        .align_y(Vertical::Center),
        progress_block,
    ]
    .spacing(GAP_SECTION);

    container(panel)
        .padding([PAD_CARD_Y, PAD_CARD_X])
        .width(Length::Fill)
        .height(Length::Fixed(MISSION_PANEL_HEIGHT))
        .style(style::mission_report_card())
}

// Scrollable console history with CRT overlay treatment.
fn render_terminal_log(ui: &LockchainUi) -> Element<'_, Message> {
    let mut lines = Column::new().spacing(GAP_GROUP);
    if ui.terminal_lines.is_empty() {
        lines = lines.push(
            text("Terminal ready. Enter parameters or press Help to review syntax.")
                .size(FONT_BODY)
                .font(FONT_MONO_REGULAR)
                .style(text_color(Color::from_rgb8(0x67, 0xd6, 0xff))),
        );
    } else {
        for (index, line) in ui.terminal_lines.iter().enumerate() {
            lines = lines.push(render_terminal_entry(index, line));
        }
    }

    let scroll = scrollable(lines).height(Length::Fill).width(Length::Fill);
    let flicker = ((ui.terminal_phase / 45.0).sin() * 0.5 + 0.5).clamp(0.0, 1.0);
    let scanlines_canvas = Canvas::new(CrtScanlines::new(
        ui.terminal_phase,
        flicker,
        ui.terminal_static_level,
        ui.terminal_glare_offset,
        ui.terminal_glare_span,
    ))
    .width(Length::Fill)
    .height(Length::Fill);

    let stack = Stack::new()
        .width(Length::Fill)
        .height(Length::Fill)
        .push(
            container(scroll)
                .padding([PAD_CARD_Y, PAD_CARD_X])
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .push(
            container(scanlines_canvas)
                .width(Length::Fill)
                .height(Length::Fill)
                .style(style::terminal_crt_scanlines()),
        )
        .push(
            container(Space::new(Length::Fill, Length::Fill))
                .width(Length::Fill)
                .height(Length::Fill)
                .style(style::terminal_crt_glow(flicker)),
        );

    container(stack)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(style::terminal_log())
        .into()
}

// Formats a single log entry with timestamp, level, and accent colour.
fn render_terminal_entry(index: usize, line: &TerminalLine) -> Element<'_, Message> {
    let label = terminal_label(line.level);
    let text_value = match label {
        Some(prefix) => format!("[{}] {}", prefix, line.message),
        None => line.message.clone(),
    };
    let timestamp = line.timestamp.format("%H:%M:%S").to_string();

    let accent = container(Space::new(Length::Fixed(4.0), Length::Fixed(20.0)))
        .padding([0, 2])
        .align_y(Vertical::Center)
        .style(style::terminal_line_accent(terminal_color(line.level)));

    let payload = row![
        text(timestamp)
            .size(FONT_MICRO)
            .font(FONT_MONO_BOLD)
            .style(text_color(Color::from_rgb8(0x39, 0xd2, 0xff))),
        text(text_value)
            .size(FONT_BODY)
            .font(if matches!(line.level, TerminalLevel::Input) {
                FONT_MONO_BOLD
            } else {
                FONT_MONO_REGULAR
            })
            .style(text_color(terminal_color(line.level))),
    ]
    .spacing(GAP_GROUP)
    .align_y(Vertical::Center);

    container(row![
        accent,
        Space::with_width(Length::Fixed(10.0)),
        payload
    ])
    .padding([6, 14])
    .width(Length::Fill)
    .style(style::terminal_line(index.is_multiple_of(2)))
    .into()
}

fn terminal_label(level: TerminalLevel) -> Option<&'static str> {
    match level {
        TerminalLevel::Input => None,
        TerminalLevel::Prompt => Some("PROMPT"),
        TerminalLevel::Info => Some("INFO"),
        TerminalLevel::Success => Some("SUCCESS"),
        TerminalLevel::Warning => Some("WARN"),
        TerminalLevel::Error => Some("ERROR"),
        TerminalLevel::Security => Some("SECURITY"),
    }
}

fn terminal_color(level: TerminalLevel) -> Color {
    match level {
        TerminalLevel::Input => Color::from_rgb8(0x00, 0xff, 0x88),
        TerminalLevel::Prompt => Color::from_rgb8(0x67, 0xd6, 0xff),
        TerminalLevel::Info => Color::from_rgb8(0xe7, 0xff, 0xff),
        TerminalLevel::Success => Color::from_rgb8(0x00, 0xff, 0x88),
        TerminalLevel::Warning => Color::from_rgb8(0xff, 0xaa, 0x00),
        TerminalLevel::Error => Color::from_rgb8(0xff, 0x00, 0x55),
        TerminalLevel::Security => Color::from_rgb8(0xff, 0x00, 0xff),
    }
}

// Execute/Help combo, disabled when workloads are in flight.
fn render_action_row(
    action_ready: bool,
    executing: bool,
    exporting_logs: bool,
) -> Row<'static, Message> {
    let mut execute_button = button(
        text("Execute")
            .size(14)
            .font(FONT_UI_BOLD)
            .style(text_color(Color::from_rgb8(0x05, 0x08, 0x1f))),
    )
    .padding([8, 18])
    .style(style::execute_button(action_ready && !executing));

    if action_ready && !executing {
        execute_button = execute_button.on_press(Message::Execute);
    }

    row![
        execute_button,
        button(
            text("Clear")
                .size(14)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0xff, 0xe6, 0xf6)))
        )
        .padding([8, 18])
        .style(style::clear_button())
        .on_press(Message::ClearTerminal),
        {
            let label = if exporting_logs {
                "Bundling…"
            } else {
                "Download Logs"
            };
            let mut log_button = button(
                text(label)
                    .size(14)
                    .font(FONT_UI_BOLD)
                    .style(text_color(Color::from_rgb8(0x05, 0x08, 0x1f))),
            )
            .padding([8, 18])
            .style(style::primary_button());

            if !exporting_logs {
                log_button = log_button.on_press(Message::DownloadLogs);
            }
            log_button
        },
        button(
            text("Help")
                .size(14)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0xe7, 0xff, 0xff)))
        )
        .padding([8, 18])
        .style(style::help_button())
        .on_press(Message::HelpPressed),
        Space::with_width(Length::Fill),
    ]
    .spacing(GAP_SECTION)
    .align_y(Vertical::Center)
}

#[derive(Debug, Clone, Copy)]
struct CrtScanlines {
    phase: f32,
    intensity: f32,
    static_level: f32,
    glare_offset: f32,
    glare_span: f32,
}

impl CrtScanlines {
    fn new(
        phase: f32,
        intensity: f32,
        static_level: f32,
        glare_offset: f32,
        glare_span: f32,
    ) -> Self {
        Self {
            phase,
            intensity,
            static_level,
            glare_offset,
            glare_span,
        }
    }
}

impl canvas::Program<Message> for CrtScanlines {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let width = bounds.width;
        let height = bounds.height;

        let spacing = 2.6 + self.glare_span * 0.7;
        let drift_wave = (self.phase * 0.02 + self.static_level * 1.7).sin();
        let offset = (self.phase * (0.45 + self.glare_span * 0.2) + drift_wave * spacing)
            .rem_euclid(spacing.max(0.1));
        let mut y = -offset;

        let base_alpha = 0.027 + self.intensity * 0.045;
        let noise_alpha = (base_alpha + self.static_level * 0.018).clamp(0.015, 0.085);
        let line_green = (0.7 + self.static_level * 0.09).clamp(0.4, 0.86);
        let line_blue = (0.5 + self.static_level * 0.07).clamp(0.32, 0.78);
        let line_color = Color::from_rgba(0.0, line_green, line_blue, noise_alpha);
        let static_thickness = 0.26 + self.intensity * 0.06 + self.static_level.abs() * 0.065;

        let mut index = 0;

        while y < height + spacing {
            let clamped_y = y.max(0.0);
            let line = Path::line(Point::new(0.0, clamped_y), Point::new(width, clamped_y));
            let thickness = if index % 11 == 0 {
                static_thickness + 0.12
            } else if index % 5 == 0 {
                static_thickness
            } else {
                static_thickness * 0.68
            };
            let stroke = Stroke::default()
                .with_width(thickness)
                .with_color(line_color);
            frame.stroke(&line, stroke);
            if index % 13 == 0 {
                let band_alpha = (0.022 + self.intensity * 0.028 + self.static_level.abs() * 0.028)
                    .clamp(0.008, 0.055);
                frame.fill_rectangle(
                    Point::new(0.0, clamped_y),
                    Size::new(width, spacing * 0.35),
                    Color::from_rgba(0.0, 0.31, 0.26, band_alpha),
                );
            }
            index += 1;
            y += spacing;
        }

        let panel = Path::rectangle(Point::new(0.0, 0.0), Size::new(width, height));
        let edge_strength = (0.08
            + self.intensity * 0.028
            + self.glare_span * 0.02
            + self.static_level.abs() * 0.028)
            .clamp(0.045, 0.15);
        let horizontal = gradient::Linear::new(
            Point::new(0.0, height * 0.5),
            Point::new(width, height * 0.5),
        )
        .add_stop(0.0, Color::from_rgba(0.0, 0.0, 0.0, edge_strength))
        .add_stop(0.5, Color::from_rgba(0.0, 0.0, 0.0, 0.0))
        .add_stop(1.0, Color::from_rgba(0.0, 0.0, 0.0, edge_strength));
        frame.fill(&panel, Gradient::Linear(horizontal));

        let vertical_strength =
            (0.13 + self.intensity * 0.035 + self.static_level.abs() * 0.03).clamp(0.09, 0.2);
        let vertical = gradient::Linear::new(
            Point::new(width * 0.5, 0.0),
            Point::new(width * 0.5, height),
        )
        .add_stop(0.0, Color::from_rgba(0.0, 0.0, 0.0, vertical_strength))
        .add_stop(0.5, Color::from_rgba(0.0, 0.0, 0.0, 0.0))
        .add_stop(1.0, Color::from_rgba(0.0, 0.0, 0.0, vertical_strength));
        frame.fill(&panel, Gradient::Linear(vertical));

        let glare_center = (0.08 + self.glare_offset * 0.84).clamp(0.0, 0.98);
        let glare_height = (0.05 + self.glare_span * 0.12).clamp(0.035, 0.18);
        let glare_top = (glare_center - glare_height * 0.5).clamp(0.0, 1.0 - glare_height);
        let highlight_alpha =
            (0.015 + self.intensity * 0.02 + self.static_level.abs() * 0.02).clamp(0.008, 0.075);
        frame.fill_rectangle(
            Point::new(0.0, height * glare_top),
            Size::new(width, height * glare_height),
            Color::from_rgba(
                0.36,
                1.0,
                0.88,
                (highlight_alpha + self.static_level.max(0.0) * 0.035).clamp(0.016, 0.095),
            ),
        );
        let lower_band_top = (glare_top + glare_height + 0.16 + self.glare_span * 0.14)
            .min(1.0 - glare_height * 0.4);
        frame.fill_rectangle(
            Point::new(0.0, height * lower_band_top),
            Size::new(width, height * (glare_height * 0.7)),
            Color::from_rgba(
                0.02,
                (0.27 + self.intensity * 0.06).clamp(0.18, 0.42),
                (0.23 + self.static_level.abs() * 0.06).clamp(0.17, 0.38),
                (highlight_alpha * 0.55).clamp(0.007, 0.06),
            ),
        );

        if self.static_level.abs() > 0.35 {
            let spark_y = (self.phase * 3.7).rem_euclid(height.max(1.0));
            frame.fill_rectangle(
                Point::new(width * 0.08, spark_y),
                Size::new(width * 0.84, 0.65 + self.static_level.abs() * 0.45),
                Color::from_rgba(0.92, 1.0, 0.44, 0.022 + self.static_level.abs() * 0.016),
            );
        }

        let rim_width = (width.max(height) * (0.012 + self.glare_span * 0.006)).clamp(2.0, 8.0);
        let rim_color = Color::from_rgba(
            0.0,
            0.28,
            0.34,
            (0.16 + self.intensity * 0.05 + self.static_level.abs() * 0.04).clamp(0.1, 0.24),
        );
        let rim = Stroke::default()
            .with_width(rim_width)
            .with_color(rim_color)
            .with_line_join(LineJoin::Round);
        frame.stroke(&panel, rim);

        let sweep_height = 22.0;
        let sweep_cycle = height + sweep_height * 2.0;
        let sweep_pos = ((self.phase * 4.2) % sweep_cycle) - sweep_height;
        if sweep_pos < height {
            let sweep_alpha = 0.014 + self.intensity * 0.045;
            let sweep_color = Color::from_rgba(0.28, 1.0, 0.92, sweep_alpha);
            let sweep = Path::rectangle(
                Point::new(0.0, sweep_pos.max(-sweep_height)),
                Size::new(width, sweep_height),
            );
            frame.fill(&sweep, sweep_color);
        }

        vec![frame.into_geometry()]
    }
}

// Small neon chip summarising a single global status.
fn render_status_chip(
    label: &str,
    value: impl Into<String>,
    tint: Color,
) -> Element<'static, Message> {
    let label_owned = label.to_owned();
    let value = value.into();
    container(
        column![
            text(label_owned)
                .size(11)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0xa9, 0xb2, 0xc6))),
            text(value)
                .size(13)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0xf4, 0xff, 0xff))),
        ]
        .spacing(2)
        .align_x(Alignment::Center),
    )
    .padding([8, 14])
    .style(style::status_chip(tint))
    .width(Length::Shrink)
    .into()
}

// Footer shows application build info and active security mode.
fn render_footer(ui: &LockchainUi) -> Element<'_, Message> {
    let (secure, label) = ui.security_state();
    container(
        row![
            text(format!("LockChain Control Deck v{}", APP_VERSION))
                .size(12)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0x5a, 0x6b, 0x8f))),
            Space::with_width(Length::Fill),
            text("Security Mode:")
                .size(12)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0x5a, 0x6b, 0x8f))),
            text(label)
                .size(12)
                .font(FONT_UI_BOLD)
                .style(text_color(if secure {
                    Color::from_rgb8(0x00, 0xff, 0x88)
                } else {
                    Color::from_rgb8(0xff, 0xaa, 0x00)
                })),
        ]
        .align_y(Vertical::Center),
    )
    .padding([10, 4])
    .into()
}

fn render_settings_overlay(ui: &LockchainUi) -> Element<'_, Message> {
    // Settings modal echoes the CLI flags with inline tooltips.
    let dataset_tip: Element<'_, Message> = render_tooltip_panel(
        "Managed encrypted root dataset list.",
        "Provide ZFS dataset names in pool/dataset form (e.g. rpool).",
    );

    let label_tip: Element<'_, Message> = render_tooltip_panel(
        "Matches the removable media LABEL from `lsblk -o LABEL`.",
        "Setting a label clears any stored UUID to avoid conflicts.",
    );

    let uuid_tip: Element<'_, Message> = render_tooltip_panel(
        "Optional match using the block device UUID reported by `blkid`.",
        "Use hexadecimal characters with optional '-' or '_' separators.",
    );

    let dataset_input = tooltip(
        text_input("rpool", &ui.settings_dataset)
            .on_input(Message::SettingsDatasetChanged)
            .size(FONT_BODY)
            .font(FONT_MONO_REGULAR)
            .padding([8, 12])
            .width(Length::Fill)
            .style(style::text_input()),
        dataset_tip,
        TooltipPosition::Bottom,
    )
    .gap(10)
    .padding(6);

    let label_input = tooltip(
        text_input("LOCKCHAINKEY", &ui.settings_label)
            .on_input(Message::SettingsLabelChanged)
            .size(FONT_BODY)
            .font(FONT_MONO_REGULAR)
            .padding([8, 12])
            .width(Length::Fill)
            .style(style::text_input()),
        label_tip,
        TooltipPosition::Bottom,
    )
    .gap(10)
    .padding(6);

    let uuid_input = tooltip(
        text_input("1234-ABCD", &ui.settings_uuid)
            .on_input(Message::SettingsUuidChanged)
            .size(FONT_BODY)
            .font(FONT_MONO_REGULAR)
            .padding([8, 12])
            .width(Length::Fill)
            .style(style::text_input()),
        uuid_tip,
        TooltipPosition::Bottom,
    )
    .gap(10)
    .padding(6);

    let passphrase_input = tooltip(
        text_input("optional fallback passphrase (masked)", &ui.settings_passphrase)
            .on_input(Message::SettingsPassphraseChanged)
            .size(FONT_BODY)
            .font(FONT_MONO_REGULAR)
            .padding([8, 12])
            .width(Length::Fill)
            .style(style::text_input())
            .secure(true),
        render_tooltip_panel(
            "Optional fallback passphrase, used only when the USB key is unavailable.",
            "Leave blank to disable. Input is masked and never stored in plaintext; derived material is saved in the config.",
        ),
        TooltipPosition::Bottom,
    )
    .gap(10)
    .padding(6);

    let mut rows = column![
        text("SETTINGS")
            .size(22)
            .font(FONT_UI_BOLD)
            .style(text_color(Color::from_rgb8(0x00, 0xd3, 0xf8))),
        text("Update provisioning defaults, dataset selection, and USB selectors.")
            .size(FONT_BODY)
            .font(FONT_UI_REGULAR)
            .style(text_color(Color::from_rgb8(0xe7, 0xff, 0xff))),
        dataset_input,
        label_input,
        uuid_input,
        passphrase_input,
        row![
            text("reset_usb=true")
                .size(FONT_BODY)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0xff, 0x00, 0xff))),
            text(" clears stored USB selectors.")
                .size(FONT_BODY)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0xe7, 0xff, 0xff))),
        ]
        .spacing(8),
    ]
    .spacing(GAP_SECTION);

    if let Some(error) = &ui.settings_error {
        rows = rows.push(
            text(error)
                .size(FONT_BODY)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0xff, 0x00, 0x55))),
        );
    }

    rows = rows.push(
        row![
            button(
                text("Discard")
                    .size(14)
                    .font(FONT_UI_BOLD)
                    .style(text_color(Color::from_rgb8(0xff, 0x73, 0xff)))
            )
            .padding([8, 18])
            .style(style::danger_button())
            .on_press(Message::SettingsDiscard),
            button(
                text("Save")
                    .size(14)
                    .font(FONT_UI_BOLD)
                    .style(text_color(Color::from_rgb8(0x05, 0x08, 0x1f)))
            )
            .padding([8, 18])
            .style(style::primary_button())
            .on_press(Message::SettingsSave),
        ]
        .spacing(GAP_SECTION)
        .align_y(Vertical::Center),
    );

    let panel = container(rows)
        .padding(18)
        .width(Length::Fixed(540.0))
        .style(style::modal_panel());

    container(panel)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(style::overlay_backdrop())
        .into()
}

fn render_uninstall_overlay() -> Element<'static, Message> {
    // Confirmation modal for uninstall flows.
    let warning = column![
        text("UNINSTALL LOCKCHAIN")
            .size(22)
            .font(FONT_UI_BOLD)
            .style(text_color(Color::from_rgb8(0xff, 0x00, 0x55))),
        text("This action removes LockChain services, configuration, cached key material, and runtime assets. USB key contents will be purged where possible.")
            .size(FONT_BODY)
            .font(FONT_UI_REGULAR)
            .style(text_color(Color::from_rgb8(0xe7, 0xff, 0xff))),
        text("This operation cannot be undone without reinstalling the application.")
            .size(FONT_BODY)
            .font(FONT_UI_REGULAR)
            .style(text_color(Color::from_rgb8(0xff, 0xaa, 0x00))),
    ]
    .spacing(GAP_GROUP);

    let buttons = row![
        button(
            text("Cancel")
                .size(14)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0x05, 0x08, 0x1f)))
        )
        .padding([8, 18])
        .style(style::primary_button())
        .on_press(Message::UninstallCancel),
        button(
            text("Confirm Uninstall")
                .size(14)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0xff, 0x73, 0xff)))
        )
        .padding([8, 18])
        .style(style::danger_button())
        .on_press(Message::UninstallConfirm),
    ]
    .spacing(GAP_SECTION);

    let panel = container(column![warning, buttons].spacing(GAP_SECTION))
        .padding(18)
        .width(Length::Fixed(560.0))
        .style(style::modal_panel());

    container(panel)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(style::overlay_backdrop())
        .into()
}

fn render_recovery_overlay(recovery: &RecoveryOverlay) -> Element<'static, Message> {
    let sanitized: String = recovery
        .secret_hex
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let uppercase = sanitized.to_uppercase();
    let formatted = uppercase
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ");

    let summary = column![
        text("RECOVERY KEY")
            .size(22)
            .font(FONT_UI_BOLD)
            .style(text_color(Color::from_rgb8(0xff, 0xff, 0x73))),
        text("Store this secret securely. It is the only way to recreate the LockChain USB key in the event of hardware loss or failure.")
            .size(FONT_BODY)
            .font(FONT_UI_REGULAR)
            .style(text_color(Color::from_rgb8(0xe7, 0xff, 0xff))),
        text("Treat anyone with access to this recovery key as fully trusted.")
            .size(FONT_BODY)
            .font(FONT_UI_REGULAR)
            .style(text_color(Color::from_rgb8(0xff, 0x55, 0x88))),
        text("Scan the QR code or copy the hex string below before continuing.")
            .size(FONT_BODY)
            .font(FONT_UI_REGULAR)
            .style(text_color(Color::from_rgb8(0xe7, 0xff, 0xff))),
    ]
    .spacing(GAP_GROUP);

    let secret_block: Element<'static, Message> = container(
        text(formatted.clone())
            .size(18)
            .font(FONT_MONO_BOLD)
            .style(text_color(Color::from_rgb8(0x00, 0xff, 0x88))),
    )
    .padding([14, 18])
    .width(Length::Fill)
    .style(style::terminal_line_accent(Color::from_rgb8(
        0x13, 0x1b, 0x32,
    )))
    .into();

    let qr_display = render_recovery_qr(&uppercase);

    let secret_section: Element<'static, Message> = if let Some(qr) = qr_display {
        row![qr, secret_block]
            .spacing(GAP_SECTION)
            .align_y(Vertical::Center)
            .into()
    } else {
        secret_block
    };

    let action_row = row![
        Space::with_width(Length::Fill),
        button(
            text("Accept")
                .size(14)
                .font(FONT_UI_BOLD)
                .style(text_color(Color::from_rgb8(0x05, 0x08, 0x1f)))
        )
        .padding([8, 18])
        .style(style::primary_button())
        .on_press(Message::RecoveryAcknowledge),
    ]
    .spacing(GAP_SECTION)
    .align_y(Vertical::Center);

    let panel = container(column![summary, secret_section, action_row].spacing(GAP_SECTION))
        .padding(22)
        .width(Length::Fixed(520.0))
        .style(style::modal_panel());

    container(panel)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(style::overlay_backdrop())
        .into()
}

fn render_recovery_qr(secret: &str) -> Option<Element<'static, Message>> {
    if secret.is_empty() {
        return None;
    }
    let code = QrCode::encode_text(secret, QrCodeEcc::Medium).ok()?;
    let size = code.size();
    if size <= 0 {
        return None;
    }
    let mut modules = vec![vec![false; size as usize]; size as usize];
    for y in 0..size {
        for x in 0..size {
            modules[y as usize][x as usize] = code.get_module(x, y);
        }
    }
    let canvas = Canvas::new(RecoveryQrCanvas { modules })
        .width(Length::Fixed(220.0))
        .height(Length::Fixed(220.0));
    Some(
        container(canvas)
            .padding(8)
            .style(style::terminal_line_accent(Color::from_rgb8(
                0x0a, 0x12, 0x24,
            )))
            .into(),
    )
}

struct RecoveryQrCanvas {
    modules: Vec<Vec<bool>>,
}

impl canvas::Program<Message> for RecoveryQrCanvas {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let module_count = self.modules.len() as f32;
        if module_count == 0.0 {
            return vec![frame.into_geometry()];
        }

        let quiet_zone = 4.0;
        let total_modules = module_count + quiet_zone * 2.0;
        let scale = (bounds.width.min(bounds.height) / total_modules).max(1.0);
        let usable = scale * total_modules;
        let offset_x = (bounds.width - usable) / 2.0;
        let offset_y = (bounds.height - usable) / 2.0;

        frame.fill_rectangle(
            Point::new(0.0, 0.0),
            frame.size(),
            Color::from_rgb8(0x05, 0x08, 0x1f),
        );

        let dark = Color::from_rgb8(0x00, 0xff, 0x88);

        for (y, row) in self.modules.iter().enumerate() {
            for (x, &module) in row.iter().enumerate() {
                if module {
                    let px = offset_x + scale * (quiet_zone + x as f32);
                    let py = offset_y + scale * (quiet_zone + y as f32);
                    let rect = Path::rectangle(Point::new(px, py), Size::new(scale, scale));
                    frame.fill(&rect, dark);
                }
            }
        }

        vec![frame.into_geometry()]
    }
}

fn render_tooltip_panel<'a>(line1: &'a str, line2: &'a str) -> Element<'a, Message> {
    // Reusable tooltip bubble matching the wireframe helper cards.
    container(
        column![
            text(line1)
                .size(FONT_MICRO)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0x00, 0xff, 0x88))),
            text(line2)
                .size(FONT_MICRO)
                .font(FONT_UI_REGULAR)
                .style(text_color(Color::from_rgb8(0x00, 0xd3, 0xf8))),
        ]
        .spacing(GAP_GROUP.min(6)),
    )
    .padding(10)
    .style(style::tooltip_panel())
    .into()
}

fn text_color(color: Color) -> impl Fn(&Theme) -> iced::widget::text::Style + Copy {
    move |_| iced::widget::text::Style { color: Some(color) }
}
