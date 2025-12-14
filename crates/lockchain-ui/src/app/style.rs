//! Control Deck colour palette and widget styles.

use iced::border::{Border, Radius};
use iced::widget::button::{Status as ButtonStatus, Style as ButtonStyle};
use iced::widget::container;
use iced::widget::progress_bar;
use iced::widget::text_input::{self, Status as InputStatus};
use iced::{Background, Color, Theme};

pub(super) const BG_SURFACE: Color = Color {
    r: 0.0,
    g: 0.0,
    b: 0.0,
    a: 1.0,
};

// Midnight backdrop for header and primary panels.
const HEADER_BG: Color = Color {
    r: 0x0d as f32 / 255.0,
    g: 0x11 as f32 / 255.0,
    b: 0x17 as f32 / 255.0,
    a: 1.0,
};
// Accent background used for lighter surfaces (e.g. activity footer).
const PANEL_BG_LIGHT: Color = Color {
    r: 0x0d as f32 / 255.0,
    g: 0x11 as f32 / 255.0,
    b: 0x17 as f32 / 255.0,
    a: 1.0,
};
const CYAN: Color = Color {
    r: 0.0,
    g: 0.82,
    b: 1.0,
    a: 1.0,
};
const MAGENTA: Color = Color {
    r: 1.0,
    g: 0.0,
    b: 1.0,
    a: 1.0,
};
const GREEN: Color = Color {
    r: 0.0,
    g: 1.0,
    b: 0.533,
    a: 1.0,
};
const BLUE_DARK: Color = Color {
    r: 0.086,
    g: 0.173,
    b: 0.314,
    a: 1.0,
};
const RED: Color = Color {
    r: 0.89,
    g: 0.125,
    b: 0.298,
    a: 1.0,
};
const SLATE: Color = Color {
    r: 0.102,
    g: 0.122,
    b: 0.227,
    a: 1.0,
};
const SLATE_LIGHT: Color = Color {
    r: 0.18,
    g: 0.2,
    b: 0.329,
    a: 1.0,
};

pub(super) fn background() -> impl Fn(&Theme) -> container::Style + Copy {
    // Base surface for the root container.
    |_| container::Style {
        background: Some(Background::Color(BG_SURFACE)),
        ..Default::default()
    }
}

pub(super) fn header_card() -> impl Fn(&Theme) -> container::Style + Copy {
    // Header shell framing the logo, title, and controls.
    |_| container::Style {
        background: Some(Background::Color(HEADER_BG)),
        border: Border {
            radius: Radius::from(20.0),
            width: 2.0,
            color: CYAN,
        },
        shadow: iced::Shadow {
            color: with_alpha(CYAN, 0.25),
            blur_radius: 14.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(super) fn module_bar_card() -> impl Fn(&Theme) -> container::Style + Copy {
    // Backdrop for the directive hotbar row.
    |_| container::Style {
        background: Some(Background::Color(PANEL_BG_LIGHT)),
        border: Border {
            radius: Radius::from(18.0),
            width: 2.0,
            color: CYAN,
        },
        shadow: iced::Shadow {
            color: with_alpha(CYAN, 0.18),
            blur_radius: 10.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(super) fn terminal_card() -> impl Fn(&Theme) -> container::Style + Copy {
    |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.06, 0.09, 0.21, 0.92))),
        border: Border {
            radius: Radius::from(24.0),
            width: 1.6,
            color: with_alpha(CYAN, 0.55),
        },
        shadow: iced::Shadow {
            color: with_alpha(CYAN, 0.18),
            blur_radius: 22.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(super) fn terminal_surface() -> impl Fn(&Theme) -> container::Style + Copy {
    // Command input shell – slightly lighter than the log area.
    |_| container::Style {
        background: Some(Background::Color(Color::from_rgb8(12, 18, 32))),
        border: Border {
            radius: Radius::from(12.0),
            width: 1.5,
            color: CYAN,
        },
        ..Default::default()
    }
}

pub(super) fn terminal_log() -> impl Fn(&Theme) -> container::Style + Copy {
    // Scrollback/log area of the terminal panel.
    |_| container::Style {
        background: Some(Background::Color(Color::from_rgb8(6, 9, 18))),
        border: Border {
            radius: Radius::from(12.0),
            width: 1.3,
            color: Color::from_rgb8(0x14, 0x3f, 0x5f),
        },
        ..Default::default()
    }
}

pub(super) fn terminal_crt_scanlines() -> impl Fn(&Theme) -> container::Style + Copy {
    // Transparent overlay for the CRT scanline canvas that keeps rounded corners.
    |_| container::Style {
        border: Border {
            radius: Radius::from(12.0),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        ..Default::default()
    }
}

pub(super) fn terminal_crt_glow(intensity: f32) -> impl Fn(&Theme) -> container::Style + Copy {
    let base_alpha = 0.04 + intensity * 0.05;
    let aura_alpha = 0.06 + intensity * 0.06;
    let glow_color = Color::from_rgba(0.02, 0.16, 0.13, base_alpha);
    let aura_color = Color::from_rgba(0.16, 0.86, 0.74, aura_alpha);
    move |_| container::Style {
        background: Some(Background::Color(glow_color)),
        border: Border {
            radius: Radius::from(12.0),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        shadow: iced::Shadow {
            color: with_alpha(aura_color, aura_alpha * 0.45),
            blur_radius: 26.0,
            offset: iced::Vector::new(0.0, 1.0),
        },
        ..Default::default()
    }
}

pub(super) fn terminal_line(even: bool) -> impl Fn(&Theme) -> container::Style + Copy {
    let base = if even {
        Color::from_rgba(0.06, 0.12, 0.26, 0.82)
    } else {
        Color::from_rgba(0.04, 0.10, 0.22, 0.86)
    };
    move |_| container::Style {
        background: Some(Background::Color(base)),
        border: Border {
            radius: Radius::from(8.0),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        ..Default::default()
    }
}

pub(super) fn terminal_line_accent(color: Color) -> impl Fn(&Theme) -> container::Style + Copy {
    move |_| container::Style {
        background: Some(Background::Color(with_alpha(color, 0.95))),
        border: Border {
            radius: Radius::from(3.0),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        ..Default::default()
    }
}

pub(super) fn mission_report_card() -> impl Fn(&Theme) -> container::Style + Copy {
    |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.03, 0.05, 0.12, 0.9))),
        border: Border {
            radius: Radius::from(20.0),
            width: 1.4,
            color: with_alpha(MAGENTA, 0.5),
        },
        shadow: iced::Shadow {
            color: with_alpha(MAGENTA, 0.28),
            blur_radius: 18.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(super) fn mission_progress_shell(
    phase: f32,
    complete: bool,
) -> impl Fn(&Theme) -> container::Style + Copy {
    move |_| {
        if complete {
            container::Style {
                background: Some(Background::Color(Color::from_rgba(0.05, 0.25, 0.16, 0.92))),
                border: Border {
                    radius: Radius::from(12.0),
                    width: 1.6,
                    color: with_alpha(Color::from_rgb8(0x2d, 0xf8, 0x8e), 0.95),
                },
                shadow: iced::Shadow {
                    color: with_alpha(Color::from_rgb8(0x2d, 0xf8, 0x8e), 0.35),
                    blur_radius: 12.0,
                    offset: iced::Vector::new(0.0, 2.0),
                },
                ..Default::default()
            }
        } else {
            let pulse = (phase / 32.0).sin().abs();
            let glow_color = Color::new(1.0, 0.4 + pulse * 0.2, 0.07, 0.94);
            container::Style {
                background: Some(Background::Color(Color::from_rgba(0.45, 0.12, 0.04, 0.9))),
                border: Border {
                    radius: Radius::from(12.0),
                    width: 1.6,
                    color: glow_color,
                },
                shadow: iced::Shadow {
                    color: with_alpha(glow_color, 0.34),
                    blur_radius: 10.0,
                    offset: iced::Vector::new(0.0, 2.0),
                },
                ..Default::default()
            }
        }
    }
}

use super::ProgressState;

pub(super) fn mission_progress_bar(
    phase: f32,
    state: ProgressState,
) -> impl Fn(&Theme) -> progress_bar::Style + Copy {
    move |_| {
        let (background, bar) = match state {
            ProgressState::Idle => (
                Background::Color(Color::from_rgba(0.18, 0.18, 0.28, 0.96)),
                Background::Color(Color::from_rgb8(0x3a, 0x4c, 0x82)),
            ),
            ProgressState::Running => {
                let pulse = (phase / 30.0).sin().abs();
                let base = Color::from_rgba(1.0, 0.46, 0.08, 0.99);
                let accent = Color::from_rgba(1.0, 0.72, 0.18, 1.0);
                (
                    Background::Color(Color::from_rgba(0.50, 0.16, 0.05, 0.97)),
                    Background::Color(Color::new(
                        base.r * (1.0 - pulse) + accent.r * pulse,
                        base.g * (1.0 - pulse) + accent.g * pulse,
                        base.b * (1.0 - pulse) + accent.b * pulse,
                        1.0,
                    )),
                )
            }
            ProgressState::Success => (
                Background::Color(Color::from_rgba(0.08, 0.32, 0.18, 0.97)),
                Background::Color(Color::from_rgb8(0x38, 0xff, 0xa0)),
            ),
            ProgressState::Failed => (
                Background::Color(Color::from_rgba(0.28, 0.05, 0.16, 0.95)),
                Background::Color(Color::from_rgb8(0xff, 0x45, 0x8a)),
            ),
        };

        progress_bar::Style {
            background,
            bar,
            border: Border {
                radius: Radius::from(8.0),
                width: 0.0,
                color: Color::TRANSPARENT,
            },
        }
    }
}

pub(super) fn mission_spinner_pod() -> impl Fn(&Theme) -> container::Style + Copy {
    |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.04, 0.07, 0.16, 0.92))),
        border: Border {
            radius: Radius::from(18.0),
            width: 1.2,
            color: with_alpha(CYAN, 0.5),
        },
        shadow: iced::Shadow {
            color: with_alpha(CYAN, 0.2),
            blur_radius: 14.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(super) fn status_chip(tint: Color) -> impl Fn(&Theme) -> container::Style + Copy {
    move |_theme| container::Style {
        background: Some(Background::Color(with_alpha(tint, 0.18))),
        border: Border {
            radius: Radius::from(12.0),
            width: 1.2,
            color: with_alpha(tint, 0.65),
        },
        shadow: iced::Shadow {
            color: with_alpha(tint, 0.18),
            blur_radius: 10.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(super) fn directive_tile(
    active: bool,
    enabled: bool,
) -> impl Fn(&Theme, ButtonStatus) -> ButtonStyle + Copy {
    // Directive button with neon outline and availability-aware colours.
    move |_theme, status| {
        let background = if matches!(status, ButtonStatus::Pressed) {
            Background::Color(Color::from_rgb8(18, 28, 46))
        } else if active {
            Background::Color(Color::from_rgb8(15, 26, 44))
        } else {
            Background::Color(Color::from_rgb8(11, 19, 34))
        };

        let border_color = if active {
            MAGENTA
        } else if enabled {
            CYAN
        } else {
            Color::from_rgb8(0xff, 0xb3, 0x4d)
        };

        ButtonStyle {
            background: Some(background),
            border: Border {
                radius: Radius::from(16.0),
                width: if active { 2.0 } else { 1.5 },
                color: border_color,
            },
            text_color: Color::from_rgb8(0xe7, 0xff, 0xff),
            ..ButtonStyle::default()
        }
    }
}

pub(super) fn primary_button() -> impl Fn(&Theme, ButtonStatus) -> ButtonStyle + Copy {
    // Shared cyan button treatment (settings, etc.).
    move |_theme, status| {
        let base = CYAN;
        let background = if matches!(status, ButtonStatus::Pressed) {
            with_alpha(base, 0.82)
        } else {
            base
        };
        ButtonStyle {
            background: Some(Background::Color(background)),
            border: Border {
                radius: Radius::from(10.0),
                width: 1.2,
                color: CYAN,
            },
            text_color: Color::from_rgb8(0x05, 0x08, 0x1f),
            ..ButtonStyle::default()
        }
    }
}

pub(super) fn execute_button(enabled: bool) -> impl Fn(&Theme, ButtonStatus) -> ButtonStyle + Copy {
    // Execute button stays green to mirror the CLI success colorway.
    move |_theme, status| {
        if !enabled {
            ButtonStyle {
                background: Some(Background::Color(SLATE)),
                border: Border {
                    radius: Radius::from(10.0),
                    width: 1.0,
                    color: SLATE_LIGHT,
                },
                text_color: Color::from_rgb8(0x55, 0x66, 0x88),
                ..ButtonStyle::default()
            }
        } else {
            let background = if matches!(status, ButtonStatus::Pressed) {
                Color::from_rgb8(0x19, 0x9a, 0x4e)
            } else {
                GREEN
            };
            ButtonStyle {
                background: Some(Background::Color(background)),
                border: Border {
                    radius: Radius::from(10.0),
                    width: 1.0,
                    color: GREEN,
                },
                text_color: Color::from_rgb8(0x05, 0x08, 0x1f),
                ..ButtonStyle::default()
            }
        }
    }
}

pub(super) fn help_button() -> impl Fn(&Theme, ButtonStatus) -> ButtonStyle + Copy {
    // Help button uses the cooler blue accent.
    move |_theme, status| {
        let background = if matches!(status, ButtonStatus::Pressed) {
            Color::from_rgb8(20, 35, 62)
        } else {
            BLUE_DARK
        };
        ButtonStyle {
            background: Some(Background::Color(background)),
            border: Border {
                radius: Radius::from(10.0),
                width: 1.0,
                color: BLUE_DARK,
            },
            text_color: Color::from_rgb8(0xe7, 0xff, 0xff),
            ..ButtonStyle::default()
        }
    }
}

pub(super) fn clear_button() -> impl Fn(&Theme, ButtonStatus) -> ButtonStyle + Copy {
    // Clear button borrows the magenta accent but keeps it subdued.
    move |_theme, status| {
        let background = if matches!(status, ButtonStatus::Pressed) {
            Color::from_rgb8(0x39, 0x17, 0x3f)
        } else {
            Color::from_rgb8(0x2b, 0x11, 0x33)
        };
        ButtonStyle {
            background: Some(Background::Color(background)),
            border: Border {
                radius: Radius::from(10.0),
                width: 1.0,
                color: Color::from_rgb8(0x66, 0x1f, 0x7a),
            },
            text_color: Color::from_rgb8(0xff, 0xe6, 0xf6),
            ..ButtonStyle::default()
        }
    }
}

pub(super) fn danger_button() -> impl Fn(&Theme, ButtonStatus) -> ButtonStyle + Copy {
    // Destructive actions (uninstall, discard) expressed in neon magenta/red.
    move |_theme, status| {
        let background = if matches!(status, ButtonStatus::Pressed) {
            Color::from_rgb8(0x6c, 0x16, 0x35)
        } else {
            RED
        };
        ButtonStyle {
            background: Some(Background::Color(background)),
            border: Border {
                radius: Radius::from(10.0),
                width: 1.0,
                color: RED,
            },
            text_color: Color::from_rgb8(0xff, 0xe6, 0xf6),
            ..ButtonStyle::default()
        }
    }
}

pub(super) fn text_input() -> impl Fn(&Theme, InputStatus) -> text_input::Style + Copy {
    // Terminal input field – darker fill with cyan focus border.
    move |_theme, status| {
        let border_color = match status {
            InputStatus::Focused => CYAN,
            _ => Color::from_rgb8(0x3a, 0x45, 0x7d),
        };
        text_input::Style {
            background: Background::Color(Color::from_rgb8(10, 15, 26)),
            border: Border {
                radius: Radius::from(10.0),
                width: 1.2,
                color: border_color,
            },
            icon: Color::WHITE,
            placeholder: with_alpha(CYAN, 0.8),
            value: Color::from_rgb8(0xf1, 0xff, 0xff),
            selection: CYAN,
        }
    }
}

pub(super) fn tooltip_panel() -> impl Fn(&Theme) -> container::Style + Copy {
    // Shared tooltip styling for directive hints and form help.
    |_| container::Style {
        background: Some(Background::Color(PANEL_BG_LIGHT)),
        border: Border {
            radius: Radius::from(12.0),
            width: 1.0,
            color: CYAN,
        },
        ..Default::default()
    }
}

pub(super) fn overlay_backdrop() -> impl Fn(&Theme) -> container::Style + Copy {
    // Dimmed backdrop used while a modal is displayed.
    |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.55))),
        ..Default::default()
    }
}

pub(super) fn modal_panel() -> impl Fn(&Theme) -> container::Style + Copy {
    // Foreground panel for settings and uninstall overlays.
    |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.05, 0.08, 0.22, 0.98))),
        border: Border {
            radius: Radius::from(20.0),
            width: 1.5,
            color: CYAN,
        },
        shadow: iced::Shadow {
            color: with_alpha(CYAN, 0.22),
            blur_radius: 12.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn with_alpha(mut color: Color, alpha: f32) -> Color {
    color.a = alpha;
    color
}
