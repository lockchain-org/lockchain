// SVG helpers for directive icons. Each glyph is recoloured at runtime to
// match availability styling.

use super::DirectiveGlyph;
use iced::widget::svg::Handle as SvgHandle;
use iced::Color;

pub(super) fn directive(glyph: DirectiveGlyph, color: Color) -> SvgHandle {
    match glyph {
        DirectiveGlyph::Key => recolor(include_bytes!("../../assets/icons/key.svg"), color),
        DirectiveGlyph::Shield => {
            recolor(include_bytes!("../../assets/icons/shield-check.svg"), color)
        }
        DirectiveGlyph::Test => recolor(include_bytes!("../../assets/icons/test-tube.svg"), color),
        DirectiveGlyph::Recover => {
            recolor(include_bytes!("../../assets/icons/rotate-ccw.svg"), color)
        }
        DirectiveGlyph::Tune => recolor(include_bytes!("../../assets/icons/wrench.svg"), color),
    }
}

fn recolor(bytes: &'static [u8], color: Color) -> SvgHandle {
    // Lucide icons ship with `stroke="currentColor"`; replace it with the
    // palette-provided hex so we can keep the assets light.
    let hex = format!(
        "#{:02X}{:02X}{:02X}",
        (color.r.clamp(0.0, 1.0) * 255.0).round() as u8,
        (color.g.clamp(0.0, 1.0) * 255.0).round() as u8,
        (color.b.clamp(0.0, 1.0) * 255.0).round() as u8
    );

    let svg = String::from_utf8(bytes.to_vec()).expect("icon svg is valid utf-8");
    let recolored = svg.replace("currentColor", &hex);
    SvgHandle::from_memory(recolored.into_bytes())
}
