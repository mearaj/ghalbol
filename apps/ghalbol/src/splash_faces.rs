//! Shared Splash faces registered on `mod.widgets` for the app UI script_mod.

use makepad_widgets::*;

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*


    // Multi-script UI fonts: Makepad falls through FontFamily members when a
    // glyph is missing. Cover Indian scheduled scripts + major world scripts.
    // CJK (zh/ja/ko) comes from Makepad's LXGW WenKai; emoji from Noto Color.
    mod.widgets.WorldFonts = set_type_default() do FontFamily{
        latin := FontMember{res: crate_resource("self:resources/fonts/NotoSans-Regular.ttf") asc: -0.1 desc: 0.0}
        devanagari := FontMember{res: crate_resource("self:resources/fonts/NotoSansDevanagari-Regular.ttf") asc: 0.0 desc: 0.0}
        bengali := FontMember{res: crate_resource("self:resources/fonts/NotoSansBengali-Regular.ttf") asc: 0.0 desc: 0.0}
        tamil := FontMember{res: crate_resource("self:resources/fonts/NotoSansTamil-Regular.ttf") asc: 0.0 desc: 0.0}
        telugu := FontMember{res: crate_resource("self:resources/fonts/NotoSansTelugu-Regular.ttf") asc: 0.0 desc: 0.0}
        gujarati := FontMember{res: crate_resource("self:resources/fonts/NotoSansGujarati-Regular.ttf") asc: 0.0 desc: 0.0}
        kannada := FontMember{res: crate_resource("self:resources/fonts/NotoSansKannada-Regular.ttf") asc: 0.0 desc: 0.0}
        malayalam := FontMember{res: crate_resource("self:resources/fonts/NotoSansMalayalam-Regular.ttf") asc: 0.0 desc: 0.0}
        gurmukhi := FontMember{res: crate_resource("self:resources/fonts/NotoSansGurmukhi-Regular.ttf") asc: 0.0 desc: 0.0}
        odia := FontMember{res: crate_resource("self:resources/fonts/NotoSansOriya-Regular.ttf") asc: 0.0 desc: 0.0}
        arabic := FontMember{res: crate_resource("self:resources/fonts/NotoSansArabic-Regular.ttf") asc: 0.0 desc: 0.0}
        hebrew := FontMember{res: crate_resource("self:resources/fonts/NotoSansHebrew-Regular.ttf") asc: 0.0 desc: 0.0}
        thai := FontMember{res: crate_resource("self:resources/fonts/NotoSansThai-Regular.ttf") asc: 0.0 desc: 0.0}
        sinhala := FontMember{res: crate_resource("self:resources/fonts/NotoSansSinhala-Regular.ttf") asc: 0.0 desc: 0.0}
        myanmar := FontMember{res: crate_resource("self:resources/fonts/NotoSansMyanmar-Regular.ttf") asc: 0.0 desc: 0.0}
        khmer := FontMember{res: crate_resource("self:resources/fonts/NotoSansKhmer-Regular.ttf") asc: 0.0 desc: 0.0}
        lao := FontMember{res: crate_resource("self:resources/fonts/NotoSansLao-Regular.ttf") asc: 0.0 desc: 0.0}
        tibetan := FontMember{res: crate_resource("self:resources/fonts/NotoSansTibetan-Regular.ttf") asc: 0.0 desc: 0.0}
        ethiopic := FontMember{res: crate_resource("self:resources/fonts/NotoSansEthiopic-Regular.ttf") asc: 0.0 desc: 0.0}
        thaana := FontMember{res: crate_resource("self:resources/fonts/NotoSansThaana-Regular.ttf") asc: 0.0 desc: 0.0}
        georgian := FontMember{res: crate_resource("self:resources/fonts/NotoSansGeorgian-Regular.ttf") asc: 0.0 desc: 0.0}
        armenian := FontMember{res: crate_resource("self:resources/fonts/NotoSansArmenian-Regular.ttf") asc: 0.0 desc: 0.0}
        meetei := FontMember{res: crate_resource("self:resources/fonts/NotoSansMeeteiMayek-Regular.ttf") asc: 0.0 desc: 0.0}
        olchiki := FontMember{res: crate_resource("self:resources/fonts/NotoSansOlChiki-Regular.ttf") asc: 0.0 desc: 0.0}
        chinese := FontMember{res: crate_resource("makepad_widgets:resources/LXGWWenKaiRegular.ttf") asc: 0.0 desc: 0.0}
        // Packaged via International + font_assets (not self: copy — that was
        // missing from the APK and made every toolbar glyph a box).
        icons := FontMember{res: crate_resource("makepad_widgets:resources/fa-solid-900.ttf") asc: 0.0 desc: 0.0}
        emoji := FontMember{res: crate_resource("makepad_widgets:resources/NotoColorEmoji.ttf") asc: 0.0 desc: 0.0}
    }
    mod.widgets.WorldFontsBold = set_type_default() do FontFamily{
        latin := FontMember{res: crate_resource("self:resources/fonts/NotoSans-Regular.ttf") asc: -0.1 desc: 0.0}
        devanagari := FontMember{res: crate_resource("self:resources/fonts/NotoSansDevanagari-Regular.ttf") asc: 0.0 desc: 0.0}
        bengali := FontMember{res: crate_resource("self:resources/fonts/NotoSansBengali-Regular.ttf") asc: 0.0 desc: 0.0}
        tamil := FontMember{res: crate_resource("self:resources/fonts/NotoSansTamil-Regular.ttf") asc: 0.0 desc: 0.0}
        telugu := FontMember{res: crate_resource("self:resources/fonts/NotoSansTelugu-Regular.ttf") asc: 0.0 desc: 0.0}
        gujarati := FontMember{res: crate_resource("self:resources/fonts/NotoSansGujarati-Regular.ttf") asc: 0.0 desc: 0.0}
        kannada := FontMember{res: crate_resource("self:resources/fonts/NotoSansKannada-Regular.ttf") asc: 0.0 desc: 0.0}
        malayalam := FontMember{res: crate_resource("self:resources/fonts/NotoSansMalayalam-Regular.ttf") asc: 0.0 desc: 0.0}
        gurmukhi := FontMember{res: crate_resource("self:resources/fonts/NotoSansGurmukhi-Regular.ttf") asc: 0.0 desc: 0.0}
        odia := FontMember{res: crate_resource("self:resources/fonts/NotoSansOriya-Regular.ttf") asc: 0.0 desc: 0.0}
        arabic := FontMember{res: crate_resource("self:resources/fonts/NotoSansArabic-Regular.ttf") asc: 0.0 desc: 0.0}
        hebrew := FontMember{res: crate_resource("self:resources/fonts/NotoSansHebrew-Regular.ttf") asc: 0.0 desc: 0.0}
        thai := FontMember{res: crate_resource("self:resources/fonts/NotoSansThai-Regular.ttf") asc: 0.0 desc: 0.0}
        sinhala := FontMember{res: crate_resource("self:resources/fonts/NotoSansSinhala-Regular.ttf") asc: 0.0 desc: 0.0}
        myanmar := FontMember{res: crate_resource("self:resources/fonts/NotoSansMyanmar-Regular.ttf") asc: 0.0 desc: 0.0}
        khmer := FontMember{res: crate_resource("self:resources/fonts/NotoSansKhmer-Regular.ttf") asc: 0.0 desc: 0.0}
        lao := FontMember{res: crate_resource("self:resources/fonts/NotoSansLao-Regular.ttf") asc: 0.0 desc: 0.0}
        tibetan := FontMember{res: crate_resource("self:resources/fonts/NotoSansTibetan-Regular.ttf") asc: 0.0 desc: 0.0}
        ethiopic := FontMember{res: crate_resource("self:resources/fonts/NotoSansEthiopic-Regular.ttf") asc: 0.0 desc: 0.0}
        thaana := FontMember{res: crate_resource("self:resources/fonts/NotoSansThaana-Regular.ttf") asc: 0.0 desc: 0.0}
        georgian := FontMember{res: crate_resource("self:resources/fonts/NotoSansGeorgian-Regular.ttf") asc: 0.0 desc: 0.0}
        armenian := FontMember{res: crate_resource("self:resources/fonts/NotoSansArmenian-Regular.ttf") asc: 0.0 desc: 0.0}
        meetei := FontMember{res: crate_resource("self:resources/fonts/NotoSansMeeteiMayek-Regular.ttf") asc: 0.0 desc: 0.0}
        olchiki := FontMember{res: crate_resource("self:resources/fonts/NotoSansOlChiki-Regular.ttf") asc: 0.0 desc: 0.0}
        chinese := FontMember{res: crate_resource("makepad_widgets:resources/LXGWWenKaiBold.ttf") asc: 0.0 desc: 0.0}
        icons := FontMember{res: crate_resource("makepad_widgets:resources/fa-solid-900.ttf") asc: 0.0 desc: 0.0}
        emoji := FontMember{res: crate_resource("makepad_widgets:resources/NotoColorEmoji.ttf") asc: 0.0 desc: 0.0}
    }
    mod.theme.font_regular.font_family = WorldFonts
    mod.theme.font_label.font_family = WorldFonts
    mod.theme.font_bold.font_family = WorldFontsBold
    mod.theme.font_italic.font_family = WorldFonts
    mod.theme.font_bold_italic.font_family = WorldFontsBold
    // Widget classes copy the theme face when they are defined, which is
    // before this script runs. Point the classes themselves at WorldFonts
    // so every label, button, and field falls through to the script fonts.
    mod.widgets.Label.draw_text.text_style.font_family = WorldFonts
    mod.widgets.Button.draw_text.text_style.font_family = WorldFonts
    mod.widgets.TextInput.draw_text.text_style.font_family = WorldFonts

    let state = mod.state

    // Intent → face (same job → same look). Quiet/Go/Stop keep legacy names as
    // aliases for secondary / submit-primary / destroy so call sites stay stable.
    // Never promote a navigate/hub jump to filled primary — use HubDestBtn / MenuRow.
    // Palette: cool shell + electric blue CTAs + navy chrome (from app_icon.png).
    mod.widgets.Quiet = set_type_default() do Button{
        width: Fit
        height: Fit
        padding: Inset{left: 20. right: 20. top: 14. bottom: 14.}
        margin: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        align: Center
        label_walk: Walk{width: Fit, height: Fit, margin: Inset{left: 2. right: 2. top: 0. bottom: 0.}}
        grab_key_focus: false
        reset_hover_on_click: true
        draw_bg.border_size: 1.0
        draw_bg.border_radius: 10.0
        draw_bg.color: #FFFFFF
        draw_bg.color_hover: #DCE4F0
        draw_bg.color_down: #C5D0DE
        draw_bg.color_focus: #FFFFFF
        draw_bg.border_color: #C5D0DE
        draw_bg.border_color_hover: #C5D0DE
        draw_bg.border_color_down: #C5D0DE
        draw_bg.border_color_focus: #0183FB
        draw_text.color: #0B1220
        draw_text.color_hover: #0B1220
        draw_text.color_down: #0B1220
        draw_text.color_focus: #0B1220
        draw_text.text_style.font_size: 13
    }
    mod.widgets.Go = set_type_default() do Button{
        width: Fit
        height: Fit
        padding: Inset{left: 22. right: 22. top: 14. bottom: 14.}
        margin: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        align: Center
        label_walk: Walk{width: Fit, height: Fit, margin: Inset{left: 2. right: 2. top: 0. bottom: 0.}}
        grab_key_focus: false
        reset_hover_on_click: true
        draw_bg.border_size: 1.0
        draw_bg.border_radius: 10.0
        draw_bg.color: #0183FB
        draw_bg.color_hover: #0170D8
        draw_bg.color_down: #015CB5
        draw_bg.color_focus: #0183FB
        draw_bg.border_color: #015CB5
        draw_bg.border_color_hover: #015CB5
        draw_bg.border_color_down: #015CB5
        draw_bg.border_color_focus: #015CB5
        draw_text.color: #FFFFFF
        draw_text.color_hover: #FFFFFF
        draw_text.color_down: #FFFFFF
        draw_text.color_focus: #FFFFFF
        draw_text.text_style.font_size: 13
    }
    mod.widgets.Stop = set_type_default() do Button{
        width: Fit
        height: Fit
        padding: Inset{left: 20. right: 20. top: 14. bottom: 14.}
        margin: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        align: Center
        label_walk: Walk{width: Fit, height: Fit, margin: Inset{left: 2. right: 2. top: 0. bottom: 0.}}
        grab_key_focus: false
        reset_hover_on_click: true
        draw_bg.border_size: 1.0
        draw_bg.border_radius: 10.0
        draw_bg.color: #FFFFFF
        draw_bg.color_hover: #FDECEA
        draw_bg.color_down: #F8D7D4
        draw_bg.color_focus: #FFFFFF
        draw_bg.border_color: #E8B4B0
        draw_bg.border_color_hover: #E8B4B0
        draw_bg.border_color_down: #E8B4B0
        draw_bg.border_color_focus: #C62828
        draw_text.color: #C62828
        draw_text.color_hover: #C62828
        draw_text.color_down: #C62828
        draw_text.color_focus: #C62828
        draw_text.text_style.font_size: 13
    }
    // Full-width multi-word CTAs — wrap + center; never Chip/ellipsis.
    mod.widgets.StackPrimaryBtn = set_type_default() do Go{
        width: Fill
        height: Fit
        flow: Right{wrap: true}
        align: Align{x: 0.5 y: 0.5}
        label_walk: Walk{width: Fit, height: Fit, margin: Inset{left: 4. right: 4. top: 0. bottom: 0.}}
        draw_text.max_lines: 4
        draw_text.text_overflow: Clip
    }
    mod.widgets.StackSecondaryBtn = set_type_default() do Quiet{
        width: Fill
        height: Fit
        flow: Right{wrap: true}
        align: Align{x: 0.5 y: 0.5}
        label_walk: Walk{width: Fit, height: Fit, margin: Inset{left: 4. right: 4. top: 0. bottom: 0.}}
        draw_text.max_lines: 4
        draw_text.text_overflow: Clip
    }
    mod.widgets.ActionStack = set_type_default() do View{
        width: Fill
        height: Fit
        flow: Down
        spacing: 10
    }
    // Navigate elsewhere (hub destination) — never filled primary.
    mod.widgets.HubDestBtn = set_type_default() do Quiet{
        width: Fill
        height: Fit
        padding: Inset{left: 20. right: 20. top: 16. bottom: 16.}
        margin: Inset{left: 0. right: 0. top: 4. bottom: 4.}
        align: Align{x: 0 y: 0.5}
        label_walk: Walk{width: Fill, height: Fit, margin: Inset{left: 2. right: 2. top: 0. bottom: 0.}}
        draw_text.max_lines: 3
        draw_text.text_overflow: Ellipsis
        draw_text.text_style.font_size: 14
    }
    mod.widgets.Field = set_type_default() do TextInput{
        width: Fill
        height: Fit
        padding: Inset{left: 16. right: 16. top: 14. bottom: 14.}
        margin: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        draw_bg.border_size: 1.0
        draw_bg.border_radius: 22.0
        draw_bg.color: #FFFFFF
        draw_bg.color_hover: #FFFFFF
        draw_bg.color_focus: #FFFFFF
        draw_bg.color_down: #FFFFFF
        draw_bg.color_empty: #FFFFFF
        draw_bg.border_color: #C5D0DE
        draw_bg.border_color_hover: #8A9BB0
        draw_bg.border_color_focus: #0183FB
        draw_bg.border_color_down: #0183FB
        draw_bg.border_color_empty: #C5D0DE
        draw_text.color: #0B1220
        draw_text.color_hover: #0B1220
        draw_text.color_focus: #0B1220
        draw_text.color_down: #0B1220
        draw_text.color_empty: #7A8B9C
        draw_text.color_empty_hover: #7A8B9C
        draw_text.color_empty_focus: #7A8B9C
        draw_text.text_style.font_size: 15
        // Theme default caret is white — invisible on our white fields.
        draw_cursor.color: #0B1220
        // Selection is drawn *over* glyphs — keep alpha so ink stays readable.
        draw_selection.color: #0183FB40
        draw_selection.color_hover: #0183FB55
        draw_selection.color_focus: #0183FB55
        draw_selection.color_down: #0183FB66
        blink_speed: 0.5
    }
    // Square Font Awesome toolbar control (WorldFonts falls through to FA).
    // grab_key_focus false — tapping next to the composer must not steal IME
    // focus (Android otherwise dismisses the keyboard mid-tap and drops the click).
    mod.widgets.IconBtn = set_type_default() do Quiet{
        width: 44
        height: 44
        padding: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        margin: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        align: Center
        grab_key_focus: false
        draw_bg.border_radius: 22.0
        draw_text.text_style.font_size: 18
        draw_text.text_style.font_family: WorldFonts
    }
    mod.widgets.IconGo = set_type_default() do Go{
        width: 44
        height: 44
        padding: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        margin: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        align: Center
        grab_key_focus: false
        draw_bg.border_radius: 22.0
        draw_text.text_style.font_size: 18
        draw_text.text_style.font_family: WorldFonts
    }
    // Read-only selectable body text — Makepad Label is not selectable.
    // Looks like a Label; drag to select / copy. Override draw_text.color as needed.
    // empty_text must be "" — theme default is "Your text here".
    mod.widgets.Selectable = set_type_default() do TextInput{
        width: Fill
        height: Fit
        is_read_only: true
        is_multiline: true
        empty_text: ""
        flow: Right{wrap: true}
        padding: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        margin: Inset{left: 0. right: 0. top: 0. bottom: 0.}
        draw_bg.border_size: 0.0
        draw_bg.border_radius: 0.0
        draw_bg.color: #00000000
        draw_bg.color_hover: #00000000
        draw_bg.color_focus: #00000000
        draw_bg.color_down: #00000000
        draw_bg.color_empty: #00000000
        draw_bg.border_color: #00000000
        draw_bg.border_color_hover: #00000000
        draw_bg.border_color_focus: #00000000
        draw_bg.border_color_down: #00000000
        draw_bg.border_color_empty: #00000000
        draw_text.color: #0B1220
        draw_text.color_hover: #0B1220
        draw_text.color_focus: #0B1220
        draw_text.color_down: #0B1220
        draw_text.color_empty: #0B1220
        draw_text.color_empty_hover: #0B1220
        draw_text.color_empty_focus: #0B1220
        draw_text.text_style.font_size: 14
        draw_cursor.color: #00000000
        // Selection is drawn *over* glyphs — keep alpha so ink stays readable.
        draw_selection.color: #0183FB40
        draw_selection.color_hover: #0183FB55
        draw_selection.color_focus: #0183FB55
        draw_selection.color_down: #0183FB66
        blink_speed: 0.0
    }
    // Chat text bubble — Label in a rounded box. Deliberately NOT a TextInput:
    // a read-only TextInput takes key focus on the finger-down that starts a
    // scroll, which yanked focus (and the soft keyboard) off the composer and
    // left stray selections on bubbles. Use Bubble (button) for media rows.
    // Flutter: chip is content-sized (max ~280), not a full-width slab. Row
    // padding below provides the opposite-side gutter (out=left, in=right).
    // Labels only — never Selectable/TextInput (those steal IME focus from the composer).
    mod.widgets.TextBubble = set_type_default() do RoundedView{
        width: Fit{max: FitBound.Abs(280)}
        height: Fit
        flow: Down
        spacing: 4
        padding: Inset{left: 12. right: 12. top: 8. bottom: 6.}
        margin: Inset{left: 0. right: 0. top: 2. bottom: 2.}
        draw_bg.border_size: 0.0
        draw_bg.border_radius: 12.0
        draw_bg.color: #FFFFFF
        body := Label{
            width: Fit{max: FitBound.Abs(256)}
            text: ""
            draw_text.color: #0B1220
            draw_text.text_style.font_size: 15
            draw_text.max_lines: 48
            draw_text.text_overflow: Ellipsis
        }
        meta := View{
            width: Fit
            height: Fit
            flow: Right
            spacing: 4
            align: Align{y: 0.5}
            caption := Label{
                width: Fit
                text: ""
                draw_text.color: #7A8B9C
                draw_text.text_style.font_size: 11
                draw_text.max_lines: 1
                draw_text.text_overflow: Ellipsis
            }
            // Ticks use FA PUA: check + check-double are single glyphs. NotoSans
            // has no ✓, so "✓✓" fell through to two wide FA checks with a gap.
            tick := Label{
                width: Fit
                text: ""
                draw_text.color: #7A8B9C
                draw_text.text_style.font_size: 12
                draw_text.text_style.font_family: WorldFonts
            }
        }
    }
    mod.widgets.Panel = set_type_default() do SolidView{
        show_bg: true
        draw_bg.color: #FFFFFF
        width: Fill
        height: Fill
    }
    mod.widgets.Bar = set_type_default() do SolidView{
        show_bg: true
        draw_bg.color: #EEF2F8
        width: Fill
        height: Fit
        flow: Right
        spacing: 10
        padding: Inset{left: 14. right: 14. top: 12. bottom: 12.}
        align: Align{y: 0.5}
    }
    // Side-rail peer — idle face. Selection is Overlay idle+active (Makepad Button
    // has no selected bit). Idle must NOT reuse active fill on hover/focus.
    mod.widgets.RailTab = set_type_default() do Button{
        width: Fill
        height: Fit
        padding: Inset{left: 40. right: 12. top: 12. bottom: 12.}
        align: Align{x: 0.0 y: 0.5}
        flow: Right{wrap: true}
        grab_key_focus: false
        reset_hover_on_click: true
        label_walk: Walk{width: Fill, height: Fit, margin: Inset{left: 0. right: 4.}}
        label_align: Align{x: 0.0 y: 0.5}
        icon_walk: Walk{width: 0. height: 0.}
        draw_bg.border_size: 0.0
        draw_bg.border_radius: 12.0
        draw_bg.color: #00000000
        draw_bg.color_hover: #DCE4F0
        draw_bg.color_down: #C5D0DE
        draw_bg.color_focus: #00000000
        draw_bg.border_color: #00000000
        draw_text.color: #5A6B7D
        draw_text.color_hover: #0B1220
        draw_text.color_down: #0B1220
        draw_text.color_focus: #5A6B7D
        draw_text.max_lines: 2
        draw_text.text_overflow: Ellipsis
        draw_text.text_style.font_size: 13
    }
    mod.widgets.RailTabOn = set_type_default() do Button{
        width: Fill
        height: Fit
        padding: Inset{left: 40. right: 12. top: 12. bottom: 12.}
        align: Align{x: 0.0 y: 0.5}
        flow: Right{wrap: true}
        grab_key_focus: false
        reset_hover_on_click: true
        label_walk: Walk{width: Fill, height: Fit, margin: Inset{left: 0. right: 4.}}
        label_align: Align{x: 0.0 y: 0.5}
        icon_walk: Walk{width: 0. height: 0.}
        draw_bg.border_size: 0.0
        draw_bg.border_radius: 12.0
        draw_bg.color: #10236D
        draw_bg.color_hover: #10236D
        draw_bg.color_down: #0C1C55
        draw_bg.color_focus: #10236D
        draw_bg.border_color: #10236D
        draw_text.color: #FFFFFF
        draw_text.color_hover: #FFFFFF
        draw_text.color_down: #FFFFFF
        draw_text.color_focus: #FFFFFF
        draw_text.max_lines: 2
        draw_text.text_overflow: Ellipsis
        draw_text.text_style.font_size: 13
    }
    // Phone bottom peers (<720) — scrollable chips; same idle/active Overlay rule.
    mod.widgets.NavChip = set_type_default() do Button{
        width: Fit{min: FitBound.Abs(88.)}
        height: 56
        padding: Inset{left: 36. right: 12. top: 8. bottom: 8.}
        align: Align{x: 0.0 y: 0.5}
        grab_key_focus: false
        reset_hover_on_click: true
        label_walk: Walk{width: Fit, height: Fit, margin: Inset{left: 0. right: 2.}}
        icon_walk: Walk{width: 0. height: 0.}
        draw_bg.border_size: 0.0
        draw_bg.border_radius: 12.0
        draw_bg.color: #00000000
        draw_bg.color_hover: #DCE4F0
        draw_bg.color_down: #C5D0DE
        draw_bg.color_focus: #00000000
        draw_bg.border_color: #00000000
        draw_text.color: #5A6B7D
        draw_text.color_hover: #0B1220
        draw_text.color_down: #0B1220
        draw_text.color_focus: #5A6B7D
        draw_text.text_style.font_size: 12
    }
    mod.widgets.NavChipOn = set_type_default() do Button{
        width: Fit{min: FitBound.Abs(88.)}
        height: 56
        padding: Inset{left: 36. right: 12. top: 8. bottom: 8.}
        align: Align{x: 0.0 y: 0.5}
        grab_key_focus: false
        reset_hover_on_click: true
        label_walk: Walk{width: Fit, height: Fit, margin: Inset{left: 0. right: 2.}}
        icon_walk: Walk{width: 0. height: 0.}
        draw_bg.border_size: 0.0
        draw_bg.border_radius: 12.0
        draw_bg.color: #10236D
        draw_bg.color_hover: #10236D
        draw_bg.color_down: #0C1C55
        draw_bg.color_focus: #10236D
        draw_bg.border_color: #10236D
        draw_text.color: #FFFFFF
        draw_text.color_hover: #FFFFFF
        draw_text.color_down: #FFFFFF
        draw_text.color_focus: #FFFFFF
        draw_text.text_style.font_size: 12
    }
    mod.widgets.NavMark = set_type_default() do Image{
        width: 22
        height: 22
        margin: Inset{left: 10. right: 0. top: 0. bottom: 0.}
    }
    // Hub roster row (Flutter `chat_hub_screen` chrome): avatar initial, title,
    // availability, preview, right-side "Unknown" chip + unread count badge.
    // No cursor / Button children — `roster_list.on_item_tap` owns the press so a
    // vertical drag scrolls the list and a plain tap opens the room (native feel).
    mod.widgets.RosterRow = set_type_default() do RoundedView{
        width: Fill
        height: Fit
        flow: Right
        spacing: 12
        padding: Inset{left: 12. right: 12. top: 10. bottom: 10.}
        align: Align{y: 0.5}
        draw_bg.border_radius: 10.0
        draw_bg.border_size: 0.0
        draw_bg.color: #FFFFFF
        avatar := RoundedView{
            width: 44
            height: 44
            align: Center
            draw_bg.border_radius: 22.0
            draw_bg.border_size: 0.0
            draw_bg.color: #D6E8FF
            initial := Label{
                text: "?"
                draw_text.color: #0183FB
                draw_text.text_style.font_size: 17
            }
        }
        body := View{
            width: Fill
            height: Fit
            flow: Down
            spacing: 2
            title := Label{
                width: Fill
                text: ""
                draw_text.color: #0B1220
                draw_text.text_style.font_size: 15
                draw_text.max_lines: 1
                draw_text.text_overflow: Ellipsis
            }
            status := Label{
                width: Fill
                text: ""
                draw_text.color: #0183FB
                draw_text.text_style.font_size: 12
                draw_text.max_lines: 1
                draw_text.text_overflow: Ellipsis
            }
            preview := Label{
                width: Fill
                text: ""
                draw_text.color: #7A8B9C
                draw_text.text_style.font_size: 13
                draw_text.max_lines: 1
                draw_text.text_overflow: Ellipsis
            }
        }
        side := View{
            width: Fit
            height: Fit
            flow: Down
            spacing: 6
            align: Align{x: 1.0}
            chip := RoundedView{
                width: Fit
                height: Fit
                padding: Inset{left: 8. right: 8. top: 3. bottom: 3.}
                draw_bg.border_radius: 8.0
                draw_bg.border_size: 1.0
                draw_bg.border_color: #F0C27B
                draw_bg.color: #FFF3DC
                Label{
                    text: "Unknown"
                    draw_text.color: #8A5A00
                    draw_text.text_style.font_size: 11
                }
            }
            badge := RoundedView{
                width: Fit
                height: Fit
                padding: Inset{left: 7. right: 7. top: 2. bottom: 2.}
                draw_bg.border_radius: 10.0
                draw_bg.border_size: 0.0
                draw_bg.color: #0183FB
                count := Label{
                    text: ""
                    draw_text.color: #FFFFFF
                    draw_text.text_style.font_size: 11
                }
            }
        }
    }
    mod.widgets.MenuRow = set_type_default() do Quiet{
        width: Fill
        height: Fit
        padding: Inset{left: 20. right: 20. top: 16. bottom: 16.}
        margin: Inset{left: 0. right: 0. top: 4. bottom: 4.}
        align: Align{x: 0 y: 0.5}
        label_walk: Walk{width: Fill, height: Fit}
        draw_text.max_lines: 3
        draw_text.text_overflow: Ellipsis
        draw_text.text_style.font_size: 14
    }
    mod.widgets.Bubble = set_type_default() do Quiet{
        width: Fit{max: FitBound.Abs(280)}
        height: Fit
        // Tapping a media row must not pull key focus (and the IME) off the composer.
        grab_key_focus: false
        padding: Inset{left: 16. right: 16. top: 12. bottom: 12.}
        margin: Inset{left: 0. right: 0. top: 2. bottom: 2.}
        align: Align{x: 0 y: 0.5}
        label_walk: Walk{width: Fit, height: Fit}
        draw_text.max_lines: 40
        draw_text.text_overflow: Ellipsis
        draw_bg.border_radius: 12.0
        draw_text.text_style.font_size: 14
    }
    // Vertical body scroller — sibling of fixed chrome (bars/composer), never wraps them.
    mod.widgets.VScroll = set_type_default() do ScrollYView{
        width: Fill
        height: Fill
        flow: Down
        scroll_bars: ScrollBars{
            show_scroll_x: false
            show_scroll_y: true
            scroll_bar_y.drag_scrolling: true
        }
    }
    // Horizontal toolbar scroller. Strip must be clearly taller than the chips
    // so Android has empty band above/below to pan. See MAKEPAD_UI.md § Scrolling.
    mod.widgets.HScroll = set_type_default() do ScrollXView{
        width: Fill
        height: 96
        flow: Right
        spacing: 10
        padding: Inset{left: 10. right: 10. top: 20. bottom: 20.}
        align: Align{y: 0.5}
        scroll_bars: ScrollBars{
            show_scroll_x: true
            show_scroll_y: false
            scroll_bar_x.drag_scrolling: true
            scroll_bar_x.use_vertical_finger_scroll: true
        }
    }
    // Hub action strip — tall finger band; title above stays compact (no HScroll).
    mod.widgets.ActionBar = set_type_default() do ScrollXView{
        show_bg: true
        draw_bg.color: #EEF2F8
        width: Fill
        height: 96
        flow: Right
        spacing: 10
        padding: Inset{left: 12. right: 12. top: 20. bottom: 20.}
        align: Align{y: 0.5}
        scroll_bars: ScrollBars{
            show_scroll_x: true
            show_scroll_y: false
            scroll_bar_x.drag_scrolling: true
            scroll_bar_x.use_vertical_finger_scroll: true
        }
    }
    // Compact toolbar chip — shorter than ActionBar/HScroll so gutters remain
    // tappable for horizontal pan (full Quiet padding fills the strip).
    // Named BarChip (not Chip) so it never clashes with RosterRow.side.chip
    // (the Unknown badge) in Splash property paths.
    mod.widgets.BarChip = set_type_default() do Quiet{
        height: Fit
        padding: Inset{left: 12. right: 12. top: 6. bottom: 6.}
        draw_text.text_style.font_size: 12
        grab_key_focus: false
    }

}
