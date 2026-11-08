//! App window tree Splash module.

use makepad_widgets::*;
use crate::App;

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*

    startup() do #(App::script_component(vm)){
        ui: Root{
            on_startup: ||{
                ui.identity_copy.render()
            }
            main_window := Window{
                window.inner_size: vec2(1180, 760)
                window.title: "Ghal Bol"
                // Match Android launch chrome — avoid a long black GL clear before first paint.
                pass +: {clear_color: #EEF2F8}
                // Makepad dark theme draws caption glyphs with color_label_inner (near-white)
                // on a transparent caption bar. Our clear is #EEF2F8, so min/max/close vanish
                // under Wayland custom chrome. Force light bar + dark glyphs.
                caption_bar +: {
                    draw_bg.color: #EEF2F8
                    caption_label +: {
                        label +: {draw_text +: {color: #0B1220}}
                    }
                    windows_buttons +: {
                        min +: {
                            draw_bg +: {
                                color: #0B1220
                                color_hover: #0B1220
                                color_down: #0B1220
                                bg_color_hover: #DCE4F0
                                bg_color_down: #C5D0DE
                            }
                        }
                        max +: {
                            draw_bg +: {
                                color: #0B1220
                                color_hover: #0B1220
                                color_down: #0B1220
                                bg_color_hover: #DCE4F0
                                bg_color_down: #C5D0DE
                            }
                        }
                        close +: {
                            draw_bg +: {
                                color: #0B1220
                                color_hover: #FFFFFF
                                color_down: #FFFFFF
                                bg_color_hover: #E81123
                                bg_color_down: #F1707A
                            }
                        }
                    }
                }
                // Own the IME inset here. Android uses adjustNothing so the OS
                // does not also shrink the surface — that double-count hid the
                // transcript and made the keyboard dance on scroll.
                body +: {
                    keyboard_resize: true
                    identity_view := Panel{
                        draw_bg.color: #EEF2F8
                        width: Fill
                        height: Fill
                        flow: Down
                        spacing: 0
                        padding: Inset{
                            top: (mod.widgets.SAFE_INSET_PAD_TOP)
                            bottom: (mod.widgets.SAFE_INSET_PAD_BOTTOM)
                            left: (mod.widgets.SAFE_INSET_PAD_LEFT)
                            right: (mod.widgets.SAFE_INSET_PAD_RIGHT)
                        }
                        unlock_scroll := VScroll{
                            spacing: 16
                            padding: Inset{left: 20. right: 20. top: 28. bottom: 28.}
                            align: Center
                            // One column: title + form share width so unlock chrome stays centered.
                            // apply_shell_layout clamps identity_column to ≤360.
                            identity_column := View{
                                width: Fill
                                height: Fit
                                flow: Down
                                spacing: 16
                                align: Center
                            identity_copy := View{
                                width: Fill
                                height: Fit
                                flow: Down
                                spacing: 10
                                align: Center
                                on_render: ||{
                                    // Fit + parent align:Center so the brand sits on the same axis as the form.
                                    Selectable{
                                        width: Fit
                                        text: "Ghal Bol"
                                        draw_text.color: #0B1220
                                        draw_text.text_style.font_size: 30
                                    }
                                    // Fill width + label_align:Center — layout align alone leaves wrapped ink left.
                                    hint_label := Selectable{
                                        width: Fill
                                        height: Fit
                                        label_align: Center
                                        text: state.hint
                                        draw_text.color: #5A6B7D
                                        draw_text.max_lines: 6
                                    }
                                    if state.status != ""
                                        status_label := Selectable{
                                            width: Fill
                                            height: Fit
                                            label_align: Center
                                            text: state.status
                                            draw_text.color: #7A8B9C
                                            draw_text.max_lines: 4
                                        }
                                    if state.algo_line != ""
                                        algo_label := Selectable{
                                            width: Fit
                                            height: Fit
                                            text: state.algo_line
                                            draw_text.color: #0183FB
                                        }
                                }
                            }
                            identity_form := View{
                                width: Fill
                                height: Fit
                                flow: Down
                                spacing: 14
                                align: Center
                            password_row := View{
                                width: Fill
                                height: Fit
                                flow: Right
                                spacing: 8
                                align: Align{y: 0.5}
                                password_input := Field{
                                    empty_text: "Password"
                                    is_password: true
                                    width: Fill
                                    height: Fit
                                }
                                password_eye := Quiet{ text: "Show" }
                            }
                            unlock_button := Go{ text: "Continue" width: Fill }
                            mode_button := Quiet{ text: "Import an existing key" width: Fill }
                            secret_row := View{
                                width: Fill
                                height: Fit
                                flow: Right
                                spacing: 8
                                align: Align{y: 0.5}
                                secret_input := Field{
                                    empty_text: "Private key hex"
                                    is_password: true
                                    width: Fill
                                    height: Fit
                                }
                                secret_eye := Quiet{ text: "Show" }
                            }
                            // Full-width HScroll — never stack these as Fill-width Down rows
                            // (that removes horizontal pan on Android).
                            algo_row := HScroll{
                                width: Fill
                                spacing: 8
                                algo_secp := Quiet{
                                    text: "secp256k1  [on]"
                                    width: Fit
                                    draw_bg.color: #D6E8FF
                                    draw_bg.color_hover: #BFD9FF
                                    draw_bg.color_down: #A8CBFF
                                    draw_bg.color_focus: #D6E8FF
                                    on_click: ||{
                                        mod.state.algo = "secp256k1"
                                        mod.state.algo_line = "Algorithm: secp256k1"
                                        mod.state.algo_gen = mod.state.algo_gen + 1
                                        ui.algo_secp.set_text("secp256k1  [on]")
                                        ui.algo_ed.set_text("ed25519")
                                        ui.algo_p256.set_text("ecdsa-p256")
                                        ui.algo_secp.draw_bg.color = #D6E8FF
                                        ui.algo_secp.draw_bg.color_hover = #BFD9FF
                                        ui.algo_secp.draw_bg.color_down = #A8CBFF
                                        ui.algo_secp.draw_bg.color_focus = #D6E8FF
                                        ui.algo_ed.draw_bg.color = #FFFFFF
                                        ui.algo_ed.draw_bg.color_hover = #DCE4F0
                                        ui.algo_ed.draw_bg.color_down = #C5D0DE
                                        ui.algo_ed.draw_bg.color_focus = #FFFFFF
                                        ui.algo_p256.draw_bg.color = #FFFFFF
                                        ui.algo_p256.draw_bg.color_hover = #DCE4F0
                                        ui.algo_p256.draw_bg.color_down = #C5D0DE
                                        ui.algo_p256.draw_bg.color_focus = #FFFFFF
                                        ui.identity_copy.render()
                                    }
                                }
                                algo_ed := Quiet{
                                    text: "ed25519"
                                    width: Fit
                                    on_click: ||{
                                        mod.state.algo = "ed25519"
                                        mod.state.algo_line = "Algorithm: ed25519"
                                        mod.state.algo_gen = mod.state.algo_gen + 1
                                        ui.algo_secp.set_text("secp256k1")
                                        ui.algo_ed.set_text("ed25519  [on]")
                                        ui.algo_p256.set_text("ecdsa-p256")
                                        ui.algo_ed.draw_bg.color = #D6E8FF
                                        ui.algo_ed.draw_bg.color_hover = #BFD9FF
                                        ui.algo_ed.draw_bg.color_down = #A8CBFF
                                        ui.algo_ed.draw_bg.color_focus = #D6E8FF
                                        ui.algo_secp.draw_bg.color = #FFFFFF
                                        ui.algo_secp.draw_bg.color_hover = #DCE4F0
                                        ui.algo_secp.draw_bg.color_down = #C5D0DE
                                        ui.algo_secp.draw_bg.color_focus = #FFFFFF
                                        ui.algo_p256.draw_bg.color = #FFFFFF
                                        ui.algo_p256.draw_bg.color_hover = #DCE4F0
                                        ui.algo_p256.draw_bg.color_down = #C5D0DE
                                        ui.algo_p256.draw_bg.color_focus = #FFFFFF
                                        ui.identity_copy.render()
                                    }
                                }
                                algo_p256 := Quiet{
                                    text: "ecdsa-p256"
                                    width: Fit
                                    on_click: ||{
                                        mod.state.algo = "ecdsa-p256"
                                        mod.state.algo_line = "Algorithm: ecdsa-p256"
                                        mod.state.algo_gen = mod.state.algo_gen + 1
                                        ui.algo_secp.set_text("secp256k1")
                                        ui.algo_ed.set_text("ed25519")
                                        ui.algo_p256.set_text("ecdsa-p256  [on]")
                                        ui.algo_p256.draw_bg.color = #D6E8FF
                                        ui.algo_p256.draw_bg.color_hover = #BFD9FF
                                        ui.algo_p256.draw_bg.color_down = #A8CBFF
                                        ui.algo_p256.draw_bg.color_focus = #D6E8FF
                                        ui.algo_secp.draw_bg.color = #FFFFFF
                                        ui.algo_secp.draw_bg.color_hover = #DCE4F0
                                        ui.algo_secp.draw_bg.color_down = #C5D0DE
                                        ui.algo_secp.draw_bg.color_focus = #FFFFFF
                                        ui.algo_ed.draw_bg.color = #FFFFFF
                                        ui.algo_ed.draw_bg.color_hover = #DCE4F0
                                        ui.algo_ed.draw_bg.color_down = #C5D0DE
                                        ui.algo_ed.draw_bg.color_focus = #FFFFFF
                                        ui.identity_copy.render()
                                    }
                                }
                            }
                            delete_button := Stop{ text: "Delete identity on this device" width: Fill }
                            import_backup_button := Quiet{ text: "Import keystore backup" width: Fill }
                            }
                            }
                        }
                    }
                    hub_view := Panel{
                        visible: false
                        draw_bg.color: #E4EAF3
                        flow: Down
                        padding: Inset{
                            top: (mod.widgets.SAFE_INSET_PAD_TOP)
                            bottom: (mod.widgets.SAFE_INSET_PAD_BOTTOM)
                            left: (mod.widgets.SAFE_INSET_PAD_LEFT)
                            right: (mod.widgets.SAFE_INSET_PAD_RIGHT)
                        }
                        hub_body := View{
                            width: Fill
                            height: Fill
                            flow: Right
                        nav_rail := SolidView{
                            show_bg: true
                            draw_bg.color: #EEF2F8
                            width: 176
                            height: Fill
                            flow: Down
                            spacing: 8
                            padding: Inset{top: 16. bottom: 14. left: 12. right: 12.}
                            Selectable{
                                text: "Ghal Bol"
                                draw_text.color: #10236D
                                draw_text.text_style.font_size: 14
                                width: Fill
                            }
                            // Peers are roots (go_peer). Idle+active Overlay — paint from hub_tab.
                            rail_chats_slot := View{
                                width: Fill height: Fit flow: Overlay
                                tab_chats := RailTab{ text: "Chats" }
                                tab_chats_on := RailTabOn{ text: "Chats" visible: false }
                                mark_chats := NavMark{ abs_pos: vec2(10, 13) }
                            }
                            rail_contacts_slot := View{
                                width: Fill height: Fit flow: Overlay
                                tab_contacts := RailTab{ text: "Contacts" }
                                tab_contacts_on := RailTabOn{ text: "Contacts" visible: false }
                                mark_contacts := NavMark{ abs_pos: vec2(10, 13) }
                            }
                            rail_invite_slot := View{
                                width: Fill height: Fit flow: Overlay
                                tab_invite := RailTab{ text: "Invite" }
                                tab_invite_on := RailTabOn{ text: "Invite" visible: false }
                                mark_invite := NavMark{ abs_pos: vec2(10, 13) }
                            }
                            rail_settings_slot := View{
                                width: Fill height: Fit flow: Overlay
                                tab_settings := RailTab{ text: "Settings" }
                                tab_settings_on := RailTabOn{ text: "Settings" visible: false }
                                mark_settings := NavMark{ abs_pos: vec2(10, 13) }
                            }
                            Filler{}
                            rail_lock_slot := View{
                                width: Fill height: Fit flow: Overlay
                                lock_button := RailTab{ text: "Lock" }
                                mark_lock := NavMark{ abs_pos: vec2(10, 13) }
                            }
                        }
                        rail_divider := SolidView{
                            show_bg: true
                            draw_bg.color: #C5D0DE
                            width: 1
                            height: Fill
                        }
                        chats_pane := View{
                            width: Fill
                            height: Fill
                            flow: Right
                            roster_col := SolidView{
                                show_bg: true
                                draw_bg.color: #FFFFFF
                                width: 400
                                height: Fill
                                flow: Down
                                spacing: 0
                                // Stack title ABOVE a full-width ActionBar. Putting title +
                                // actions in one `flow: Right` row on Android gives the
                                // scroller a leftover width and kills horizontal pan — never
                                // again nest HScroll beside the title on narrow chrome.
                                roster_bar := SolidView{
                                    show_bg: true
                                    draw_bg.color: #EEF2F8
                                    width: Fill
                                    height: Fit
                                    flow: Down
                                    spacing: 0
                                    // Title is static — keep it short; vertical space belongs
                                    // to ActionBar (horizontal pan finger band), not the label.
                                    View{
                                        width: Fill
                                        height: Fit
                                        padding: Inset{left: 12. right: 12. top: 4. bottom: 0.}
                                        Label{
                                            text: "Ghal Bol"
                                            draw_text.color: #0B1220
                                            draw_text.text_style.font_size: 16
                                            width: Fill
                                            draw_text.max_lines: 1
                                            draw_text.text_overflow: Ellipsis
                                        }
                                    }
                                    roster_actions := ActionBar{
                                        width: Fill
                                        new_chat_button := BarChip{ text: "New chat" }
                                        invite_button := BarChip{ text: "Invite" }
                                        join_button := BarChip{ text: "Join" }
                                        scan_button := BarChip{ text: "Scan" }
                                        delivery_button := BarChip{ text: "Delivery" }
                                        hub_lock_button := BarChip{ text: "Lock" }
                                    }
                                }
                                SolidView{
                                    show_bg: true
                                    draw_bg.color: #FFFFFF
                                    width: Fill
                                    height: Fit
                                    padding: Inset{left: 16. right: 16. top: 12. bottom: 12.}
                                    search_input := Field{
                                        empty_text: "Search contacts…"
                                        width: Fill
                                    }
                                }
                                roster_list := VScroll{
                                    spacing: 6
                                    padding: Inset{left: 8. right: 8. top: 8. bottom: 12.}
                                    // Container owns the press (rows have no cursor/Button): a
                                    // drag scrolls, a tap opens. Index matches state.roster.
                                    on_item_tap: |index|{
                                        if index >= state.roster.len() { return }
                                        let row = state.roster[index]
                                        mod.state.selected_pk = row.pk
                                        mod.state.selected_title = row.title
                                        mod.state.open_gen = mod.state.open_gen + 1
                                        ui.chat_log.render()
                                    }
                                    on_render: ||{
                                        if state.roster.len() == 0
                                            View{
                                                width: Fill
                                                height: Fit
                                                flow: Down
                                                spacing: 12
                                                padding: 28
                                                align: Center
                                                Label{
                                                    text: state.roster_empty_title
                                                    draw_text.color: #0B1220
                                                    draw_text.text_style.font_size: 18
                                                }
                                                Label{
                                                    width: Fill
                                                    text: state.roster_empty_body
                                                    draw_text.color: #7A8B9C
                                                }
                                            }
                                        else for i, row in state.roster {
                                            // Open room = green wash, unread = blue wash with a
                                            // count badge (Flutter roster chrome).
                                            if row.pk == state.selected_pk
                                                RosterRow{
                                                    draw_bg.color: #D6E8FF
                                                    avatar.draw_bg.color: #A8CBFF
                                                    avatar.initial.text: row.initial
                                                    body.title.text: row.title
                                                    body.status.text: row.status
                                                    body.status.visible: row.status != ""
                                                    body.preview.text: row.preview
                                                    side.chip.visible: row.unknown == "1"
                                                    side.badge.visible: row.unread != "0"
                                                    side.badge.count.text: row.unread
                                                }
                                            else if row.unread != "0"
                                                RosterRow{
                                                    draw_bg.color: #E7F3FF
                                                    avatar.draw_bg.color: #C5E1F7
                                                    avatar.initial.draw_text.color: #0B5CAB
                                                    avatar.initial.text: row.initial
                                                    body.title.text: row.title
                                                    body.title.draw_text.color: #0B5CAB
                                                    body.status.text: row.status
                                                    body.status.visible: row.status != ""
                                                    body.preview.text: row.preview
                                                    body.preview.draw_text.color: #0B1220
                                                    side.chip.visible: row.unknown == "1"
                                                    side.badge.visible: true
                                                    side.badge.count.text: row.unread
                                                }
                                            else
                                                RosterRow{
                                                    avatar.initial.text: row.initial
                                                    body.title.text: row.title
                                                    body.status.text: row.status
                                                    body.status.visible: row.status != ""
                                                    body.preview.text: row.preview
                                                    side.chip.visible: row.unknown == "1"
                                                    side.badge.visible: false
                                                }
                                        }
                                    }
                                }
                            }
                            chat_col := SolidView{
                                show_bg: true
                                draw_bg.color: #ECE5DD
                                width: Fill
                                height: Fill
                                flow: Down
                                spacing: 0
                                // Title row + horizontally scrollable action strip (icons).
                                chat_bar := SolidView{
                                    show_bg: true
                                    draw_bg.color: #EEF2F8
                                    width: Fill
                                    height: Fit
                                    flow: Down
                                    spacing: 0
                                    View{
                                        width: Fill
                                        height: Fit
                                        flow: Right
                                        spacing: 10
                                        padding: Inset{left: 10. right: 10. top: 8. bottom: 4.}
                                        align: Align{y: 0.5}
                                        chat_back_button := IconBtn{ text: "\u{f060}" visible: false }
                                        chat_title_label := Label{
                                            text: state.selected_title
                                            draw_text.color: #0B1220
                                            draw_text.text_style.font_size: 17
                                            width: Fill
                                            draw_text.max_lines: 1
                                            draw_text.text_overflow: Ellipsis
                                        }
                                    }
                                    chat_actions := HScroll{
                                        spacing: 6
                                        call_button := IconBtn{ text: "\u{f095}" }
                                        video_button := IconBtn{ text: "\u{f03d}" }
                                        chat_menu_button := IconBtn{ text: "\u{f142}" }
                                    }
                                    // Contact-trust banner (DESIGN.md § Contact trust): shown only
                                    // while the open peer is `is_known: false`. Add / Block here;
                                    // ack policy is untouched — this is chrome only.
                                    trust_banner := SolidView{
                                        visible: false
                                        show_bg: true
                                        draw_bg.color: #E8F4FD
                                        width: Fill
                                        height: Fit
                                        flow: Right
                                        spacing: 8
                                        padding: Inset{left: 14. right: 10. top: 8. bottom: 8.}
                                        align: Align{y: 0.5}
                                        Label{
                                            width: Fill
                                            text: "You have not added this person yet."
                                            draw_text.color: #0B1220
                                            draw_text.text_style.font_size: 13
                                            draw_text.max_lines: 2
                                            draw_text.text_overflow: Ellipsis
                                        }
                                        trust_add_button := Quiet{
                                            text: "Add"
                                            padding: Inset{left: 14. right: 14. top: 8. bottom: 8.}
                                            draw_text.color: #0183FB
                                            draw_text.color_hover: #0183FB
                                            draw_text.color_down: #0183FB
                                            draw_text.color_focus: #0183FB
                                        }
                                        trust_block_button := Quiet{
                                            text: "Block"
                                            padding: Inset{left: 14. right: 14. top: 8. bottom: 8.}
                                            draw_text.color: #C62828
                                            draw_text.color_hover: #C62828
                                            draw_text.color_down: #C62828
                                            draw_text.color_focus: #C62828
                                        }
                                    }
                                    // Flutter `_hubChatRoomPopupMenu` — toggled by ⋮.
                                    chat_menu := SolidView{
                                        visible: false
                                        show_bg: true
                                        draw_bg.color: #FFFFFF
                                        width: Fill
                                        height: Fit
                                        flow: Down
                                        spacing: 0
                                        padding: Inset{left: 8. right: 8. top: 4. bottom: 8.}
                                        menu_call_button := MenuRow{ text: "Voice call" }
                                        menu_video_button := MenuRow{ text: "Video call" }
                                        menu_share_button := MenuRow{ text: "Share invitation" }
                                        menu_join_button := MenuRow{ text: "Join someone" }
                                        menu_add_button := MenuRow{ text: "Add contact" }
                                        menu_block_button := MenuRow{ text: "Block" }
                                        menu_lock_button := MenuRow{ text: "Lock" }
                                    }
                                }
                                chat_log := VScroll{
                                    spacing: 10
                                    padding: 16
                                    on_render: ||{
                                        // Labels, not Selectable: nothing in the scrolling log may
                                        // take key focus from the composer.
                                        call_label := Label{
                                            width: Fill
                                            text: state.call_line
                                            if state.call_line_is_error == "1"
                                                draw_text.color: #C62828
                                            else
                                                draw_text.color: #7A8B9C
                                        }
                                        if state.lines.len() == 0
                                            Label{
                                                width: Fill
                                                text: state.transcript
                                                draw_text.color: #5A6B7D
                                            }
                                        else for i, line in state.lines {
                                            // Outgoing (right) / inbound (left). Opposite-side
                                            // gutter (~48) so chips are not full-bleed; ticks +
                                            // caption live inside the bubble meta row (Flutter).
                                            if line.side == "out"
                                                View{
                                                    width: Fill
                                                    height: Fit
                                                    flow: Right
                                                    align: Align{x: 1.0}
                                                    padding: Inset{left: 48. right: 8. top: 0. bottom: 0.}
                                                    if line.action != ""
                                                        View{
                                                            width: Fit{max: FitBound.Abs(280)}
                                                            height: Fit
                                                            flow: Down
                                                            spacing: 2
                                                            Bubble{
                                                                width: Fit{max: FitBound.Abs(280)}
                                                                draw_bg.color: #D6E8FF
                                                                draw_bg.color_hover: #BFD9FF
                                                                draw_bg.color_down: #A8CBFF
                                                                draw_bg.border_color: #D6E8FF
                                                                draw_text.color: #0B1220
                                                                text: line.body
                                                                on_click: ||{
                                                                    mod.state.play_path = line.path
                                                                    mod.state.play_action = line.action
                                                                    mod.state.play_gen = mod.state.play_gen + 1
                                                                }
                                                            }
                                                            View{
                                                                width: Fill
                                                                height: Fit
                                                                flow: Right
                                                                spacing: 4
                                                                align: Align{x: 1.0 y: 0.5}
                                                                Label{
                                                                    text: line.caption
                                                                    draw_text.color: #7A8B9C
                                                                    draw_text.text_style.font_size: 11
                                                                }
                                                                if line.read == "1"
                                                                    Label{
                                                                        text: line.tick
                                                                        draw_text.color: #34B7F1
                                                                        draw_text.text_style.font_size: 12
                                                                    }
                                                                else if line.read == "failed"
                                                                    Label{
                                                                        text: line.tick
                                                                        draw_text.color: #D84315
                                                                        draw_text.text_style.font_size: 12
                                                                    }
                                                                else
                                                                    Label{
                                                                        text: line.tick
                                                                        draw_text.color: #7A8B9C
                                                                        draw_text.text_style.font_size: 12
                                                                    }
                                                            }
                                                        }
                                                    else if line.read == "1"
                                                        TextBubble{
                                                            draw_bg.color: #D6E8FF
                                                            body.text: line.body
                                                            meta.caption.text: line.caption
                                                            meta.tick.text: line.tick
                                                            meta.tick.draw_text.color: #34B7F1
                                                        }
                                                    else if line.read == "failed"
                                                        TextBubble{
                                                            draw_bg.color: #D6E8FF
                                                            body.text: line.body
                                                            meta.caption.text: line.caption
                                                            meta.tick.text: line.tick
                                                            meta.tick.draw_text.color: #D84315
                                                        }
                                                    else
                                                        TextBubble{
                                                            draw_bg.color: #D6E8FF
                                                            body.text: line.body
                                                            meta.caption.text: line.caption
                                                            meta.tick.text: line.tick
                                                        }
                                                }
                                            else
                                                View{
                                                    width: Fill
                                                    height: Fit
                                                    flow: Right
                                                    align: Align{x: 0.0}
                                                    padding: Inset{left: 8. right: 48. top: 0. bottom: 0.}
                                                    if line.action == "fetch"
                                                        View{
                                                            width: Fit{max: FitBound.Abs(280)}
                                                            height: Fit
                                                            flow: Down
                                                            spacing: 4
                                                            RoundedView{
                                                                width: Fit{max: FitBound.Abs(280)}
                                                                height: Fit
                                                                flow: Down
                                                                spacing: 6
                                                                padding: Inset{left: 12. right: 12. top: 10. bottom: 8.}
                                                                draw_bg.border_radius: 12.0
                                                                draw_bg.border_size: 0.0
                                                                draw_bg.color: #FFFFFF
                                                                Label{
                                                                    width: Fit{max: FitBound.Abs(256)}
                                                                    text: line.body
                                                                    draw_text.color: #0B1220
                                                                    draw_text.text_style.font_size: 14
                                                                    draw_text.max_lines: 2
                                                                    draw_text.text_overflow: Ellipsis
                                                                }
                                                                Label{
                                                                    text: line.detail
                                                                    draw_text.color: #7A8B9C
                                                                    draw_text.text_style.font_size: 12
                                                                }
                                                                View{
                                                                    width: Fill
                                                                    height: Fit
                                                                    flow: Right
                                                                    spacing: 4
                                                                    align: Align{y: 0.5}
                                                                    Bubble{
                                                                        width: Fit
                                                                        text: "Download"
                                                                        padding: Inset{left: 12. right: 12. top: 8. bottom: 8.}
                                                                        on_click: ||{
                                                                            mod.state.play_path = line.path
                                                                            mod.state.play_action = "fetch"
                                                                            mod.state.play_gen = mod.state.play_gen + 1
                                                                        }
                                                                    }
                                                                    Filler{}
                                                                    Label{
                                                                        text: line.caption
                                                                        draw_text.color: #7A8B9C
                                                                        draw_text.text_style.font_size: 11
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    else if line.action == "file"
                                                        View{
                                                            width: Fit{max: FitBound.Abs(280)}
                                                            height: Fit
                                                            flow: Down
                                                            spacing: 4
                                                            RoundedView{
                                                                width: Fit{max: FitBound.Abs(280)}
                                                                height: Fit
                                                                flow: Down
                                                                spacing: 6
                                                                padding: Inset{left: 12. right: 12. top: 10. bottom: 8.}
                                                                draw_bg.border_radius: 12.0
                                                                draw_bg.border_size: 0.0
                                                                draw_bg.color: #FFFFFF
                                                                Label{
                                                                    width: Fit{max: FitBound.Abs(256)}
                                                                    text: line.body
                                                                    draw_text.color: #0B1220
                                                                    draw_text.text_style.font_size: 14
                                                                    draw_text.max_lines: 2
                                                                    draw_text.text_overflow: Ellipsis
                                                                }
                                                                Label{
                                                                    text: line.detail
                                                                    draw_text.color: #7A8B9C
                                                                    draw_text.text_style.font_size: 12
                                                                }
                                                                View{
                                                                    width: Fill
                                                                    height: Fit
                                                                    flow: Right
                                                                    spacing: 4
                                                                    Bubble{
                                                                        width: Fit
                                                                        text: "Open"
                                                                        padding: Inset{left: 12. right: 12. top: 8. bottom: 8.}
                                                                        on_click: ||{
                                                                            mod.state.play_path = line.path
                                                                            mod.state.play_action = "file"
                                                                            mod.state.play_gen = mod.state.play_gen + 1
                                                                        }
                                                                    }
                                                                    Bubble{
                                                                        width: Fit
                                                                        text: "Save"
                                                                        padding: Inset{left: 12. right: 12. top: 8. bottom: 8.}
                                                                        on_click: ||{
                                                                            mod.state.play_path = line.path
                                                                            mod.state.play_action = "save"
                                                                            mod.state.play_gen = mod.state.play_gen + 1
                                                                        }
                                                                    }
                                                                    Filler{}
                                                                    Label{
                                                                        text: line.caption
                                                                        draw_text.color: #7A8B9C
                                                                        draw_text.text_style.font_size: 11
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    else if line.action != ""
                                                        View{
                                                            width: Fit{max: FitBound.Abs(280)}
                                                            height: Fit
                                                            flow: Down
                                                            spacing: 2
                                                            Bubble{
                                                                width: Fit{max: FitBound.Abs(280)}
                                                                draw_bg.color: #FFFFFF
                                                                draw_bg.color_hover: #E4EAF3
                                                                draw_bg.color_down: #DCE4F0
                                                                draw_bg.border_color: #FFFFFF
                                                                draw_text.color: #0B1220
                                                                text: line.body
                                                                on_click: ||{
                                                                    mod.state.play_path = line.path
                                                                    mod.state.play_action = line.action
                                                                    mod.state.play_gen = mod.state.play_gen + 1
                                                                }
                                                            }
                                                            Label{
                                                                text: line.caption
                                                                draw_text.color: #7A8B9C
                                                                draw_text.text_style.font_size: 11
                                                            }
                                                        }
                                                    else
                                                        TextBubble{
                                                            body.text: line.body
                                                            meta.caption.text: line.caption
                                                            meta.tick.text: ""
                                                        }
                                                }
                                        }
                                    }
                                }
                                // Messenger-dense chrome (Telegram/WhatsApp): ~40px icons, tight
                                // gutters, field max ~4 lines then scrolls — not a growing slab.
                                composer_bar := SolidView{
                                    show_bg: true
                                    draw_bg.color: #E4EAF3
                                    width: Fill
                                    height: Fit
                                    flow: Down
                                    spacing: 4
                                    padding: Inset{left: 4. right: 4. top: 4. bottom: 4.}
                                    older_button := BarChip{ text: "Older messages" visible: false }
                                    // Flutter `_voiceRecordingBar`: Discard · red · timer · Send.
                                    // Shown while `host::voice_note_recording()`; hides composer_row.
                                    recording_bar := View{
                                        visible: false
                                        width: Fill
                                        height: Fit
                                        flow: Right
                                        spacing: 4
                                        align: Align{y: 0.5}
                                        record_discard_button := IconBtn{
                                            width: 40
                                            height: 40
                                            text: "\u{f1f8}"
                                            draw_text.text_style.font_size: 16
                                            draw_text.color: #D32F2F
                                            draw_text.color_hover: #D32F2F
                                            draw_text.color_down: #B71C1C
                                            draw_text.color_focus: #D32F2F
                                        }
                                        RoundedView{
                                            width: Fill
                                            height: 40
                                            flow: Right
                                            spacing: 8
                                            padding: Inset{left: 10. right: 10. top: 6. bottom: 6.}
                                            align: Align{y: 0.5}
                                            draw_bg.border_radius: 20.0
                                            draw_bg.border_size: 1.0
                                            draw_bg.border_color: #C5D0DE
                                            draw_bg.color: #FFFFFF
                                            RoundedView{
                                                width: 8
                                                height: 8
                                                draw_bg.border_radius: 4.0
                                                draw_bg.border_size: 0.0
                                                draw_bg.color: #FF5252
                                            }
                                            record_timer_label := Label{
                                                text: "0:00"
                                                draw_text.color: #0B1220
                                                draw_text.text_style.font_size: 14
                                            }
                                        }
                                        record_send_button := IconGo{
                                            width: 40
                                            height: 40
                                            text: "\u{f1d8}"
                                            draw_text.text_style.font_size: 16
                                        }
                                    }
                                    // Icon | Fill field | Send — never HScroll long labels (that
                                    // squeezed the field into a vertical "M/e/s/s/a/g/e" pill).
                                    composer_row := View{
                                        width: Fill
                                        height: Fit
                                        flow: Right
                                        spacing: 4
                                        // Bottom-align icons when the field grows with wrapped lines.
                                        align: Align{y: 1.0}
                                        record_button := IconBtn{
                                            width: 40
                                            height: 40
                                            text: "\u{f130}"
                                            draw_text.text_style.font_size: 16
                                        }
                                        choose_file_button := IconBtn{
                                            width: 40
                                            height: 40
                                            text: "\u{f0c6}"
                                            draw_text.text_style.font_size: 16
                                        }
                                        // Multiline like Flutter — wrap needs Right{wrap:true}.
                                        // Desktop: Enter sends, Shift+Enter newline (submit_on_enter).
                                        // Android soft keyboard: never return_key_type:Send — that
                                        // replaces Enter with IME Send and kills newlines. Soft Enter
                                        // inserts newline; paper-plane IconGo sends.
                                        // Cap height so long drafts scroll inside the field.
                                        composer := Field{
                                            empty_text: "Message"
                                            width: Fill
                                            height: Fit{max: FitBound.Abs(100)}
                                            padding: Inset{left: 12. right: 12. top: 8. bottom: 8.}
                                            draw_bg.border_radius: 18.0
                                            is_multiline: true
                                            submit_on_enter: true
                                            flow: Right{wrap: true}
                                        }
                                        // Press (not click-up): IME reflow must not move the
                                        // hit target before FingerUp. grab_key_focus is off on IconGo.
                                        send_button := IconGo{
                                            width: 40
                                            height: 40
                                            text: "\u{f1d8}"
                                            draw_text.text_style.font_size: 16
                                        }
                                    }
                                }
                            }
                        }
                        contacts_pane := Panel{
                            visible: false
                            draw_bg.color: #FFFFFF
                            width: Fill
                            height: Fill
                            flow: Down
                            spacing: 0
                            contacts_scroll := VScroll{
                                spacing: 10
                                padding: 32
                                Selectable{
                                    text: "Contacts"
                                    draw_text.color: #0B1220
                                    draw_text.text_style.font_size: 24
                                }
                                Selectable{
                                    width: Fill
                                    text: "People you chat with. Add by public key, rename, or remove. Blocking is local to this device."
                                    draw_text.color: #5A6B7D
                                }
                                contacts_button := HubDestBtn{ text: "Contacts — add, rename, or remove by public key" }
                                add_contact_button := HubDestBtn{ text: "Add contact by public key" }
                                blocked_button := HubDestBtn{ text: "Blocked contacts — people you blocked on this device" }
                            }
                        }
                        invite_pane := Panel{
                            visible: false
                            draw_bg.color: #FFFFFF
                            width: Fill
                            height: Fill
                            flow: Down
                            spacing: 0
                            invite_scroll := VScroll{
                                spacing: 10
                                padding: 32
                                Selectable{
                                    text: "Invite"
                                    draw_text.color: #0B1220
                                    draw_text.text_style.font_size: 24
                                }
                                Selectable{
                                    width: Fill
                                    text: "Share your invitation so a guest can store your public key and dial. You do not need theirs first."
                                    draw_text.color: #5A6B7D
                                }
                                invite_button_id := StackPrimaryBtn{ text: "Show QR invitation" }
                                ActionStack{
                                    invite_copy_button := StackSecondaryBtn{ text: "Copy invitation link" }
                                    key_copy_button := StackSecondaryBtn{ text: "Copy public key" }
                                }
                                Selectable{
                                    text: "Join someone"
                                    draw_text.color: #0B1220
                                    draw_text.text_style.font_size: 18
                                }
                                join_nav_button := HubDestBtn{ text: "Paste invitation link or ghalbol:// URI" }
                                scan_nav_button := HubDestBtn{ text: "Scan invitation QR with camera" }
                                scan_file_button := HubDestBtn{ text: "Join from QR picture — PNG or JPEG" }
                            }
                        }
                        settings_pane := Panel{
                            visible: false
                            draw_bg.color: #FFFFFF
                            width: Fill
                            height: Fill
                            flow: Down
                            spacing: 0
                            settings_scroll := VScroll{
                                spacing: 14
                                padding: 32
                                Selectable{
                                    text: "Settings"
                                    draw_text.color: #0B1220
                                    draw_text.text_style.font_size: 24
                                }
                                Selectable{
                                    width: Fill
                                    text: state.identity_blurb
                                    draw_text.color: #5A6B7D
                                }
                                Selectable{
                                    text: "Your identity"
                                    draw_text.color: #0B1220
                                    draw_text.text_style.font_size: 18
                                }
                                Selectable{
                                    width: Fill
                                    text: state.identity_detail
                                    draw_text.color: #0B1220
                                }
                                Selectable{
                                    text: "Display name on invitations"
                                    draw_text.color: #0B1220
                                    draw_text.text_style.font_size: 16
                                }
                                Selectable{
                                    width: Fill
                                    text: "Optional name guests see when they scan your QR. Saved on this device."
                                    draw_text.color: #7A8B9C
                                }
                                display_name_input := Field{
                                    empty_text: "Your name (optional)"
                                    width: Fill
                                }
                                save_display_name_button := StackSecondaryBtn{ text: "Save display name" }
                                Selectable{
                                    text: "Backup and private key"
                                    draw_text.color: #0B1220
                                    draw_text.text_style.font_size: 16
                                }
                                ActionStack{
                                    key_button := StackSecondaryBtn{ text: "Show private key" }
                                    backup_button := StackSecondaryBtn{ text: "Export backup" }
                                    password_button := StackSecondaryBtn{ text: "Change password" }
                                }
                                Selectable{
                                    width: Fill
                                    text: "App password is required to view the secret. Keep backups with your password."
                                    draw_text.color: #7A8B9C
                                }
                                language_button := HubDestBtn{ text: "Language — display language for this app" }
                                delivery_nav_button := HubDestBtn{ text: "Delivery storage" }
                                log_button := HubDestBtn{ text: "App log — session diagnostics" }
                                about_button := HubDestBtn{ text: "Availability and About" }
                                logout_button := Stop{ text: "Log out" width: Fit }
                            }
                        }
                        }
                        bottom_nav := SolidView{
                            visible: false
                            show_bg: true
                            draw_bg.color: #E4EAF3
                            width: Fill
                            height: Fit
                            flow: Right
                            spacing: 0
                            padding: Inset{left: 8. right: 8. top: 8. bottom: 8.}
                            align: Align{y: 0.5}
                            bottom_nav_scroll := HScroll{
                                height: 64
                                padding: Inset{left: 4. right: 4. top: 4. bottom: 4.}
                                bottom_chats_slot := View{
                                    width: Fit height: Fit flow: Overlay
                                    bottom_chats := NavChip{ text: "Chats" }
                                    bottom_chats_on := NavChipOn{ text: "Chats" visible: false }
                                }
                                bottom_contacts_slot := View{
                                    width: Fit height: Fit flow: Overlay
                                    bottom_contacts := NavChip{ text: "Contacts" }
                                    bottom_contacts_on := NavChipOn{ text: "Contacts" visible: false }
                                }
                                bottom_invite_slot := View{
                                    width: Fit height: Fit flow: Overlay
                                    bottom_invite := NavChip{ text: "Invite" }
                                    bottom_invite_on := NavChipOn{ text: "Invite" visible: false }
                                }
                                bottom_settings_slot := View{
                                    width: Fit height: Fit flow: Overlay
                                    bottom_settings := NavChip{ text: "Settings" }
                                    bottom_settings_on := NavChipOn{ text: "Settings" visible: false }
                                }
                            }
                        }
                    }
                    sheet_view := Panel{
                        visible: false
                        draw_bg.color: #EEF2F8
                        width: Fill
                        height: Fill
                        flow: Down
                        spacing: 12
                        padding: Inset{
                            left: 24.
                            right: 24.
                            top: (mod.widgets.SAFE_INSET_PAD_TOP + 20.)
                            bottom: (mod.widgets.SAFE_INSET_PAD_BOTTOM + 16.)
                        }
                        back_button := Quiet{ text: "Back" }
                        sheet_scroll := VScroll{
                            spacing: 14
                            padding: Inset{left: 0. right: 0. top: 4. bottom: 12.}
                            sheet_copy := View{
                                width: Fill
                                height: Fit
                                flow: Down
                                spacing: 12
                                on_render: ||{
                                    sheet_title := Selectable{
                                        width: Fill
                                        text: state.sheet_title
                                        draw_text.color: #0B1220
                                        draw_text.text_style.font_size: 22
                                    }
                                    sheet_body := Selectable{
                                        width: Fill
                                        text: state.sheet_body
                                        draw_text.color: #5A6B7D
                                    }
                                    if state.languages.len() > 0
                                        for i, row in state.languages {
                                            if row.code == ""
                                                Selectable{
                                                    width: Fill
                                                    margin: Inset{left: 4. right: 4. top: 12. bottom: 4.}
                                                    text: row.name
                                                    draw_text.color: #7A8B9C
                                                    draw_text.text_style.font_size: 12
                                                }
                                            else
                                                Quiet{
                                                    width: Fill
                                                    label_walk: Walk{width: Fill, height: Fit}
                                                    text: row.name
                                                    on_click: ||{
                                                        mod.state.lang_code = row.code
                                                        mod.state.lang_gen = mod.state.lang_gen + 1
                                                    }
                                                }
                                        }
                                }
                            }
                            invite_frame := SolidView{
                                visible: false
                                show_bg: true
                                draw_bg.color: #FFFFFF
                                width: Fill
                                height: Fit
                                padding: 18
                                align: Center
                                invite_qr := Image{
                                    width: 280
                                    height: 280
                                }
                            }
                            scan_frame := SolidView{
                                visible: false
                                show_bg: true
                                draw_bg.color: #0B1220
                                width: Fill
                                height: Fit
                                padding: 12
                                align: Center
                                scan_preview := Image{
                                    width: 320
                                    height: 240
                                }
                            }
                            paste_row := View{
                                width: Fill
                                height: Fit
                                flow: Right
                                spacing: 8
                                align: Align{y: 0.5}
                                paste_input := Field{
                                    empty_text: "Invitation link"
                                    width: Fill
                                    height: Fit
                                }
                                paste_eye := Quiet{ text: "Show" visible: false }
                            }
                            pk_row := View{
                                width: Fill
                                height: Fit
                                flow: Right
                                spacing: 8
                                align: Align{y: 0.5}
                                pk_input := Field{
                                    empty_text: "Public key"
                                    width: Fill
                                    height: Fit
                                }
                                pk_eye := Quiet{ text: "Show" visible: false }
                            }
                            alias_row := View{
                                width: Fill
                                height: Fit
                                flow: Right
                                spacing: 8
                                align: Align{y: 0.5}
                                alias_input := Field{
                                    empty_text: "Display name"
                                    width: Fill
                                    height: Fit
                                }
                                alias_eye := Quiet{ text: "Show" visible: false }
                            }
                            status_row := View{
                                visible: false
                                width: Fill
                                height: Fit
                                flow: Right{wrap: true}
                                spacing: 10
                                status_available := Quiet{ text: "Available" }
                                status_busy := Quiet{ text: "Busy" }
                                status_away := Quiet{ text: "Away" }
                                status_call := Quiet{ text: "In a call" }
                                status_clear := Quiet{ text: "Clear" }
                            }
                        }
                        sheet_action := Go{ text: "Save" }
                    }
                    // Voice-first call chrome: peer avatar + name + status. Video tiles
                    // stay hidden until a video call is actually active (empty Image
                    // widgets were the two black rectangles on every voice dial).
                    call_view := SolidView{
                        visible: false
                        show_bg: true
                        draw_bg.color: #0B1220
                        width: Fill
                        height: Fill
                        flow: Down
                        spacing: 0
                        padding: Inset{
                            top: (mod.widgets.SAFE_INSET_PAD_TOP)
                            bottom: (mod.widgets.SAFE_INSET_PAD_BOTTOM)
                            left: (mod.widgets.SAFE_INSET_PAD_LEFT)
                            right: (mod.widgets.SAFE_INSET_PAD_RIGHT)
                        }
                        call_body := View{
                            width: Fill
                            height: Fill
                            flow: Down
                            spacing: 20
                            padding: 28
                            align: Center
                            call_peer_block := View{
                                width: Fill
                                height: Fit
                                flow: Down
                                spacing: 14
                                align: Center
                                call_avatar := RoundedView{
                                    width: 112
                                    height: 112
                                    align: Center
                                    draw_bg.border_radius: 56.0
                                    draw_bg.border_size: 0.0
                                    draw_bg.color: #0183FB
                                    call_initial := Label{
                                        text: "?"
                                        draw_text.color: #FFFFFF
                                        draw_text.text_style.font_size: 42
                                    }
                                }
                                call_peer_name := Label{
                                    width: Fill
                                    text: ""
                                    draw_text.color: #FFFFFF
                                    draw_text.text_style.font_size: 24
                                    draw_text.max_lines: 2
                                    draw_text.text_overflow: Ellipsis
                                }
                            }
                            call_copy := View{
                                width: Fill
                                height: Fit
                                flow: Down
                                spacing: 8
                                align: Center
                                on_render: ||{
                                    // Label — not Selectable (that looked like a text field).
                                    call_screen_title := Label{
                                        width: Fill
                                        text: state.call_line
                                        if state.call_line_is_error == "1"
                                            draw_text.color: #FF8A80
                                        else
                                            draw_text.color: #AEC4CF
                                        draw_text.text_style.font_size: 16
                                        draw_text.max_lines: 3
                                        draw_text.text_overflow: Ellipsis
                                    }
                                }
                            }
                            video_row := View{
                                visible: false
                                width: Fill
                                height: Fit
                                flow: Down
                                spacing: 10
                                remote_video := Image{ width: Fill height: 280 }
                                local_video := Image{ width: 140 height: 105 }
                            }
                        }
                        // Labeled controls; HScroll when the row overflows.
                        call_actions := HScroll{
                            width: Fill
                            spacing: 12
                            accept_call_button := Go{ text: "Accept" height: Fit }
                            mute_button := Quiet{ text: "Mute" height: Fit }
                            speaker_button := Quiet{ text: "Speaker" height: Fit }
                            camera_button := Quiet{ text: "Camera on" height: Fit }
                            flip_camera_button := Quiet{ text: "Flip camera" height: Fit }
                            end_call_button := Stop{ text: "End call" height: Fit }
                        }
                    }
                }
            }
        }
    }
}
