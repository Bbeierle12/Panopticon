//! Header toolbar view.

use iced::widget::{button, column, container, row, text, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::message::Message;
use crate::theme::{self, colors};

/// Render a danger/warning style button (for vuln report).
fn danger_button_style(_theme: &iced::Theme, status: iced::widget::button::Status) -> iced::widget::button::Style {
    let base = iced::widget::button::Style {
        background: Some(Background::Color(Color::from_rgba(0.94, 0.27, 0.27, 0.1))),
        text_color: colors::RED,
        border: Border {
            color: Color::from_rgba(0.94, 0.27, 0.27, 0.3),
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    };

    match status {
        iced::widget::button::Status::Hovered => iced::widget::button::Style {
            background: Some(Background::Color(Color::from_rgba(0.94, 0.27, 0.27, 0.2))),
            ..base
        },
        _ => base,
    }
}

/// Render the header toolbar.
pub fn view<'a>(
    is_scanning: bool,
    vuln_count: usize,
    ws_connected: bool,
    device_count: usize,
    alert_count: usize,
    scan_count: usize,
) -> Element<'a, Message> {
    // Logo and title
    let logo = container(
        text("\u{25CE}")  // ◎
            .size(20)
            .color(colors::CYAN)
    )
    .padding([4, 8])
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.13, 0.83, 0.93, 0.1))),
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    });

    // Status message based on state
    let status_msg = if is_scanning {
        "Scanning..."
    } else if !ws_connected {
        "Connecting to backend..."
    } else {
        "System Ready"
    };

    // Status color
    let status_color = if is_scanning {
        colors::YELLOW
    } else if !ws_connected {
        colors::RED
    } else {
        colors::GREEN
    };

    let title_section = row![
        logo,
        Space::with_width(12),
        column![
            text("NETWATCH")
                .size(14)
                .color(colors::TEXT_PRIMARY),
            row![
                // Connection status indicator
                container(Space::with_width(6).height(6))
                    .style(move |_| container::Style {
                        background: Some(Background::Color(status_color)),
                        border: Border {
                            radius: 3.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                Space::with_width(6),
                text(status_msg)
                    .size(9)
                    .color(colors::TEXT_MUTED),
                Space::with_width(12),
                // Device count
                text(format!("{} devices", device_count))
                    .size(9)
                    .color(colors::CYAN),
                Space::with_width(8),
                // Alert count
                if alert_count > 0 {
                    text(format!("{} alerts", alert_count))
                        .size(9)
                        .color(colors::ORANGE)
                } else {
                    text("0 alerts")
                        .size(9)
                        .color(colors::TEXT_MUTED)
                },
            ]
            .align_y(Alignment::Center)
        ]
    ]
    .align_y(Alignment::Center);

    // Vuln Report button
    let vuln_content: Element<'a, Message> = if vuln_count > 0 {
        row![
            text("\u{26A0}").size(12), // ⚠
            Space::with_width(6),
            text("VULN REPORT").size(10),
            Space::with_width(6),
            container(
                text(vuln_count.to_string())
                    .size(9)
                    .color(Color::WHITE)
            )
            .padding([2, 6])
            .style(|_| container::Style {
                background: Some(Background::Color(colors::RED)),
                border: Border {
                    radius: 8.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
        ]
        .align_y(Alignment::Center)
        .into()
    } else {
        row![
            text("\u{26A0}").size(12), // ⚠
            Space::with_width(6),
            text("VULN REPORT").size(10),
        ]
        .align_y(Alignment::Center)
        .into()
    };

    let vuln_btn = button(vuln_content)
        .on_press(Message::ShowVulnDashboard)
        .padding([6, 12])
        .style(danger_button_style);

    // Alerts button
    let alerts_content: Element<'a, Message> = if alert_count > 0 {
        row![
            text("\u{1F514}").size(12), // 🔔
            Space::with_width(6),
            text("ALERTS").size(10),
            Space::with_width(6),
            container(
                text(alert_count.to_string())
                    .size(9)
                    .color(Color::WHITE)
            )
            .padding([2, 6])
            .style(|_| container::Style {
                background: Some(Background::Color(colors::ORANGE)),
                border: Border {
                    radius: 8.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
        ]
        .align_y(Alignment::Center)
        .into()
    } else {
        row![
            text("\u{1F514}").size(12), // 🔔
            Space::with_width(6),
            text("ALERTS").size(10),
        ]
        .align_y(Alignment::Center)
        .into()
    };

    let alerts_btn = button(alerts_content)
        .on_press(Message::ShowAlertsDashboard)
        .padding([6, 12])
        .style(|_theme, status| {
            let base = iced::widget::button::Style {
                background: Some(Background::Color(Color::from_rgba(1.0, 0.6, 0.0, 0.1))),
                text_color: colors::ORANGE,
                border: Border {
                    color: Color::from_rgba(1.0, 0.6, 0.0, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            };

            match status {
                iced::widget::button::Status::Hovered => iced::widget::button::Style {
                    background: Some(Background::Color(Color::from_rgba(1.0, 0.6, 0.0, 0.2))),
                    ..base
                },
                _ => base,
            }
        });

    // Scans dashboard button
    let scans_content: Element<'a, Message> = if scan_count > 0 {
        row![
            text("\u{1F4CB}").size(12), // 📋
            Space::with_width(6),
            text("SCANS").size(10),
            Space::with_width(6),
            container(
                text(scan_count.to_string())
                    .size(9)
                    .color(Color::WHITE)
            )
            .padding([2, 6])
            .style(|_| container::Style {
                background: Some(Background::Color(colors::CYAN)),
                border: Border {
                    radius: 8.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
        ]
        .align_y(Alignment::Center)
        .into()
    } else {
        row![
            text("\u{1F4CB}").size(12), // 📋
            Space::with_width(6),
            text("SCANS").size(10),
        ]
        .align_y(Alignment::Center)
        .into()
    };

    let scans_btn = button(scans_content)
        .on_press(Message::ShowScansDashboard)
        .padding([6, 12])
        .style(|_theme, status| {
            let base = iced::widget::button::Style {
                background: Some(Background::Color(Color::from_rgba(0.13, 0.83, 0.93, 0.1))),
                text_color: colors::CYAN,
                border: Border {
                    color: Color::from_rgba(0.13, 0.83, 0.93, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            };

            match status {
                iced::widget::button::Status::Hovered => iced::widget::button::Style {
                    background: Some(Background::Color(Color::from_rgba(0.13, 0.83, 0.93, 0.2))),
                    ..base
                },
                _ => base,
            }
        });

    // Scan button
    let scan_btn = button(
        row![
            text(if is_scanning { "\u{27F3}" } else { "\u{1F50D}" }).size(12), // 🔍 or ⟳
            Space::with_width(6),
            text(if is_scanning { "SCANNING..." } else { "SCAN NETWORK" }).size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::ScanNetwork)
    .padding([6, 16])
    .style(if is_scanning {
        theme::secondary_button_style
    } else {
        theme::primary_button_style
    });

    // Refresh button
    let refresh_btn = button(
        row![
            text("\u{21BB}").size(12), // ↻
            Space::with_width(6),
            text("REFRESH").size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::RefreshAll)
    .padding([6, 12])
    .style(theme::secondary_button_style);

    // Traffic button
    let traffic_btn = button(
        row![
            text("\u{1F4CA}").size(12), // 📊
            Space::with_width(6),
            text("TRAFFIC").size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::ShowTrafficDashboard)
    .padding([6, 12])
    .style(theme::secondary_button_style);

    // Browsing metrics button
    let browsing_btn = button(
        row![
            text("\u{1F310}").size(12), // 🌐
            Space::with_width(6),
            text("BROWSING").size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::ShowBrowsingDashboard)
    .padding([6, 12])
    .style(theme::secondary_button_style);

    // Tools button
    let tools_btn = button(
        row![
            text("\u{1F527}").size(12), // 🔧
            Space::with_width(6),
            text("TOOLS").size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::ShowToolsDashboard)
    .padding([6, 12])
    .style(theme::secondary_button_style);

    // Scheduler button
    let scheduler_btn = button(
        row![
            text("\u{1F4C5}").size(12), // 📅
            Space::with_width(6),
            text("SCHEDULE").size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::ShowSchedulerDashboard)
    .padding([6, 12])
    .style(theme::secondary_button_style);

    // Settings button
    let settings_btn = button(
        row![
            text("\u{2699}").size(12), // ⚙
            Space::with_width(6),
            text("SETTINGS").size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::ShowSettings)
    .padding([6, 12])
    .style(theme::secondary_button_style);

    // Load button
    let load_btn = button(
        row![
            text("\u{1F4C2}").size(12), // 📂
            Space::with_width(6),
            text("LOAD").size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::LoadProject)
    .padding([6, 12])
    .style(theme::secondary_button_style);

    // Save button
    let save_btn = button(
        row![
            text("\u{1F4BE}").size(12), // 💾
            Space::with_width(6),
            text("SAVE").size(10),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::SaveProject)
    .padding([6, 12])
    .style(theme::secondary_button_style);

    // Terminal toggle
    let terminal_btn = button(text("Terminal").size(10))
        .on_press(Message::ToggleTerminalPanel)
        .padding([6, 12])
        .style(theme::secondary_button_style);

    // Inspector toggle
    let inspector_btn = button(text("Inspector").size(10))
        .on_press(Message::ToggleInspectorPanel)
        .padding([6, 12])
        .style(theme::secondary_button_style);

    let content = row![
        title_section,
        Space::with_width(Length::Fill),
        vuln_btn,
        Space::with_width(4),
        alerts_btn,
        Space::with_width(4),
        scans_btn,
        Space::with_width(4),
        traffic_btn,
        Space::with_width(4),
        browsing_btn,
        Space::with_width(4),
        tools_btn,
        Space::with_width(4),
        scheduler_btn,
        Space::with_width(12),
        scan_btn,
        Space::with_width(4),
        refresh_btn,
        Space::with_width(12),
        load_btn,
        Space::with_width(4),
        save_btn,
        Space::with_width(4),
        settings_btn,
        Space::with_width(12),
        terminal_btn,
        Space::with_width(4),
        inspector_btn,
    ]
    .padding([8, 16])
    .align_y(Alignment::Center);

    container(content)
        .width(Length::Fill)
        .height(Length::Fixed(56.0))
        .style(theme::panel_style)
        .into()
}
