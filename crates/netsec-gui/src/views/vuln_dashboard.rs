//! Vulnerability dashboard modal view.

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::message::{Message, Severity};
use crate::state::network::{NetworkState, Vulnerability};
use crate::theme::colors;

/// Get severity badge color.
fn severity_color(severity: &Severity) -> Color {
    match severity {
        Severity::Critical => colors::RED,
        Severity::High => colors::ORANGE,
        Severity::Medium => colors::YELLOW,
        Severity::Low => Color::from_rgb(0.23, 0.51, 0.95), // Blue
    }
}

/// Render a vulnerability card.
fn vuln_card<'a>(
    vuln: &'a Vulnerability,
    node_label: &'a str,
    node_ip: &'a str,
) -> Element<'a, Message> {
    let severity_badge = container(
        column![
            text(format!("{:.1}", vuln.cvss))
                .size(14)
                .color(Color::WHITE),
            text("CVSS")
                .size(7)
                .color(Color::from_rgba(1.0, 1.0, 1.0, 0.7)),
        ]
        .align_x(Alignment::Center)
    )
    .padding([8, 12])
    .style(move |_| container::Style {
        background: Some(Background::Color(severity_color(&vuln.severity))),
        border: Border {
            radius: 6.0.into(),
            ..Default::default()
        },
        ..Default::default()
    });

    let severity_label = container(
        text(vuln.severity.label())
            .size(8)
            .color(severity_color(&vuln.severity))
    )
    .padding([2, 6])
    .style(move |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(
            severity_color(&vuln.severity).r,
            severity_color(&vuln.severity).g,
            severity_color(&vuln.severity).b,
            0.2,
        ))),
        border: Border {
            color: severity_color(&vuln.severity),
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    });

    let header = row![
        text(&vuln.cve)
            .size(12)
            .color(colors::TEXT_PRIMARY),
        Space::with_width(8),
        severity_label,
    ]
    .align_y(Alignment::Center);

    let description = text(&vuln.description)
        .size(10)
        .color(colors::TEXT_SECONDARY);

    let device_info = row![
        text("\u{1F4BB}").size(10), // 💻
        Space::with_width(6),
        text(node_label)
            .size(10)
            .color(colors::CYAN),
        Space::with_width(8),
        container(
            text(node_ip)
                .size(9)
                .color(colors::TEXT_MUTED)
        )
        .padding([2, 6])
        .style(|_| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.3))),
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
    ]
    .align_y(Alignment::Center);

    let main_content = column![
        header,
        Space::with_height(6),
        description,
        Space::with_height(8),
        device_info,
    ]
    .width(Length::Fill);

    container(
        row![
            severity_badge,
            Space::with_width(16),
            main_content,
        ]
        .align_y(Alignment::Start)
    )
    .padding(16)
    .width(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.03))),
        border: Border {
            color: Color::from_rgba(1.0, 1.0, 1.0, 0.05),
            width: 1.0,
            radius: 6.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Render the vulnerability dashboard.
pub fn view<'a>(
    network: &'a NetworkState,
    filter_severity: Option<Severity>,
    search_query: &'a str,
) -> Element<'a, Message> {
    let all_vulns = network.all_vulnerabilities();
    let (critical, high, medium, low) = network.vuln_counts();
    let total = critical + high + medium + low;

    // Header
    let header = row![
        container(
            text("\u{26A0}")  // ⚠
                .size(20)
                .color(colors::RED)
        )
        .padding([8, 12])
        .style(|_| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.94, 0.27, 0.27, 0.2))),
            border: Border {
                radius: 8.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
        Space::with_width(16),
        column![
            text("GLOBAL VULNERABILITY REPORT")
                .size(18)
                .color(colors::TEXT_PRIMARY),
            text(format!("{} Issues Detected Across {} Assets", total, network.nodes.len()))
                .size(10)
                .color(colors::TEXT_MUTED),
        ],
        Space::with_width(Length::Fill),
        button(
            text("\u{2716}").size(18).color(colors::TEXT_MUTED) // ✖
        )
        .on_press(Message::HideVulnDashboard)
        .padding([8, 12])
        .style(|_theme: &iced::Theme, status| {
            let mut style = iced::widget::button::Style {
                background: Some(Background::Color(Color::TRANSPARENT)),
                text_color: colors::TEXT_MUTED,
                ..Default::default()
            };
            if matches!(status, iced::widget::button::Status::Hovered) {
                style.background = Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.1)));
            }
            style
        }),
    ]
    .align_y(Alignment::Center)
    .padding([16, 24]);

    // Filter toolbar
    let filter_btn = |sev: Option<Severity>, label: &'a str, count: usize, color: Color| {
        let is_active = filter_severity == sev;
        button(
            row![
                text(label).size(9).color(if is_active { Color::WHITE } else { color }),
                Space::with_width(4),
                text(count.to_string()).size(9).color(if is_active { Color::WHITE } else { colors::TEXT_MUTED }),
            ]
        )
        .on_press(Message::VulnFilterSeverity(sev))
        .padding([6, 12])
        .style(move |_, status| {
            let bg = if is_active {
                color
            } else if matches!(status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(color.r, color.g, color.b, 0.2)
            } else {
                Color::TRANSPARENT
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: if is_active { Color::WHITE } else { color },
                border: Border {
                    color: Color::from_rgba(color.r, color.g, color.b, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        })
    };

    let filters = row![
        text("Filter:").size(9).color(colors::TEXT_MUTED),
        Space::with_width(8),
        filter_btn(None, "ALL", total, colors::CYAN),
        Space::with_width(4),
        filter_btn(Some(Severity::Critical), "CRITICAL", critical, colors::RED),
        Space::with_width(4),
        filter_btn(Some(Severity::High), "HIGH", high, colors::ORANGE),
        Space::with_width(4),
        filter_btn(Some(Severity::Medium), "MEDIUM", medium, colors::YELLOW),
        Space::with_width(4),
        filter_btn(Some(Severity::Low), "LOW", low, Color::from_rgb(0.23, 0.51, 0.95)),
        Space::with_width(Length::Fill),
        text_input("Search device or IP...", search_query)
            .on_input(Message::VulnSearch)
            .padding([6, 12])
            .width(Length::Fixed(200.0))
            .size(10),
    ]
    .align_y(Alignment::Center)
    .padding([12, 24]);

    // Filter vulnerabilities
    let filtered_vulns: Vec<_> = all_vulns
        .iter()
        .filter(|(node, vuln)| {
            // Filter by severity
            if let Some(ref sev) = filter_severity {
                if &vuln.severity != sev {
                    return false;
                }
            }
            // Filter by search
            if !search_query.is_empty() {
                let query = search_query.to_lowercase();
                if !node.label.to_lowercase().contains(&query)
                    && !node.ip.to_lowercase().contains(&query)
                    && !vuln.cve.to_lowercase().contains(&query)
                {
                    return false;
                }
            }
            true
        })
        .collect();

    // Vulnerability list
    let vuln_list: Element<'a, Message> = if filtered_vulns.is_empty() {
        container(
            column![
                text("\u{26A0}").size(48).color(Color::from_rgba(1.0, 1.0, 1.0, 0.1)),
                Space::with_height(16),
                text("No matching vulnerabilities found")
                    .size(12)
                    .color(colors::TEXT_MUTED),
            ]
            .align_x(Alignment::Center)
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
    } else {
        let mut cards = column![].spacing(8);
        for (node, vuln) in filtered_vulns {
            cards = cards.push(vuln_card(vuln, &node.label, &node.ip));
        }
        scrollable(
            container(cards)
                .padding([12, 24])
                .width(Length::Fill)
        )
        .height(Length::Fill)
        .into()
    };

    // Main content
    let content = column![
        header,
        container(Space::with_height(1))
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(colors::BORDER)),
                ..Default::default()
            }),
        filters,
        container(Space::with_height(1))
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(colors::BORDER)),
                ..Default::default()
            }),
        vuln_list,
    ];

    // Modal overlay
    container(
        container(content)
            .width(Length::Fixed(900.0))
            .height(Length::Fixed(600.0))
            .style(|_| container::Style {
                background: Some(Background::Color(colors::BG_PRIMARY)),
                border: Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..Default::default()
            })
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.8))),
        ..Default::default()
    })
    .into()
}
