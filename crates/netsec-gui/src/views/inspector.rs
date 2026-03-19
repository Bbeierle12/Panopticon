//! Device inspector panel with tabs.

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::message::{InspectorTab, Message, NodeId, Severity};
use crate::state::network::{Connection, NetworkState, Node};
use crate::theme::{self, colors};

/// Fixed width for the inspector panel.
pub const INSPECTOR_WIDTH: f32 = 280.0;

/// Render a tab button.
fn tab_button<'a>(
    label: &'a str,
    icon: &'a str,
    tab: InspectorTab,
    active_tab: InspectorTab,
) -> Element<'a, Message> {
    let is_active = tab == active_tab;

    button(
        row![
            text(icon).size(10),
            Space::with_width(4),
            text(label).size(9),
        ]
        .align_y(Alignment::Center)
    )
    .on_press(Message::SetInspectorTab(tab))
    .padding([8, 12])
    .width(Length::FillPortion(1))
    .style(move |_, status| {
        let bg = if is_active {
            Color::from_rgba(0.13, 0.83, 0.93, 0.05)
        } else if matches!(status, iced::widget::button::Status::Hovered) {
            Color::from_rgba(1.0, 1.0, 1.0, 0.05)
        } else {
            Color::TRANSPARENT
        };

        iced::widget::button::Style {
            background: Some(Background::Color(bg)),
            text_color: if is_active { colors::CYAN } else { colors::TEXT_MUTED },
            border: Border {
                color: if is_active { colors::CYAN } else { Color::TRANSPARENT },
                width: if is_active { 2.0 } else { 0.0 },
                radius: 0.0.into(),
            },
            ..Default::default()
        }
    })
    .into()
}

/// Render a key-value row.
fn info_row<'a>(key: &'a str, value: &'a str, value_color: Color) -> Element<'a, Message> {
    row![
        text(key)
            .size(9)
            .color(colors::TEXT_MUTED),
        Space::with_width(Length::Fill),
        text(value)
            .size(10)
            .color(value_color),
    ]
    .into()
}

/// Render the details tab content.
fn view_details<'a>(node: &'a Node, network: &'a NetworkState) -> Element<'a, Message> {
    let mut content = column![].spacing(12);

    // Status indicator
    let status_color = match node.status {
        crate::message::NodeStatus::Online => colors::GREEN,
        crate::message::NodeStatus::Warning => colors::YELLOW,
        crate::message::NodeStatus::Compromised => colors::RED,
        crate::message::NodeStatus::Offline => colors::TEXT_MUTED,
    };

    let _status_text = match node.status {
        crate::message::NodeStatus::Online => "ONLINE",
        crate::message::NodeStatus::Warning => "WARNING",
        crate::message::NodeStatus::Compromised => "COMPROMISED",
        crate::message::NodeStatus::Offline => "OFFLINE",
    };

    // Header with status
    let header = row![
        container(Space::with_width(8).height(8))
            .style(move |_| container::Style {
                background: Some(Background::Color(status_color)),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
        Space::with_width(8),
        text(&node.label)
            .size(16)
            .color(if matches!(node.status, crate::message::NodeStatus::Compromised) {
                colors::RED
            } else {
                colors::TEXT_PRIMARY
            }),
    ]
    .align_y(Alignment::Center);

    let node_type = text(node.node_type.label())
        .size(9)
        .color(colors::CYAN);

    content = content.push(header);
    content = content.push(node_type);
    content = content.push(Space::with_height(8));

    // Security breach alert
    if matches!(node.status, crate::message::NodeStatus::Compromised) {
        let alert = container(
            column![
                row![
                    text("\u{26A0}").size(12).color(colors::RED),
                    Space::with_width(8),
                    text("SECURITY BREACH")
                        .size(9)
                        .color(colors::RED),
                ]
                .align_y(Alignment::Center),
                Space::with_height(4),
                text("Target has been successfully exploited.")
                    .size(9)
                    .color(Color::from_rgba(1.0, 0.5, 0.5, 0.8)),
            ]
        )
        .padding(12)
        .width(Length::Fill)
        .style(|_| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.94, 0.27, 0.27, 0.1))),
            border: Border {
                color: Color::from_rgba(0.94, 0.27, 0.27, 0.3),
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        });
        content = content.push(alert);
    }

    // Vulnerabilities section
    if !node.vulnerabilities.is_empty() {
        content = content.push(
            text("DETECTED VULNERABILITIES")
                .size(9)
                .color(colors::TEXT_MUTED)
        );

        for vuln in &node.vulnerabilities {
            let severity_color = match vuln.severity {
                Severity::Critical => colors::RED,
                Severity::High => colors::ORANGE,
                Severity::Medium => colors::YELLOW,
                Severity::Low => Color::from_rgb(0.23, 0.51, 0.95),
            };

            let vuln_card = container(
                column![
                    row![
                        text(&vuln.cve)
                            .size(10)
                            .color(colors::TEXT_PRIMARY),
                        Space::with_width(8),
                        container(
                            text(vuln.severity.label())
                                .size(7)
                                .color(Color::WHITE)
                        )
                        .padding([2, 4])
                        .style(move |_| container::Style {
                            background: Some(Background::Color(severity_color)),
                            border: Border {
                                radius: 2.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                        Space::with_width(Length::Fill),
                        text(format!("CVSS {:.1}", vuln.cvss))
                            .size(9)
                            .color(severity_color),
                    ]
                    .align_y(Alignment::Center),
                    Space::with_height(4),
                    text(&vuln.description)
                        .size(8)
                        .color(colors::TEXT_MUTED),
                ]
            )
            .padding(8)
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.03))),
                border: Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            });
            content = content.push(vuln_card);
        }
    } else {
        // No vulnerabilities
        let empty = container(
            column![
                text("\u{2714}").size(24).color(colors::GREEN), // ✔
                Space::with_height(8),
                text("No Vulnerabilities Detected")
                    .size(9)
                    .color(colors::TEXT_MUTED),
            ]
            .align_x(Alignment::Center)
        )
        .padding(16)
        .width(Length::Fill)
        .style(|_| container::Style {
            border: Border {
                color: colors::BORDER,
                width: 1.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        });
        content = content.push(empty);
    }

    // Open ports
    if !node.ports.is_empty() {
        content = content.push(Space::with_height(8));
        content = content.push(
            row![
                text("\u{2261}").size(12).color(colors::GREEN), // ≡
                Space::with_width(8),
                text("OPEN PORTS")
                    .size(9)
                    .color(colors::TEXT_MUTED),
            ]
            .align_y(Alignment::Center)
        );

        for port in &node.ports {
            let port_row = container(
                row![
                    text(format!("{}/{}", port.number, port.protocol))
                        .size(10)
                        .color(colors::GREEN),
                    Space::with_width(8),
                    container(
                        text(&port.state)
                            .size(7)
                            .color(colors::GREEN)
                    )
                    .padding([2, 4])
                    .style(|_| container::Style {
                        background: Some(Background::Color(Color::from_rgba(0.13, 0.77, 0.37, 0.2))),
                        border: Border {
                            radius: 2.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    Space::with_width(Length::Fill),
                    text(port.service_name.as_deref().unwrap_or("-"))
                        .size(9)
                        .color(colors::TEXT_MUTED),
                ]
                .align_y(Alignment::Center)
            )
            .padding([4, 8])
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.13, 0.77, 0.37, 0.05))),
                border: Border {
                    color: Color::from_rgba(0.13, 0.77, 0.37, 0.2),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            });
            content = content.push(port_row);
        }
    }

    // Device info section
    content = content.push(Space::with_height(8));
    let info_section = container(
        column![
            info_row("Address", &node.ip, colors::TEXT_PRIMARY),
            if let Some(ref vendor) = node.vendor {
                info_row("Vendor", vendor, colors::CYAN)
            } else {
                info_row("Vendor", "Unknown", colors::TEXT_MUTED)
            },
            if let Some(ref os) = node.os_family {
                info_row("OS", os, colors::TEXT_SECONDARY)
            } else {
                info_row("OS", "Unknown", colors::TEXT_MUTED)
            },
        ]
        .spacing(6)
    )
    .padding(12)
    .width(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.03))),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    });
    content = content.push(info_section);

    // Isolate button
    content = content.push(Space::with_height(8));
    let isolate_btn = button(
        row![
            text("\u{1F512}").size(10), // 🔒
            Space::with_width(8),
            text("ISOLATE HARDWARE").size(9),
        ]
        .align_y(Alignment::Center)
    )
    .padding([10, 16])
    .width(Length::Fill)
    .style(|_, status| {
        let bg = if matches!(status, iced::widget::button::Status::Hovered) {
            Color::from_rgba(0.94, 0.27, 0.27, 0.2)
        } else {
            Color::from_rgba(0.94, 0.27, 0.27, 0.1)
        };
        iced::widget::button::Style {
            background: Some(Background::Color(bg)),
            text_color: colors::RED,
            border: Border {
                color: Color::from_rgba(0.94, 0.27, 0.27, 0.3),
                width: 1.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        }
    });
    content = content.push(isolate_btn);

    scrollable(content)
        .height(Length::Fill)
        .into()
}

/// Render the connections tab content.
fn view_connections<'a>(node: &'a Node, network: &'a NetworkState) -> Element<'a, Message> {
    let connections = network.connections_for_node(node.id);

    if connections.is_empty() {
        return container(
            column![
                text("No Active Connections")
                    .size(10)
                    .color(colors::TEXT_MUTED),
            ]
            .align_x(Alignment::Center)
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into();
    }

    let mut content = column![].spacing(8);

    for conn in connections {
        let other_id = if conn.from == node.id { conn.to } else { conn.from };
        let other_node = network.get_node(other_id);

        if let Some(other) = other_node {
            let status_color = match other.status {
                crate::message::NodeStatus::Online => colors::GREEN,
                _ => colors::RED,
            };

            let conn_type_label = match conn.connection_type {
                crate::message::ConnectionType::Wired => "WIRED",
                crate::message::ConnectionType::Wireless => "WIRELESS",
            };

            let conn_card = container(
                column![
                    row![
                        container(Space::with_width(6).height(6))
                            .style(move |_| container::Style {
                                background: Some(Background::Color(status_color)),
                                border: Border {
                                    radius: 3.0.into(),
                                    ..Default::default()
                                },
                                ..Default::default()
                            }),
                        Space::with_width(8),
                        column![
                            text(&other.label)
                                .size(11)
                                .color(colors::TEXT_PRIMARY),
                            text(&other.ip)
                                .size(8)
                                .color(colors::TEXT_MUTED),
                        ],
                        Space::with_width(Length::Fill),
                        container(
                            text(conn_type_label)
                                .size(7)
                                .color(colors::CYAN)
                        )
                        .padding([2, 6])
                        .style(|_| container::Style {
                            background: Some(Background::Color(Color::from_rgba(0.13, 0.83, 0.93, 0.1))),
                            border: Border {
                                radius: 4.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                    ]
                    .align_y(Alignment::Center),
                ]
            )
            .padding(12)
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.03))),
                border: Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            });

            content = content.push(conn_card);
        }
    }

    scrollable(content)
        .height(Length::Fill)
        .into()
}

/// Render the traffic tab content (placeholder).
fn view_traffic<'a>(node: &'a Node, network: &'a NetworkState) -> Element<'a, Message> {
    let connections = network.connections_for_node(node.id);

    if connections.is_empty() {
        return container(
            text("No Active Connections")
                .size(10)
                .color(colors::TEXT_MUTED)
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into();
    }

    let mut content = column![].spacing(12);

    for conn in connections {
        let other_id = if conn.from == node.id { conn.to } else { conn.from };
        let other_node = network.get_node(other_id);

        if let Some(other) = other_node {
            let traffic_bar = container(
                column![
                    row![
                        text(format!("LINK: {}", other.label))
                            .size(9)
                            .color(colors::TEXT_MUTED),
                        Space::with_width(Length::Fill),
                        text("LIVE")
                            .size(8)
                            .color(colors::CYAN),
                    ],
                    Space::with_height(8),
                    // Traffic bar visualization
                    container(
                        row![
                            container(Space::with_width(Length::FillPortion((conn.traffic * 10.0) as u16)))
                                .height(Length::Fixed(4.0))
                                .style(|_| container::Style {
                                    background: Some(Background::Color(colors::CYAN)),
                                    border: Border {
                                        radius: 2.0.into(),
                                        ..Default::default()
                                    },
                                    ..Default::default()
                                }),
                            Space::with_width(Length::Fill),
                        ]
                    )
                    .width(Length::Fill)
                    .height(Length::Fixed(4.0))
                    .style(|_| container::Style {
                        background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.1))),
                        border: Border {
                            radius: 2.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                    Space::with_height(4),
                    text(format!("{:.1} MB/s", conn.traffic))
                        .size(9)
                        .color(colors::CYAN),
                ]
            )
            .padding(12)
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.03))),
                border: Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            });

            content = content.push(traffic_bar);
        }
    }

    scrollable(content)
        .height(Length::Fill)
        .into()
}

/// Render the device inspector panel.
pub fn view<'a>(
    network: &'a NetworkState,
    active_tab: InspectorTab,
) -> Element<'a, Message> {
    let selected = network.selected_node();

    // Header
    let header = container(
        text("Inspector")
            .size(12)
            .color(colors::TEXT_MUTED)
    )
    .padding([12, 16]);

    if let Some(node) = selected {
        // Tab bar
        let tabs = row![
            tab_button("Details", "\u{1F4CB}", InspectorTab::Details, active_tab),
            tab_button("Links", "\u{1F517}", InspectorTab::Connections, active_tab),
            tab_button("Traffic", "\u{1F4CA}", InspectorTab::Traffic, active_tab),
        ];

        // Tab content
        let tab_content = container(
            match active_tab {
                InspectorTab::Details => view_details(node, network),
                InspectorTab::Connections => view_connections(node, network),
                InspectorTab::Traffic => view_traffic(node, network),
            }
        )
        .padding(16);

        container(
            column![
                header,
                container(tabs)
                    .width(Length::Fill)
                    .style(|_| container::Style {
                        border: Border {
                            color: colors::BORDER,
                            width: 1.0,
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                tab_content,
            ]
        )
        .width(Length::Fixed(INSPECTOR_WIDTH))
        .height(Length::Fill)
        .style(theme::panel_style)
        .into()
    } else {
        // No selection
        container(
            column![
                header,
                container(
                    column![
                        text("\u{1F50D}").size(32).color(Color::from_rgba(1.0, 1.0, 1.0, 0.1)),
                        Space::with_height(16),
                        text("Select a device to inspect")
                            .size(11)
                            .color(colors::TEXT_MUTED),
                    ]
                    .align_x(Alignment::Center)
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
            ]
        )
        .width(Length::Fixed(INSPECTOR_WIDTH))
        .height(Length::Fill)
        .style(theme::panel_style)
        .into()
    }
}
