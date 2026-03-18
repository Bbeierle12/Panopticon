//! Alerts dashboard view with filtering and details.

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::api::{Alert, AlertStats};
use crate::message::Message;
use crate::theme::colors;

/// Alert severity for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl AlertSeverity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Info,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }

    pub fn color(&self) -> Color {
        match self {
            Self::Critical => colors::RED,
            Self::High => colors::ORANGE,
            Self::Medium => colors::YELLOW,
            Self::Low => Color::from_rgb(0.23, 0.51, 0.95),
            Self::Info => colors::CYAN,
        }
    }
}

/// Alert status for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Resolved,
    Dismissed,
}

impl AlertStatus {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "open" | "active" => Self::Open,
            "acknowledged" | "ack" => Self::Acknowledged,
            "resolved" | "closed" => Self::Resolved,
            "dismissed" | "ignored" => Self::Dismissed,
            _ => Self::Open,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Acknowledged => "ACK",
            Self::Resolved => "RESOLVED",
            Self::Dismissed => "DISMISSED",
        }
    }

    pub fn color(&self) -> Color {
        match self {
            Self::Open => colors::RED,
            Self::Acknowledged => colors::YELLOW,
            Self::Resolved => colors::GREEN,
            Self::Dismissed => colors::TEXT_MUTED,
        }
    }
}

/// Render a severity badge.
fn severity_badge<'a>(severity: AlertSeverity) -> Element<'a, Message> {
    container(
        text(severity.label())
            .size(8)
            .color(Color::WHITE)
    )
    .padding([3, 6])
    .style(move |_| container::Style {
        background: Some(Background::Color(severity.color())),
        border: Border {
            radius: 3.0.into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .into()
}

/// Render a status badge.
fn status_badge<'a>(status: AlertStatus) -> Element<'a, Message> {
    container(
        text(status.label())
            .size(7)
            .color(status.color())
    )
    .padding([2, 5])
    .style(move |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(
            status.color().r,
            status.color().g,
            status.color().b,
            0.15,
        ))),
        border: Border {
            color: Color::from_rgba(
                status.color().r,
                status.color().g,
                status.color().b,
                0.3,
            ),
            width: 1.0,
            radius: 3.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Render an alert card.
fn alert_card(alert: &Alert, is_selected: bool) -> Element<'_, Message> {
    let severity = AlertSeverity::from_str(&alert.severity);
    let status = AlertStatus::from_str(&alert.status);

    // Time ago calculation
    let time_ago = {
        let now = chrono::Utc::now();
        let diff = now.signed_duration_since(alert.last_seen);
        if diff.num_days() > 0 {
            format!("{}d ago", diff.num_days())
        } else if diff.num_hours() > 0 {
            format!("{}h ago", diff.num_hours())
        } else if diff.num_minutes() > 0 {
            format!("{}m ago", diff.num_minutes())
        } else {
            "just now".to_string()
        }
    };

    // Header row with title and badges
    let header = row![
        severity_badge(severity),
        Space::with_width(8),
        text(alert.title.clone())
            .size(11)
            .color(colors::TEXT_PRIMARY),
        Space::with_width(Length::Fill),
        status_badge(status),
    ]
    .align_y(Alignment::Center);

    // Description
    let description = if let Some(ref desc) = alert.description {
        text(desc.clone())
            .size(9)
            .color(colors::TEXT_SECONDARY)
    } else {
        text("")
            .size(9)
    };

    // Metadata row - build with owned values
    let source_tool = alert.source_tool.clone();
    let device_ip = alert.device_ip.clone();
    let count = alert.count;

    let mut meta_row_content = row![
        text("\u{2699}").size(9).color(colors::TEXT_MUTED), // ⚙
        Space::with_width(4),
        text(source_tool)
            .size(8)
            .color(colors::CYAN),
    ]
    .align_y(Alignment::Center);

    // Device IP if present
    if let Some(ip) = device_ip {
        meta_row_content = meta_row_content.push(Space::with_width(12));
        meta_row_content = meta_row_content.push(
            row![
                text("\u{1F4BB}").size(9).color(colors::TEXT_MUTED), // 💻
                Space::with_width(4),
                text(ip)
                    .size(8)
                    .color(colors::TEXT_SECONDARY),
            ]
            .align_y(Alignment::Center)
        );
    }

    // Count if > 1
    if count > 1 {
        meta_row_content = meta_row_content.push(Space::with_width(12));
        meta_row_content = meta_row_content.push(
            container(
                text(format!("x{}", count))
                    .size(8)
                    .color(colors::ORANGE)
            )
            .padding([2, 4])
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(1.0, 0.6, 0.0, 0.1))),
                border: Border {
                    radius: 3.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            })
        );
    }

    meta_row_content = meta_row_content.push(Space::with_width(Length::Fill));
    meta_row_content = meta_row_content.push(
        text(time_ago)
            .size(8)
            .color(colors::TEXT_MUTED)
    );

    let meta_row = meta_row_content;

    // Card content
    let content = column![
        header,
        Space::with_height(6),
        description,
        Space::with_height(8),
        meta_row,
    ];

    // Card with selection style
    let bg_color = if is_selected {
        Color::from_rgba(0.13, 0.83, 0.93, 0.1)
    } else {
        Color::from_rgba(1.0, 1.0, 1.0, 0.02)
    };

    let border_color = if is_selected {
        colors::CYAN
    } else {
        colors::BORDER
    };

    button(
        container(content)
            .padding(12)
            .width(Length::Fill)
    )
    .on_press(Message::AlertSelected(alert.id.clone()))
    .padding(0)
    .width(Length::Fill)
    .style(move |_, status| {
        let bg = if matches!(status, iced::widget::button::Status::Hovered) && !is_selected {
            Color::from_rgba(1.0, 1.0, 1.0, 0.05)
        } else {
            bg_color
        };
        iced::widget::button::Style {
            background: Some(Background::Color(bg)),
            text_color: colors::TEXT_PRIMARY,
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        }
    })
    .into()
}

/// Render the alert detail panel.
fn alert_detail(alert: &Alert) -> Element<'_, Message> {
    let severity = AlertSeverity::from_str(&alert.severity);
    let status = AlertStatus::from_str(&alert.status);

    // Header
    let header = column![
        row![
            severity_badge(severity),
            Space::with_width(8),
            status_badge(status),
        ],
        Space::with_height(12),
        text(alert.title.clone())
            .size(16)
            .color(colors::TEXT_PRIMARY),
    ];

    // Description
    let description = if let Some(ref desc) = alert.description {
        column![
            Space::with_height(12),
            text(desc.clone())
                .size(10)
                .color(colors::TEXT_SECONDARY),
        ]
    } else {
        column![]
    };

    // Info rows helper - takes owned strings
    let info_row_owned = |label: &'static str, value: String, value_color: Color| -> Element<'_, Message> {
        row![
            text(label)
                .size(9)
                .color(colors::TEXT_MUTED)
                .width(Length::Fixed(100.0)),
            text(value)
                .size(10)
                .color(value_color),
        ]
        .into()
    };

    let mut info_section = column![].spacing(8);

    info_section = info_section.push(info_row_owned("Source Tool", alert.source_tool.clone(), colors::CYAN));

    if let Some(ref ip) = alert.device_ip {
        info_section = info_section.push(info_row_owned("Device IP", ip.clone(), colors::TEXT_PRIMARY));
    }

    if let Some(ref category) = alert.category {
        info_section = info_section.push(info_row_owned("Category", category.clone(), colors::TEXT_SECONDARY));
    }

    info_section = info_section.push(info_row_owned(
        "First Seen",
        alert.first_seen.format("%Y-%m-%d %H:%M").to_string(),
        colors::TEXT_SECONDARY,
    ));

    info_section = info_section.push(info_row_owned(
        "Last Seen",
        alert.last_seen.format("%Y-%m-%d %H:%M").to_string(),
        colors::TEXT_SECONDARY,
    ));

    info_section = info_section.push(info_row_owned(
        "Count",
        alert.count.to_string(),
        if alert.count > 1 { colors::ORANGE } else { colors::TEXT_SECONDARY },
    ));

    // Action buttons
    let action_buttons = row![
        button(
            text("Acknowledge").size(9)
        )
        .on_press(Message::AcknowledgeAlert(alert.id.clone()))
        .padding([8, 16])
        .style(|_, status| {
            let bg = if matches!(status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(1.0, 0.8, 0.0, 0.2)
            } else {
                Color::from_rgba(1.0, 0.8, 0.0, 0.1)
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::YELLOW,
                border: Border {
                    color: Color::from_rgba(1.0, 0.8, 0.0, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        }),
        Space::with_width(8),
        button(
            text("Resolve").size(9)
        )
        .on_press(Message::ResolveAlert(alert.id.clone()))
        .padding([8, 16])
        .style(|_, status| {
            let bg = if matches!(status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(0.13, 0.77, 0.37, 0.2)
            } else {
                Color::from_rgba(0.13, 0.77, 0.37, 0.1)
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::GREEN,
                border: Border {
                    color: Color::from_rgba(0.13, 0.77, 0.37, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        }),
        Space::with_width(8),
        button(
            text("Dismiss").size(9)
        )
        .on_press(Message::DismissAlert(alert.id.clone()))
        .padding([8, 16])
        .style(|_, status| {
            let bg = if matches!(status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(1.0, 1.0, 1.0, 0.1)
            } else {
                Color::TRANSPARENT
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::TEXT_MUTED,
                border: Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        }),
    ];

    // Raw data section is simplified - show key count instead of full JSON
    // to avoid lifetime issues with local string formatting
    let raw_data_section = if let Some(ref raw) = alert.raw_data {
        if !raw.is_empty() {
            let key_count = raw.len();
            column![
                Space::with_height(16),
                text("Raw Data")
                    .size(9)
                    .color(colors::TEXT_MUTED),
                Space::with_height(8),
                container(
                    text(format!("{} data fields available", key_count))
                        .size(9)
                        .color(colors::TEXT_SECONDARY)
                )
                .padding(12)
                .width(Length::Fill)
                .style(|_| container::Style {
                    background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.3))),
                    border: Border {
                        color: colors::BORDER,
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                }),
            ]
        } else {
            column![]
        }
    } else {
        column![]
    };

    container(
        scrollable(
            column![
                header,
                description,
                Space::with_height(16),
                container(info_section)
                    .padding(12)
                    .width(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.02))),
                        border: Border {
                            color: colors::BORDER,
                            width: 1.0,
                            radius: 4.0.into(),
                        },
                        ..Default::default()
                    }),
                Space::with_height(16),
                action_buttons,
                raw_data_section,
            ]
            .padding(16)
        )
        .height(Length::Fill)
    )
    .width(Length::Fixed(350.0))
    .height(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(colors::BG_SECONDARY)),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            ..Default::default()
        },
        ..Default::default()
    })
    .into()
}

/// Render the stats bar.
fn stats_bar<'a>(stats: Option<&'a AlertStats>, total: usize) -> Element<'a, Message> {
    let (critical, high, medium, low) = if let Some(s) = stats {
        (
            s.open_by_severity.get("critical").copied().unwrap_or(0),
            s.open_by_severity.get("high").copied().unwrap_or(0),
            s.open_by_severity.get("medium").copied().unwrap_or(0),
            s.open_by_severity.get("low").copied().unwrap_or(0),
        )
    } else {
        (0, 0, 0, 0)
    };

    let stat_box = |label: &'a str, count: i32, color: Color| -> Element<'a, Message> {
        container(
            column![
                text(count.to_string())
                    .size(18)
                    .color(color),
                text(label)
                    .size(8)
                    .color(colors::TEXT_MUTED),
            ]
            .align_x(Alignment::Center)
        )
        .padding([8, 16])
        .style(move |_| container::Style {
            background: Some(Background::Color(Color::from_rgba(color.r, color.g, color.b, 0.1))),
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
    };

    row![
        stat_box("CRITICAL", critical, colors::RED),
        Space::with_width(8),
        stat_box("HIGH", high, colors::ORANGE),
        Space::with_width(8),
        stat_box("MEDIUM", medium, colors::YELLOW),
        Space::with_width(8),
        stat_box("LOW", low, Color::from_rgb(0.23, 0.51, 0.95)),
        Space::with_width(Length::Fill),
        text(format!("{} total alerts", total))
            .size(10)
            .color(colors::TEXT_MUTED),
    ]
    .align_y(Alignment::Center)
    .into()
}

/// Render the alerts dashboard.
pub fn view<'a>(
    alerts: &'a [Alert],
    stats: Option<&'a AlertStats>,
    selected_id: Option<&'a str>,
    filter_severity: Option<&'a str>,
    filter_status: Option<&'a str>,
    search_query: &'a str,
) -> Element<'a, Message> {
    // Header
    let header = row![
        container(
            text("\u{1F514}")  // 🔔
                .size(20)
                .color(colors::ORANGE)
        )
        .padding([8, 12])
        .style(|_| container::Style {
            background: Some(Background::Color(Color::from_rgba(1.0, 0.6, 0.0, 0.2))),
            border: Border {
                radius: 8.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
        Space::with_width(16),
        column![
            text("SECURITY ALERTS")
                .size(18)
                .color(colors::TEXT_PRIMARY),
            text("Monitor and manage security events")
                .size(10)
                .color(colors::TEXT_MUTED),
        ],
        Space::with_width(Length::Fill),
        button(
            text("\u{21BB}").size(14).color(colors::TEXT_MUTED) // ↻
        )
        .on_press(Message::FetchAlerts)
        .padding([8, 12])
        .style(|_, status| {
            let bg = if matches!(status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(1.0, 1.0, 1.0, 0.1)
            } else {
                Color::TRANSPARENT
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::TEXT_MUTED,
                border: Border::default(),
                ..Default::default()
            }
        }),
        Space::with_width(8),
        button(
            text("\u{2716}").size(18).color(colors::TEXT_MUTED) // ✖
        )
        .on_press(Message::HideAlertsDashboard)
        .padding([8, 12])
        .style(|_, status| {
            let bg = if matches!(status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(1.0, 1.0, 1.0, 0.1)
            } else {
                Color::TRANSPARENT
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::TEXT_MUTED,
                border: Border::default(),
                ..Default::default()
            }
        }),
    ]
    .align_y(Alignment::Center)
    .padding([16, 24]);

    // Filter toolbar
    let filter_btn = |label: &'a str, is_active: bool, color: Color, msg: Message| -> Element<'a, Message> {
        button(
            text(label).size(9).color(if is_active { Color::WHITE } else { color })
        )
        .on_press(msg)
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
        .into()
    };

    let severity_filters = row![
        text("Severity:").size(9).color(colors::TEXT_MUTED),
        Space::with_width(8),
        filter_btn("ALL", filter_severity.is_none(), colors::CYAN, Message::AlertFilterSeverity(None)),
        Space::with_width(4),
        filter_btn("CRITICAL", filter_severity == Some("critical"), colors::RED, Message::AlertFilterSeverity(Some("critical".to_string()))),
        Space::with_width(4),
        filter_btn("HIGH", filter_severity == Some("high"), colors::ORANGE, Message::AlertFilterSeverity(Some("high".to_string()))),
        Space::with_width(4),
        filter_btn("MEDIUM", filter_severity == Some("medium"), colors::YELLOW, Message::AlertFilterSeverity(Some("medium".to_string()))),
        Space::with_width(4),
        filter_btn("LOW", filter_severity == Some("low"), Color::from_rgb(0.23, 0.51, 0.95), Message::AlertFilterSeverity(Some("low".to_string()))),
    ]
    .align_y(Alignment::Center);

    let status_filters = row![
        text("Status:").size(9).color(colors::TEXT_MUTED),
        Space::with_width(8),
        filter_btn("ALL", filter_status.is_none(), colors::CYAN, Message::AlertFilterStatus(None)),
        Space::with_width(4),
        filter_btn("OPEN", filter_status == Some("open"), colors::RED, Message::AlertFilterStatus(Some("open".to_string()))),
        Space::with_width(4),
        filter_btn("ACK", filter_status == Some("acknowledged"), colors::YELLOW, Message::AlertFilterStatus(Some("acknowledged".to_string()))),
        Space::with_width(4),
        filter_btn("RESOLVED", filter_status == Some("resolved"), colors::GREEN, Message::AlertFilterStatus(Some("resolved".to_string()))),
    ]
    .align_y(Alignment::Center);

    let filters = column![
        row![
            severity_filters,
            Space::with_width(Length::Fill),
            text_input("Search alerts...", search_query)
                .on_input(Message::AlertSearch)
                .padding([6, 12])
                .width(Length::Fixed(200.0))
                .size(10),
        ]
        .align_y(Alignment::Center),
        Space::with_height(8),
        status_filters,
    ]
    .padding([12, 24]);

    // Filter alerts
    let filtered_alerts: Vec<&Alert> = alerts
        .iter()
        .filter(|alert| {
            // Filter by severity
            if let Some(sev) = filter_severity {
                if alert.severity.to_lowercase() != sev.to_lowercase() {
                    return false;
                }
            }
            // Filter by status
            if let Some(st) = filter_status {
                if alert.status.to_lowercase() != st.to_lowercase() {
                    return false;
                }
            }
            // Filter by search
            if !search_query.is_empty() {
                let query = search_query.to_lowercase();
                if !alert.title.to_lowercase().contains(&query)
                    && !alert.source_tool.to_lowercase().contains(&query)
                    && !alert.device_ip.as_ref().map(|s| s.to_lowercase().contains(&query)).unwrap_or(false)
                {
                    return false;
                }
            }
            true
        })
        .collect();

    // Alert list
    let alert_list: Element<'a, Message> = if filtered_alerts.is_empty() {
        container(
            column![
                text("\u{1F514}").size(48).color(Color::from_rgba(1.0, 1.0, 1.0, 0.1)),
                Space::with_height(16),
                text("No alerts match your filters")
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
        for alert in &filtered_alerts {
            let is_selected = selected_id == Some(&alert.id);
            cards = cards.push(alert_card(alert, is_selected));
        }
        scrollable(
            container(cards)
                .padding([0, 24])
                .width(Length::Fill)
        )
        .height(Length::Fill)
        .into()
    };

    // Detail panel (if an alert is selected)
    let selected_alert = selected_id.and_then(|id| alerts.iter().find(|a| a.id == id));

    // Main content with optional detail panel
    let main_content: Element<'a, Message> = if let Some(alert) = selected_alert {
        row![
            container(alert_list)
                .width(Length::Fill)
                .height(Length::Fill),
            alert_detail(alert),
        ]
        .into()
    } else {
        alert_list
    };

    // Stats bar
    let stats_section = stats_bar(stats, filtered_alerts.len());

    // Full layout
    let content = column![
        header,
        container(Space::with_height(1))
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(colors::BORDER)),
                ..Default::default()
            }),
        container(stats_section)
            .padding([12, 24])
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.2))),
                ..Default::default()
            }),
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
        container(main_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding([12, 0]),
    ];

    // Modal overlay
    container(
        container(content)
            .width(Length::Fixed(1100.0))
            .height(Length::Fixed(700.0))
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
