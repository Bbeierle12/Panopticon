//! Browsing metrics dashboard view.

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::api::{
    BeaconDetection, BrowsingData, BrowsingEvent, BrowsingRealtime, DnsQueryType,
    DnsTopDomain, ProtocolDist, SuspiciousDomain, TlsVersionCount,
};
use crate::message::Message;
use crate::theme::colors;

/// Format bytes to human-readable string.
fn format_bytes(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = KB * 1024;
    const GB: i64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Render a stat pill.
fn stat_pill(label: &str, value: &str, color: Color) -> Element<'static, Message> {
    let label = label.to_string();
    let value = value.to_string();
    container(
        column![
            text(value).size(16).color(color),
            text(label).size(8).color(colors::TEXT_MUTED),
        ]
        .align_x(Alignment::Center)
        .spacing(2),
    )
    .padding([8, 16])
    .style(move |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(
            color.r, color.g, color.b, 0.08,
        ))),
        border: Border {
            color: Color::from_rgba(color.r, color.g, color.b, 0.2),
            width: 1.0,
            radius: 6.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Render the real-time stats bar.
fn stats_bar(realtime: Option<&BrowsingRealtime>) -> Element<'_, Message> {
    if let Some(r) = realtime {
        let pills: Vec<Element<'_, Message>> = vec![
            stat_pill("DNS QPS", &format!("{:.1}", r.dns_qps), colors::CYAN),
            stat_pill("CONNECTIONS", &r.active_connections.to_string(), colors::GREEN),
            stat_pill("UPLOAD", &format_bytes(r.bandwidth_up), colors::PURPLE),
            stat_pill("DOWNLOAD", &format_bytes(r.bandwidth_down), Color::from_rgb(0.23, 0.51, 0.95)),
            stat_pill("DNS TOTAL", &r.total_dns_queries.to_string(), colors::YELLOW),
            stat_pill("TLS TOTAL", &r.total_tls.to_string(), Color::from_rgb(0.66, 0.33, 0.97)),
        ];
        row(pills).spacing(8).into()
    } else {
        text("Loading...").size(10).color(colors::TEXT_MUTED).into()
    }
}

/// Render a table row for domains.
fn domain_row(domain: &DnsTopDomain) -> Element<'static, Message> {
    let name_color = if domain.is_suspicious { colors::RED } else { colors::TEXT_PRIMARY };
    let domain_name = domain.domain.clone();
    let count_str = domain.count.to_string();

    let badge: Element<'static, Message> = if domain.is_suspicious {
        container(text("SUSPICIOUS").size(7).color(Color::WHITE))
            .padding([2, 4])
            .style(|_| container::Style {
                background: Some(Background::Color(colors::RED)),
                border: Border { radius: 2.0.into(), ..Default::default() },
                ..Default::default()
            })
            .into()
    } else {
        Space::with_width(0).into()
    };

    container(
        row![
            text(domain_name).size(10).color(name_color).width(Length::FillPortion(5)),
            badge,
            Space::with_width(Length::Fill),
            text(count_str).size(10).color(colors::CYAN),
        ]
        .align_y(Alignment::Center)
        .spacing(8),
    )
    .padding([6, 10])
    .width(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.02))),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Render an event card.
fn event_card(event: &BrowsingEvent) -> Element<'static, Message> {
    let type_color = match event.event_type.as_str() {
        "dns" => colors::CYAN,
        "tls" => Color::from_rgb(0.66, 0.33, 0.97),
        "http" => colors::GREEN,
        _ => colors::TEXT_MUTED,
    };

    let badge_text = event.event_type.to_uppercase();
    let summary = event.summary.clone();
    let summary_color = if event.is_suspicious { colors::RED } else { colors::TEXT_SECONDARY };
    let time_str = if event.timestamp.len() > 19 {
        event.timestamp[11..19].to_string()
    } else {
        event.timestamp.clone()
    };

    container(
        row![
            container(text(badge_text).size(7).color(Color::WHITE))
                .padding([2, 6])
                .style(move |_| container::Style {
                    background: Some(Background::Color(type_color)),
                    border: Border { radius: 3.0.into(), ..Default::default() },
                    ..Default::default()
                }),
            Space::with_width(8),
            text(summary).size(9).color(summary_color).width(Length::Fill),
            text(time_str).size(8).color(colors::TEXT_MUTED),
        ]
        .align_y(Alignment::Center),
    )
    .padding([4, 8])
    .width(Length::Fill)
    .style(|_| container::Style {
        border: Border {
            color: Color::from_rgba(1.0, 1.0, 1.0, 0.05),
            width: 1.0,
            radius: 3.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Render a beacon detection card.
fn beacon_card(beacon: &BeaconDetection) -> Element<'static, Message> {
    let route = format!("{} \u{2192} {}:{}", beacon.src_ip, beacon.dst_ip, beacon.dst_port);
    let interval = format!("Interval: {:.1}s", beacon.interval_secs);
    let jitter = format!("Jitter: {:.4}", beacon.jitter);
    let conns = format!("{} connections", beacon.connection_count);

    container(
        column![
            row![
                text("\u{26A0}").size(12).color(colors::RED),
                Space::with_width(8),
                text(route).size(11).color(colors::TEXT_PRIMARY),
            ].align_y(Alignment::Center),
            Space::with_height(4),
            row![
                text(interval).size(9).color(colors::YELLOW),
                Space::with_width(16),
                text(jitter).size(9).color(colors::TEXT_MUTED),
                Space::with_width(16),
                text(conns).size(9).color(colors::TEXT_MUTED),
            ],
        ]
    )
    .padding(10)
    .width(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.94, 0.27, 0.27, 0.08))),
        border: Border {
            color: Color::from_rgba(0.94, 0.27, 0.27, 0.3),
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Render the browsing metrics dashboard.
pub fn view(data: Option<&BrowsingData>) -> Element<'_, Message> {
    let close_btn = button(
        text("\u{2715} CLOSE").size(10).color(colors::TEXT_MUTED),
    )
    .on_press(Message::HideBrowsingDashboard)
    .padding([6, 12])
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
    });

    let header = row![
        text("BROWSING METRICS").size(14).color(colors::TEXT_PRIMARY),
        Space::with_width(Length::Fill),
        close_btn,
    ]
    .align_y(Alignment::Center);

    let content: Element<'_, Message> = if let Some(data) = data {
        let stats = stats_bar(Some(&data.realtime));

        // DNS top domains section
        let mut dns_section = column![
            text("TOP DOMAINS").size(9).color(colors::TEXT_MUTED),
        ]
        .spacing(4);
        for domain in data.top_domains.iter().take(15) {
            dns_section = dns_section.push(domain_row(domain));
        }

        // Query types
        let mut query_types_section = column![
            text("QUERY TYPES").size(9).color(colors::TEXT_MUTED),
        ]
        .spacing(4);
        for qt in &data.query_types {
            let rrtype = qt.rrtype.clone();
            let count = qt.count.to_string();
            query_types_section = query_types_section.push(
                row![
                    text(rrtype).size(10).color(colors::CYAN).width(Length::Fixed(60.0)),
                    text(count).size(10).color(colors::TEXT_SECONDARY),
                ]
            );
        }

        // TLS versions
        let mut tls_section = column![
            text("TLS VERSIONS").size(9).color(colors::TEXT_MUTED),
        ]
        .spacing(4);
        for tv in &data.tls_versions {
            let color = if tv.version.contains("1.3") {
                colors::GREEN
            } else if tv.version.contains("1.2") {
                colors::YELLOW
            } else {
                colors::RED
            };
            let ver = tv.version.clone();
            let count = tv.count.to_string();
            tls_section = tls_section.push(
                row![
                    text(ver).size(10).color(color).width(Length::Fixed(80.0)),
                    text(count).size(10).color(colors::TEXT_SECONDARY),
                ]
            );
        }

        // Protocols
        let mut proto_section = column![
            text("PROTOCOLS").size(9).color(colors::TEXT_MUTED),
        ]
        .spacing(4);
        for p in &data.protocols {
            let proto = p.protocol.clone();
            let bytes = format_bytes(p.bytes_total);
            let pct = format!("{:.1}%", p.percentage);
            proto_section = proto_section.push(
                row![
                    text(proto).size(10).color(colors::CYAN).width(Length::Fixed(80.0)),
                    text(bytes).size(10).color(colors::TEXT_SECONDARY),
                    Space::with_width(8),
                    text(pct).size(9).color(colors::TEXT_MUTED),
                ]
            );
        }

        // Security section
        let mut security_section = column![
            text("SECURITY").size(9).color(colors::TEXT_MUTED),
        ]
        .spacing(4);

        if data.beacons.is_empty() && data.suspicious_domains.is_empty() {
            security_section = security_section.push(
                text("\u{2714} No threats detected").size(10).color(colors::GREEN),
            );
        }
        for beacon in &data.beacons {
            security_section = security_section.push(beacon_card(beacon));
        }
        for sus in data.suspicious_domains.iter().take(10) {
            let sus_domain = sus.domain.clone();
            let sus_entropy = format!("entropy: {:.2}", sus.entropy);
            let sus_source = sus.threat_source.clone();
            let sus_card = container(
                row![
                    text(sus_domain).size(10).color(colors::RED),
                    Space::with_width(Length::Fill),
                    text(sus_entropy).size(8).color(colors::YELLOW),
                    Space::with_width(8),
                    text(sus_source).size(8).color(colors::TEXT_MUTED),
                ]
                .align_y(Alignment::Center),
            )
            .padding([4, 8])
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.94, 0.27, 0.27, 0.05))),
                border: Border {
                    color: Color::from_rgba(0.94, 0.27, 0.27, 0.2),
                    width: 1.0,
                    radius: 3.0.into(),
                },
                ..Default::default()
            });
            let el: Element<'_, Message> = sus_card.into();
            security_section = security_section.push(el);
        }

        // Live event feed
        let mut events_section = column![
            text("LIVE EVENTS").size(9).color(colors::TEXT_MUTED),
        ]
        .spacing(2);
        for event in data.recent_events.iter().rev().take(30) {
            events_section = events_section.push(event_card(event));
        }

        // Layout: two columns
        let left = column![
            stats,
            Space::with_height(12),
            dns_section,
            Space::with_height(12),
            security_section,
        ]
        .spacing(4)
        .width(Length::FillPortion(5));

        let right = column![
            query_types_section,
            Space::with_height(12),
            tls_section,
            Space::with_height(12),
            proto_section,
            Space::with_height(12),
            events_section,
        ]
        .spacing(4)
        .width(Length::FillPortion(4));

        scrollable(
            row![left, Space::with_width(16), right]
                .width(Length::Fill),
        )
        .height(Length::Fill)
        .into()
    } else {
        container(
            text("Loading browsing metrics...")
                .size(12)
                .color(colors::TEXT_MUTED),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
    };

    container(
        column![
            header,
            Space::with_height(12),
            content,
        ]
        .spacing(0),
    )
    .padding(20)
    .width(Length::Fixed(1100.0))
    .height(Length::Fixed(750.0))
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.02, 0.03, 0.05, 0.98))),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    })
    .into()
}
