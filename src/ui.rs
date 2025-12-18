//! Terminal User Interface module using Ratatui.
//!
//! Provides a real-time dashboard for monitoring network flows and
//! visualizing beacon detection results.

use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState, Wrap,
    },
    Frame, Terminal,
};
use tokio::sync::mpsc;

use crate::analyzer::{AnalysisReport, FlowAnalysis, FlowClassification};
use crate::error::Result;

/// Terminal type alias for convenience.
type Term = Terminal<CrosstermBackend<Stdout>>;

/// UI state and configuration.
pub struct App {
    /// Current analysis report.
    report: Option<AnalysisReport>,
    /// Table selection state.
    table_state: TableState,
    /// Scrollbar state.
    scroll_state: ScrollbarState,
    /// Whether to show help overlay.
    show_help: bool,
    /// Application running state.
    running: bool,
    /// Total events processed (for stats display).
    events_processed: u64,
    /// Selected flow index for detail view.
    selected_flow: Option<usize>,
}

impl App {
    pub fn new() -> Self {
        Self {
            report: None,
            table_state: TableState::default(),
            scroll_state: ScrollbarState::default(),
            show_help: false,
            running: true,
            events_processed: 0,
            selected_flow: None,
        }
    }

    /// Updates the app with a new analysis report.
    pub fn update_report(&mut self, report: AnalysisReport) {
        self.events_processed = report.events_processed;
        self.report = Some(report);

        // Update scroll state
        if let Some(ref report) = self.report {
            self.scroll_state = self
                .scroll_state
                .content_length(report.suspicious_flows.len());
        }
    }

    /// Handles keyboard input.
    pub fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = !self.show_help,
            KeyCode::Down | KeyCode::Char('j') => self.next_row(),
            KeyCode::Up | KeyCode::Char('k') => self.prev_row(),
            KeyCode::Enter => self.toggle_detail(),
            KeyCode::Home => self.first_row(),
            KeyCode::End => self.last_row(),
            _ => {}
        }
    }

    fn next_row(&mut self) {
        if let Some(ref report) = self.report {
            let len = report.suspicious_flows.len();
            if len == 0 {
                return;
            }

            let i = match self.table_state.selected() {
                Some(i) => (i + 1).min(len - 1),
                None => 0,
            };
            self.table_state.select(Some(i));
            self.scroll_state = self.scroll_state.position(i);
        }
    }

    fn prev_row(&mut self) {
        if let Some(ref report) = self.report {
            if report.suspicious_flows.is_empty() {
                return;
            }

            let i = match self.table_state.selected() {
                Some(i) => i.saturating_sub(1),
                None => 0,
            };
            self.table_state.select(Some(i));
            self.scroll_state = self.scroll_state.position(i);
        }
    }

    fn first_row(&mut self) {
        if let Some(ref report) = self.report {
            if !report.suspicious_flows.is_empty() {
                self.table_state.select(Some(0));
                self.scroll_state = self.scroll_state.position(0);
            }
        }
    }

    fn last_row(&mut self) {
        if let Some(ref report) = self.report {
            let len = report.suspicious_flows.len();
            if len > 0 {
                self.table_state.select(Some(len - 1));
                self.scroll_state = self.scroll_state.position(len - 1);
            }
        }
    }

    fn toggle_detail(&mut self) {
        self.selected_flow = match self.selected_flow {
            Some(_) => None,
            None => self.table_state.selected(),
        };
    }

    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// Initializes the terminal for TUI rendering.
pub fn init_terminal() -> Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Restores the terminal to its original state.
pub fn restore_terminal(terminal: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

/// Main UI rendering function.
pub fn render(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(5), // Stats
            Constraint::Min(10),   // Main table
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    render_header(frame, chunks[0]);
    render_stats(frame, chunks[1], app);
    render_flows_table(frame, chunks[2], app);
    render_footer(frame, chunks[3]);

    // Render help overlay if active
    if app.show_help {
        render_help_overlay(frame);
    }

    // Render detail overlay if a flow is selected
    if let Some(idx) = app.selected_flow {
        if let Some(ref report) = app.report {
            if let Some(flow) = report.suspicious_flows.get(idx) {
                render_detail_overlay(frame, flow);
            }
        }
    }
}

fn render_header(frame: &mut Frame, area: Rect) {
    let title = vec![
        Span::styled(
            "  NETWORK-BEACON",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  "),
        Span::styled("C2 Beacon Detection System", Style::default().fg(Color::Gray)),
    ];

    let header = Paragraph::new(Line::from(title))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default());

    frame.render_widget(header, area);
}

fn render_stats(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let (total_flows, active_flows, suspicious_count, events) = match &app.report {
        Some(r) => (
            r.total_flows,
            r.active_flows,
            r.suspicious_flows.len(),
            r.events_processed,
        ),
        None => (0, 0, 0, app.events_processed),
    };

    // Total Flows
    let total_block = Paragraph::new(format!("{}", total_flows))
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .title(" Total Flows ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        );
    frame.render_widget(total_block, chunks[0]);

    // Active Flows
    let active_block = Paragraph::new(format!("{}", active_flows))
        .style(Style::default().fg(Color::Green))
        .block(
            Block::default()
                .title(" Active Flows ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        );
    frame.render_widget(active_block, chunks[1]);

    // Suspicious Flows
    let suspicious_color = if suspicious_count > 0 {
        Color::Red
    } else {
        Color::Green
    };
    let suspicious_block = Paragraph::new(format!("{}", suspicious_count))
        .style(Style::default().fg(suspicious_color))
        .block(
            Block::default()
                .title(" Suspicious ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(suspicious_color)),
        );
    frame.render_widget(suspicious_block, chunks[2]);

    // Events Processed
    let events_block = Paragraph::new(format!("{}", events))
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .title(" Events ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(events_block, chunks[3]);
}

fn render_flows_table(frame: &mut Frame, area: Rect, app: &mut App) {
    let header_cells = ["Severity", "Source IP", "Dest IP:Port", "CV", "Interval", "Packets"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).bold()));

    let header = Row::new(header_cells)
        .style(Style::default())
        .height(1)
        .bottom_margin(1);

    let rows: Vec<Row> = match &app.report {
        Some(report) => report
            .suspicious_flows
            .iter()
            .map(|flow| {
                let severity_style = match flow.classification {
                    FlowClassification::HighlyPeriodic => Style::default().fg(Color::Red).bold(),
                    FlowClassification::JitteredPeriodic => Style::default().fg(Color::Yellow),
                    FlowClassification::Moderate => Style::default().fg(Color::Blue),
                    _ => Style::default().fg(Color::Gray),
                };

                let cv_str = flow
                    .cv
                    .map(|cv| format!("{:.3}", cv))
                    .unwrap_or_else(|| "N/A".to_string());

                let interval_str = flow
                    .mean_interval_ms
                    .map(|ms| {
                        if ms >= 1000.0 {
                            format!("{:.1}s", ms / 1000.0)
                        } else {
                            format!("{:.0}ms", ms)
                        }
                    })
                    .unwrap_or_else(|| "N/A".to_string());

                Row::new(vec![
                    Cell::from(flow.classification.severity()).style(severity_style),
                    Cell::from(flow.flow_key.src_ip.to_string()),
                    Cell::from(format!("{}:{}", flow.flow_key.dst_ip, flow.flow_key.dst_port)),
                    Cell::from(cv_str),
                    Cell::from(interval_str),
                    Cell::from(flow.packet_count.to_string()),
                ])
            })
            .collect(),
        None => vec![],
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(22),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Suspicious Flows ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White)),
    )
    .highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");

    frame.render_stateful_widget(table, area, &mut app.table_state);

    // Render scrollbar
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓")),
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut app.scroll_state,
    );
}

fn render_footer(frame: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow)),
        Span::raw(": Quit  "),
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(": Navigate  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(": Details  "),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::raw(": Help"),
    ]))
    .style(Style::default().fg(Color::Gray))
    .block(Block::default().borders(Borders::TOP));

    frame.render_widget(footer, area);
}

fn render_help_overlay(frame: &mut Frame) {
    let area = centered_rect(60, 60, frame.area());

    let help_text = vec![
        Line::from(Span::styled(
            "Keyboard Shortcuts",
            Style::default().bold().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("q / Esc    ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit application"),
        ]),
        Line::from(vec![
            Span::styled("↑ / k      ", Style::default().fg(Color::Yellow)),
            Span::raw("Move selection up"),
        ]),
        Line::from(vec![
            Span::styled("↓ / j      ", Style::default().fg(Color::Yellow)),
            Span::raw("Move selection down"),
        ]),
        Line::from(vec![
            Span::styled("Enter      ", Style::default().fg(Color::Yellow)),
            Span::raw("Show flow details"),
        ]),
        Line::from(vec![
            Span::styled("Home       ", Style::default().fg(Color::Yellow)),
            Span::raw("Jump to first row"),
        ]),
        Line::from(vec![
            Span::styled("End        ", Style::default().fg(Color::Yellow)),
            Span::raw("Jump to last row"),
        ]),
        Line::from(vec![
            Span::styled("? / h      ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle this help"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Classification Legend",
            Style::default().bold().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("CRITICAL   ", Style::default().fg(Color::Red)),
            Span::raw("CV < 0.1 - Highly Periodic (Probable Bot)"),
        ]),
        Line::from(vec![
            Span::styled("HIGH       ", Style::default().fg(Color::Yellow)),
            Span::raw("CV 0.1-0.5 - Jittered (Suspicious)"),
        ]),
        Line::from(vec![
            Span::styled("MEDIUM     ", Style::default().fg(Color::Blue)),
            Span::raw("CV 0.5-1.0 - Moderate Variation"),
        ]),
        Line::from(vec![
            Span::styled("LOW        ", Style::default().fg(Color::Green)),
            Span::raw("CV > 1.0 - Stochastic (Organic)"),
        ]),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(Clear, area);
    frame.render_widget(help, area);
}

fn render_detail_overlay(frame: &mut Frame, flow: &FlowAnalysis) {
    let area = centered_rect(70, 50, frame.area());

    let severity_style = match flow.classification {
        FlowClassification::HighlyPeriodic => Style::default().fg(Color::Red).bold(),
        FlowClassification::JitteredPeriodic => Style::default().fg(Color::Yellow).bold(),
        _ => Style::default().fg(Color::White),
    };

    let detail_text = vec![
        Line::from(vec![
            Span::styled("Classification: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{}", flow.classification), severity_style),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Source IP:      ", Style::default().fg(Color::Gray)),
            Span::raw(flow.flow_key.src_ip.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Destination:    ", Style::default().fg(Color::Gray)),
            Span::raw(format!(
                "{}:{}",
                flow.flow_key.dst_ip, flow.flow_key.dst_port
            )),
        ]),
        Line::from(vec![
            Span::styled("Protocol:       ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}", flow.flow_key.protocol)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("CV Score:       ", Style::default().fg(Color::Gray)),
            Span::raw(
                flow.cv
                    .map(|cv| format!("{:.4}", cv))
                    .unwrap_or_else(|| "N/A".to_string()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Mean Interval:  ", Style::default().fg(Color::Gray)),
            Span::raw(
                flow.mean_interval_ms
                    .map(|ms| {
                        if ms >= 1000.0 {
                            format!("{:.2} seconds", ms / 1000.0)
                        } else {
                            format!("{:.2} ms", ms)
                        }
                    })
                    .unwrap_or_else(|| "N/A".to_string()),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Packets:        ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}", flow.packet_count)),
        ]),
        Line::from(vec![
            Span::styled("Total Bytes:    ", Style::default().fg(Color::Gray)),
            Span::raw(format_bytes(flow.total_bytes)),
        ]),
        Line::from(vec![
            Span::styled("Duration:       ", Style::default().fg(Color::Gray)),
            Span::raw(format_duration(flow.duration_secs)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Press Enter or Esc to close",
            Style::default().fg(Color::DarkGray).italic(),
        )),
    ];

    let detail = Paragraph::new(detail_text).block(
        Block::default()
            .title(" Flow Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    frame.render_widget(Clear, area);
    frame.render_widget(detail, area);
}

/// Helper to create a centered rectangle.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Format bytes in human-readable form.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format duration in human-readable form.
fn format_duration(secs: i64) -> String {
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

/// Main UI event loop.
pub async fn run_ui(mut report_rx: mpsc::Receiver<AnalysisReport>) -> Result<()> {
    let mut terminal = init_terminal()?;
    let mut app = App::new();

    let tick_rate = Duration::from_millis(100);

    while app.is_running() {
        // Check for new reports (non-blocking)
        while let Ok(report) = report_rx.try_recv() {
            app.update_report(report);
        }

        // Draw UI
        terminal.draw(|f| render(f, &mut app))?;

        // Handle input events
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key.code);
                }
            }
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}
