//! 彩色 TUI：ansi_shadow 艺术字 banner（青→品红逐列渐变）+ 账号列表方向键/鼠标选择。
//!
//! banner 与字体样式参考 `../x_key_scanner/src/ui.rs`：banner 内容由 pyfiglet
//! `ansi_shadow` 字体离线生成后硬编码，运行时无需字体文件。

use std::io::{self, Write};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind};
use crossterm::{cursor, execute, queue, terminal};

/// pyfiglet `ansi_shadow` 生成的 "qqdbkey" 艺术字。
const BANNER: &[&str] = &[
    " ██████╗  ██████╗ ██████╗ ██████╗ ██╗  ██╗███████╗██╗   ██╗",
    "██╔═══██╗██╔═══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝╚██╗ ██╔╝",
    "██║   ██║██║   ██║██║  ██║██████╔╝█████╔╝ █████╗   ╚████╔╝ ",
    "██║▄▄ ██║██║▄▄ ██║██║  ██║██╔══██╗██╔═██╗ ██╔══╝    ╚██╔╝  ",
    "╚██████╔╝╚██████╔╝██████╔╝██████╔╝██║  ██╗███████╗   ██║   ",
    " ╚══▀▀═╝  ╚══▀▀═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ",
];

/// 逐列 cyan(0,255,255)→magenta(255,0,255) 渐变，粗体。
fn gradient(t: f32, ch: char) -> String {
    let t = t.clamp(0.0, 1.0);
    let r = (t * 255.0).round() as u8;
    let g = ((1.0 - t) * 255.0).round() as u8;
    format!("\x1b[1;38;2;{r};{g};255m{ch}\x1b[0m")
}

/// 打印大 banner（渐变艺术字 + 副标题）。
pub fn app_banner(subtitle: &str) {
    let mut out = io::stdout();
    let _ = writeln!(out);
    let width = BANNER.iter().map(|l| l.chars().count()).max().unwrap_or(1).max(1) as f32;
    for line in BANNER {
        let mut painted = String::new();
        for (col, ch) in line.chars().enumerate() {
            if ch == ' ' {
                painted.push(' ');
            } else {
                painted.push_str(&gradient(col as f32 / width, ch));
            }
        }
        let _ = writeln!(out, "{painted}");
    }
    let _ = writeln!(out, "  \x1b[90m{subtitle}\x1b[0m\n");
}

pub fn info(msg: &str) {
    println!("\x1b[1;34m[info]\x1b[0m {msg}");
}

pub fn ok(msg: &str) {
    println!("\x1b[1;32m[ ok ]\x1b[0m {msg}");
}

pub fn warn(msg: &str) {
    eprintln!("\x1b[1;33m[warn]\x1b[0m {msg}");
}

pub fn error(msg: &str) {
    eprintln!("\x1b[1;31m[fail]\x1b[0m {msg}");
}

pub fn section(title: &str) {
    println!("\n\x1b[1;36m{title}\x1b[0m");
    println!("\x1b[90m{}\x1b[0m", "─".repeat(title.chars().count().max(1)));
}

pub fn field(label: &str, value: &str) {
    println!("  \x1b[90m{:<16}\x1b[0m \x1b[1;37m{value}\x1b[0m", label);
}

pub fn key_line(label: &str, value: &str) {
    println!("  \x1b[90m{:<16}\x1b[0m \x1b[1;92m{value}\x1b[0m", label);
}

/// 账号列表项（对应 login.db 一行）。
pub struct Choice {
    pub uin: String,
    pub nick: String,
    pub uid: String,
    pub last_login_at: i64,
}

/// 交互式选择账号：方向键上下 + 回车；鼠标左键点击 / 滚轮。
///
/// 交互在替代屏幕上跑；返回选中项的下标。
pub fn select_account(choices: &[Choice]) -> Result<usize> {
    if choices.is_empty() {
        anyhow::bail!("账号列表为空");
    }
    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(
        stdout,
        terminal::EnterAlternateScreen,
        event::EnableMouseCapture,
        cursor::Hide
    )?;

    let result = select_loop(&mut stdout, choices);

    let _ = execute!(
        stdout,
        event::DisableMouseCapture,
        cursor::Show,
        terminal::LeaveAlternateScreen
    );
    let _ = terminal::disable_raw_mode();
    result
}

/// 单行渲染：`▸ 昵称  (uin)  ·  uid  ·  最后登录`。
fn row_text(c: &Choice, selected: bool) -> String {
    let marker = if selected { "\u{25b8}" } else { " " };
    let head = format!("{marker} {}  ({})", if c.nick.is_empty() { "(无昵称)" } else { &c.nick }, c.uin);
    let tail = if c.last_login_at > 0 {
        format!("   · uid {} · 最后登录 {}", shorten(&c.uid), c.last_login_at)
    } else {
        format!("   · uid {}", shorten(&c.uid))
    };
    format!("{head}{tail}")
}

fn shorten(uid: &str) -> String {
    if uid.chars().count() <= 16 {
        uid.to_string()
    } else {
        let head: String = uid.chars().take(8).collect();
        let tail: String = uid.chars().rev().take(4).collect::<String>().chars().rev().collect();
        format!("{head}…{tail}")
    }
}

/// 渲染一整帧（标题 + 列表 + 页脚），并定位光标。
fn render(stdout: &mut io::Stdout, choices: &[Choice], sel: usize) -> Result<()> {
    queue!(stdout, cursor::MoveTo(0, 0))?;
    let _ = execute!(stdout, terminal::Clear(terminal::ClearType::All));
    queue!(stdout, cursor::MoveTo(0, 0))?;
    let _ = queue!(
        stdout,
        terminal::SetTitle("qqdbkey \u{00b7} 选择账号")
    );
    queue!(
        stdout,
        cursor::MoveTo(0, 0)
    )?;
    write!(stdout, "\x1b[1;36m选择要提取 dbkey 的账号\x1b[0m\r\n")?;
    write!(stdout, "\x1b[90m\u{2191}/\u{2193} 或鼠标选择，回车确认，q 退出\x1b[0m\r\n\r\n")?;

    for (i, c) in choices.iter().enumerate() {
        let selected = i == sel;
        let text = row_text(c, selected);
        if selected {
            write!(stdout, "\x1b[1;97;45m {text} \x1b[0m\r\n")?;
        } else {
            write!(stdout, "\x1b[37m {text} \x1b[0m\r\n")?;
        }
    }
    stdout.flush()?;
    Ok(())
}

fn select_loop(stdout: &mut io::Stdout, choices: &[Choice]) -> Result<usize> {
    let mut sel = 0usize;
    // 列表首行在屏幕上的 y 坐标（标题 2 行 + 空 1 行 + 表头说明共 3 行）。
    const LIST_TOP: u16 = 3;
    render(stdout, choices, sel)?;
    loop {
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if sel > 0 {
                        sel -= 1;
                        render(stdout, choices, sel)?;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if sel + 1 < choices.len() {
                        sel += 1;
                        render(stdout, choices, sel)?;
                    }
                }
                KeyCode::Enter => return Ok(sel),
                KeyCode::Esc | KeyCode::Char('q') => anyhow::bail!("已取消"),
                _ => {}
            },
            Event::Mouse(me) => match me.kind {
                MouseEventKind::ScrollUp => {
                    if sel > 0 {
                        sel -= 1;
                        render(stdout, choices, sel)?;
                    }
                }
                MouseEventKind::ScrollDown => {
                    if sel + 1 < choices.len() {
                        sel += 1;
                        render(stdout, choices, sel)?;
                    }
                }
                MouseEventKind::Down(MouseButton::Left) => {
                    if me.row >= LIST_TOP {
                        let idx = (me.row - LIST_TOP) as usize;
                        if idx < choices.len() {
                            sel = idx;
                            return Ok(sel);
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}
