//! A stand-in for `ssh` (and `ssh-keygen`) that any platform can run.
//!
//! It is compiled by the test support with `rustc`, because Windows needs a real
//! executable named `ssh.exe` and a shell script will not do. What it does is
//! written in a file next to it with the same name and the extension `script`,
//! one command per line:
//!
//! - `stdout TEXT` and `stderr TEXT`: print TEXT and a line break; stderr lines
//!   end with `\r\n`, as ssh's do.
//! - `exit N`: exit with status N.
//! - `abort`: end abnormally, as a crash does.
//! - `sleep MILLISECONDS`: wait.
//!
//! It records how it was started in the file with the extension `log`: its own
//! path, then one argument per line.

use std::io::Write;

fn main() {
    let exe = std::env::current_exe().expect("the path of the fake");
    let mut record = exe.display().to_string();
    for argument in std::env::args().skip(1) {
        record.push('\n');
        record.push_str(&argument);
    }
    let _ = std::fs::write(exe.with_extension("log"), record);

    let script = std::fs::read_to_string(exe.with_extension("script")).unwrap_or_default();
    for line in script.lines() {
        let (command, rest) = line.split_once(' ').unwrap_or((line, ""));
        match command {
            "stdout" => {
                let mut out = std::io::stdout();
                let _ = write!(out, "{rest}\n");
                let _ = out.flush();
            }
            "stderr" => {
                let mut err = std::io::stderr();
                let _ = write!(err, "{rest}\r\n");
                let _ = err.flush();
            }
            "sleep" => std::thread::sleep(std::time::Duration::from_millis(
                rest.parse().unwrap_or(0),
            )),
            "exit" => std::process::exit(rest.parse().unwrap_or(0)),
            "abort" => std::process::abort(),
            _ => {}
        }
    }
}
