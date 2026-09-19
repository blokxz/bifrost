//! The panic hook must restore the terminal before the panic message is printed.
//!
//! This is its own test binary, and holds a single test, because a panic hook is
//! process-global: installing one next to other tests would race with them.

use std::panic;
use std::sync::Mutex;

use bifrost_ssh::tui::terminal::install_panic_hook_with;

static ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

fn record(step: &'static str) {
    ORDER.lock().unwrap().push(step);
}

#[test]
fn restore_runs_before_the_previous_hook() {
    panic::set_hook(Box::new(|_| record("previous hook prints the message")));
    install_panic_hook_with(|| record("terminal restored"));

    let result = panic::catch_unwind(|| panic!("boom"));
    let _ = panic::take_hook();

    assert!(result.is_err());
    assert_eq!(
        *ORDER.lock().unwrap(),
        ["terminal restored", "previous hook prints the message"]
    );
}
