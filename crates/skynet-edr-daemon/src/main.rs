//! Minimal daemon entry point for Skynet-EDR.

use std::{env, process::ExitCode};

use skynet_edr_core::ProductInfo;

fn main() -> ExitCode {
    let mut args = env::args();
    let binary = args
        .next()
        .unwrap_or_else(|| "skynet-edr-daemon".to_owned());

    match args.next().as_deref() {
        None | Some("status") => {
            print_status();
            ExitCode::SUCCESS
        }
        Some("--help" | "-h" | "help") => {
            print_help(&binary);
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            println!("skynet-edr-daemon {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("unknown daemon command: {command}");
            eprintln!("try '{binary} --help'");
            ExitCode::FAILURE
        }
    }
}

fn print_status() {
    let info = ProductInfo::default();
    println!(
        "{} daemon status: mode={} sensors=not-started",
        info.name,
        info.run_mode.as_str()
    );
}

fn print_help(binary: &str) {
    println!("Usage: {binary} [status|--version|--help]");
    println!();
    println!("Commands:");
    println!("  status     Print daemon status without starting privileged sensors");
}
