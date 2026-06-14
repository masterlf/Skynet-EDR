//! Command-line entry point for Skynet-EDR.

use std::{env, process::ExitCode};

use skynet_edr_core::ProductInfo;

fn main() -> ExitCode {
    let mut args = env::args();
    let binary = args.next().unwrap_or_else(|| "skynet-edr".to_owned());

    let command = args.next();
    if let Some(extra) = args.next() {
        eprintln!("unexpected argument: {extra}");
        eprintln!("try '{binary} --help'");
        return ExitCode::FAILURE;
    }

    match command.as_deref() {
        None | Some("status") => {
            print_status();
            ExitCode::SUCCESS
        }
        Some("--help" | "-h" | "help") => {
            print_help(&binary);
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            println!(
                "{} {}",
                ProductInfo::default().binary_name,
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("unknown command: {command}");
            eprintln!("try '{binary} --help'");
            ExitCode::FAILURE
        }
    }
}

fn print_status() {
    let info = ProductInfo::default();
    println!("{} status: mode={}", info.name, info.run_mode.as_str());
}

fn print_help(binary: &str) {
    println!("Usage: {binary} [status|--version|--help]");
    println!();
    println!("Commands:");
    println!("  status     Print product status and default runtime mode");
}
