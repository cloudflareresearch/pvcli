use clap::Parser;
use std::fs;

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Parser, Debug)]
#[command(name = "ferret", about = "A curl-like client for privacy protocols")]
#[command(next_line_help = true)]
pub struct Args {
    pub url: String,

    #[arg(short, long, action = clap::ArgAction::Count)]
    /// -v: info logs | -vv: debug logs | -vvv: all logs
    pub verbosity: u8,

    /// boolean flag to suppress all non-error output
    #[arg(short, long, action)]
    pub silent: bool,

    #[arg(short = 'X', long, ignore_case = true)]
    pub method: Option<Method>,

    #[arg(short = 'H', long)]
    pub header: Option<Vec<String>>,

    #[arg(short, long, value_parser = parse_data)]
    /// ferret uses "Content-Type: application/x-www-form-urlencoded" by default. See --header to customize
    pub data: Option<String>,
}

fn parse_data(d: &str) -> Result<String, String> {
    if let Some(path) = d.strip_prefix("@") {
        Ok(fs::read_to_string(path).expect("failed to read from file"))
    } else {
        Ok(d.to_string())
    }
}
