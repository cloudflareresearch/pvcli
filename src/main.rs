use clap::Parser;
use ferret::http::HttpClient;
use foundations::telemetry::{
    self, TelemetryConfig, log,
    settings::{LogFormat, LogOutput, LogVerbosity, TelemetrySettings},
};

#[derive(Parser, Debug)]
#[command(name = "ferret", about = "A curl-like client for privacy protocols")]
struct Args {
    url: String,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbosity: u8,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    configure_logging(&args);

    log::debug!("{:?}", args);

    if let Err(e) = run(args).await {
        log::error!("{}", e);
        std::process::exit(1);
    }
}

async fn run(args: Args) -> ferret::error::Result<()> {
    let client = HttpClient::new()?;
    let response = client.get(&args.url).await?;
    println!("{}", response.body);

    Ok(())
}

fn configure_logging(args: &Args) {
    let service_info: foundations::ServiceInfo = foundations::service_info!();
    let mut settings = TelemetrySettings::default();
    settings.logging.output = LogOutput::Stderr;

    settings.logging.verbosity = match args.verbosity {
        0_u8 => LogVerbosity::Warning,
        1_u8 => LogVerbosity::Info,
        2_u8 => LogVerbosity::Debug,
        _ => LogVerbosity::Trace,
    };

    settings.logging.format = LogFormat::Text;

    let _ = telemetry::init(TelemetryConfig {
        service_info: &service_info,
        settings: &settings,
        custom_server_routes: vec![],
    });
}
