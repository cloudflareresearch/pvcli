use clap::Parser;
use ferret::http::HttpClient;

#[derive(Parser, Debug)]
#[command(name = "ferret")]
#[command(about = "A curl-like client for privacy protocols")]
struct Args {
    url: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        println!("{}", e);
        std::process::exit(1);
    }
}

async fn run(args: Args) -> ferret::error::Result<()> {
    let client = HttpClient::new()?;
    let response = client.get(&args.url).await?;
    println!("{}", response.body);

    Ok(())
}
