use httpmock::MockServer;

#[tokio::main]
async fn main() {
    let server = setup_mock_server();
    println!("{}", server.base_url());
    // keep alive until ctrl+c
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    println!("Shutting down");
}

fn setup_mock_server() -> MockServer {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("GET").body_excludes("data").path("/testget");
        then.status(200).body("get successful");
    });
    server.mock(|when, then| {
        // when.method("POST").path("/testpost");
        when.method("POST").body_includes("data").path("/testpost");
        then.status(200).body("post successful");
    });

    server
}
