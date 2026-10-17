mod support;

use std::{
    error::Error as StdError,
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use support::server::{self, Event, Server};
use wreq::{Body, Client, redirect::Policy};

fn client_over(server: &Server) -> Client {
    client_with(TcpStream::connect(server.addr()).unwrap())
}

fn client_with(stream: TcpStream) -> Client {
    Client::builder()
        .tcp_stream(stream)
        .redirect(Policy::default())
        .build()
        .unwrap()
}

fn error_chain(err: &wreq::Error) -> String {
    let mut chain = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        chain.push_str(" <- ");
        chain.push_str(&cause.to_string());
        source = cause.source();
    }
    chain
}

/// Answers `/cross` with a redirect to another host and every other path with "ok".
fn counting_server() -> (Server, Arc<AtomicUsize>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let server = server::http({
        let requests = requests.clone();
        move |req| {
            requests.fetch_add(1, Ordering::SeqCst);
            async move {
                if req.uri().path() == "/cross" {
                    let host = req.headers()["host"].to_str().unwrap();
                    let port = host.rsplit_once(':').unwrap().1;
                    http::Response::builder()
                        .status(302)
                        .header("location", format!("http://localhost:{port}/dst"))
                        .body(Body::default())
                        .unwrap()
                } else {
                    http::Response::new("ok".into())
                }
            }
        }
    });
    (server, requests)
}

async fn wait_for_close(server: &mut Server) -> bool {
    for _ in 0..200 {
        if server
            .events()
            .iter()
            .any(|event| matches!(event, Event::ConnectionClosed))
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn request_runs_over_the_stream_and_closes_it_on_drop() {
    let (mut server, requests) = counting_server();

    for run in 0..20 {
        let client = client_over(&server);
        let body = client
            .get(format!("http://{}/", server.addr()))
            .send()
            .await
            .unwrap_or_else(|err| panic!("run {run}: {}", error_chain(&err)))
            .text()
            .await
            .unwrap();
        assert_eq!(body, "ok");
        drop(client);
        assert!(
            wait_for_close(&mut server).await,
            "run {run}: the connection stayed open after the client dropped"
        );
    }
    assert_eq!(requests.load(Ordering::SeqCst), 20);
}

#[tokio::test(flavor = "multi_thread")]
async fn unused_stream_closes_when_the_client_drops() {
    let (mut server, requests) = counting_server();

    drop(client_over(&server));

    assert!(
        wait_for_close(&mut server).await,
        "the unused stream stayed open"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_to_another_host_fails_and_keeps_the_first_connection() {
    let (mut server, requests) = counting_server();
    let stream = TcpStream::connect(server.addr()).unwrap();
    let local_addr = stream.local_addr().unwrap();
    let client = client_with(stream);

    let err = client
        .get(format!("http://{}/cross", server.addr()))
        .send()
        .await
        .unwrap_err();

    assert!(err.is_connect());
    assert!(
        error_chain(&err)
            .contains("the preconnected stream carries a connection to another destination"),
        "{}",
        error_chain(&err)
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    // An immediate request can race the pool taking the connection back.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let res = client
        .get(format!("http://{}/", server.addr()))
        .send()
        .await
        .unwrap_or_else(|err| panic!("{}", error_chain(&err)));
    assert_eq!(res.local_addr(), Some(local_addr));
    assert_eq!(res.text().await.unwrap(), "ok");
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    drop(client);
    assert!(
        wait_for_close(&mut server).await,
        "the connection stayed open after the client dropped"
    );
}
