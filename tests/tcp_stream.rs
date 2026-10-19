mod support;

use std::{
    error::Error as StdError,
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use support::server::{self, Event, Server};
use wreq::{Body, Client, redirect::Policy};

// The pool race needs worker threads and does not hit every run, so the redirect test repeats it.
const RUNS: usize = 50;

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

/// Redirects `/same` and `/same-close` to `/` on the same host and `/cross` to another host.
/// Answers every other path with "ok".
fn redirect_server() -> (Server, Arc<AtomicUsize>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let server = server::http({
        let requests = requests.clone();
        move |req| {
            requests.fetch_add(1, Ordering::SeqCst);
            async move {
                let host = req.headers()["host"].to_str().unwrap();
                let port = host.rsplit_once(':').unwrap().1;
                let redirect = |location: String| {
                    http::Response::builder()
                        .status(302)
                        .header("location", location)
                };
                match req.uri().path() {
                    "/same" => redirect("/".into()).body(Body::default()).unwrap(),
                    "/same-close" => redirect("/".into())
                        .header("connection", "close")
                        .body(Body::default())
                        .unwrap(),
                    "/cross" => redirect(format!("http://localhost:{port}/"))
                        .body(Body::default())
                        .unwrap(),
                    _ => http::Response::new("ok".into()),
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
    let (mut server, requests) = redirect_server();

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
    let (mut server, requests) = redirect_server();

    drop(client_over(&server));

    assert!(
        wait_for_close(&mut server).await,
        "the unused stream stayed open"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn same_host_redirect_reuses_the_stream_and_closes_it_on_drop() {
    let (mut server, requests) = redirect_server();

    for run in 0..RUNS {
        let client = client_over(&server);
        let res = client
            .get(format!("http://{}/same", server.addr()))
            .send()
            .await
            .unwrap_or_else(|err| panic!("run {run}: {}", error_chain(&err)));
        assert_eq!(res.uri().path(), "/");
        assert_eq!(res.text().await.unwrap(), "ok");
        drop(client);
        assert!(
            wait_for_close(&mut server).await,
            "run {run}: the connection stayed open after the client dropped"
        );
    }
    assert_eq!(requests.load(Ordering::SeqCst), 2 * RUNS);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_requests_wait_for_the_stream_and_close_it_on_drop() {
    let mut server = server::http(|_req| async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        http::Response::new("ok".into())
    });
    let client = client_over(&server);
    let url = format!("http://{}/", server.addr());

    let tasks: Vec<_> = (0..10)
        .map(|_| {
            let (client, url) = (client.clone(), url.clone());
            tokio::spawn(async move { client.get(url).send().await?.text().await })
        })
        .collect();

    for task in tasks {
        let body = task
            .await
            .unwrap()
            .unwrap_or_else(|err| panic!("{}", error_chain(&err)));
        assert_eq!(body, "ok");
    }

    drop(client);
    assert!(
        wait_for_close(&mut server).await,
        "the connection stayed open after the client dropped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_timeout_limits_the_wait() {
    let server = server::http(|req| async move {
        if req.uri().path() == "/slow" {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        http::Response::new("ok".into())
    });
    let client = Client::builder()
        .tcp_stream(TcpStream::connect(server.addr()).unwrap())
        .connect_timeout(Duration::from_millis(100))
        .build()
        .unwrap();

    let slow = tokio::spawn({
        let client = client.clone();
        let url = format!("http://{}/slow", server.addr());
        async move { client.get(url).send().await?.text().await }
    });
    // Let the slow request take the stream first.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = Instant::now();
    let err = client
        .get(format!("http://{}/", server.addr()))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_timeout(), "{}", error_chain(&err));
    assert!(started.elapsed() < Duration::from_millis(400));

    let body = slow
        .await
        .unwrap()
        .unwrap_or_else(|err| panic!("{}", error_chain(&err)));
    assert_eq!(body, "ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_to_another_host_fails_and_keeps_the_first_connection() {
    let (mut server, requests) = redirect_server();
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

#[tokio::test(flavor = "multi_thread")]
async fn redirect_after_connection_close_fails() {
    let (server, requests) = redirect_server();
    let client = client_over(&server);

    let err = client
        .get(format!("http://{}/same-close", server.addr()))
        .send()
        .await
        .unwrap_err();

    assert!(err.is_connect());
    assert!(
        error_chain(&err).contains("the connection on the preconnected stream is closed"),
        "{}",
        error_chain(&err)
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}
