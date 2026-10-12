//! Shared HTTP deadlines and bounded response buffering.

use std::time::Duration;

use crate::browsers::{BrowserError, Result};

pub(crate) const METADATA_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const DOWNLOAD_TIMEOUT: Duration = Duration::from_mins(20);
pub(crate) const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_EXTENSION_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn build_client(total_timeout: Duration) -> Result<reqwest::Client> {
    client_with_limits(total_timeout, CONNECT_TIMEOUT, READ_TIMEOUT)
}

fn client_with_limits(
    total: Duration,
    connect: Duration,
    read: Duration,
) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("nomad-portable")
        .redirect(crate::downloader::redirect_policy())
        .connect_timeout(connect)
        .read_timeout(read)
        .timeout(total)
        .build()
        .map_err(map_network_err)
}

#[allow(clippy::needless_pass_by_value)] // map_err takes the error by value
pub(crate) fn map_network_err(error: reqwest::Error) -> BrowserError {
    // Strip the URL: upstream endpoints can carry private query data.
    let offline = error.is_connect()
        || error.is_timeout()
        || error.status() == Some(reqwest::StatusCode::FORBIDDEN);
    let message = error.without_url().to_string();
    if offline {
        BrowserError::Offline(message)
    } else {
        BrowserError::Network(message)
    }
}

pub(crate) async fn fetch_bytes(
    client: &reqwest::Client,
    url: &str,
    limit: usize,
) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(map_network_err)?
        .error_for_status()
        .map_err(map_network_err)?;
    read_body(response, limit).await
}

pub(crate) async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    let bytes = fetch_bytes(client, url, MAX_METADATA_BYTES).await?;
    String::from_utf8(bytes).map_err(|error| BrowserError::Parse(error.to_string()))
}

pub(crate) async fn read_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let too_large = || BrowserError::Network(format!("response exceeds the {limit} B limit"));
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_network_err)? {
        // Check before extending, including for chunked/undeclared responses.
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Read, Write};

    // A finite local socket fixture exposes headers and body separately, which
    // httpmock's whole-response delay cannot exercise. No upstream calls.
    pub(crate) fn socket_fixture(
        headers: &'static [u8],
        body: &'static [u8],
        delay: Duration,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/fixture", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            // Bound the fixture even if a broken client never connects.
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "client never connected"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            // Windows accepted sockets inherit the listener's non-blocking mode.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request);
            stream.write_all(headers).unwrap();
            std::thread::sleep(delay);
            let _ = stream.write_all(body); // client may already have aborted
        });
        (url, thread)
    }

    #[test]
    fn socket_fixture_waits_for_delayed_request() {
        let (url, server) = socket_fixture(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n",
            b"ok",
            Duration::ZERO,
        );
        let address = url
            .strip_prefix("http://")
            .unwrap()
            .trim_end_matches("/fixture");
        let mut client = std::net::TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        client
            .write_all(b"GET /fixture HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server.join().unwrap();
        assert!(response.ends_with("\r\n\r\nok"), "{response:?}");
    }

    #[tokio::test]
    async fn chunked_body_is_bounded_without_content_length() {
        let (url, server) = socket_fixture(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            b"4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n",
            Duration::ZERO,
        );
        let client = build_client(METADATA_TIMEOUT).unwrap();
        assert!(matches!(
            fetch_bytes(&client, &url, 6).await,
            Err(BrowserError::Network(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn stalled_body_times_out_after_headers() {
        let (url, server) = socket_fixture(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
            b"done",
            Duration::from_millis(250),
        );
        let client = client_with_limits(
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_millis(40),
        )
        .unwrap();
        assert!(matches!(
            fetch_bytes(&client, &url, 8).await,
            Err(BrowserError::Offline(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn declared_oversize_is_rejected_before_waiting_for_body() {
        let (url, server) = socket_fixture(
            b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\nConnection: close\r\n\r\n",
            b"done",
            Duration::from_millis(250),
        );
        let client = build_client(Duration::from_millis(80)).unwrap();
        assert!(matches!(
            fetch_bytes(&client, &url, 4).await,
            Err(BrowserError::Network(_))
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn body_at_exact_limit_succeeds() {
        let (url, server) = socket_fixture(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
            b"done",
            Duration::ZERO,
        );
        let client = build_client(METADATA_TIMEOUT).unwrap();
        assert_eq!(fetch_bytes(&client, &url, 4).await.unwrap(), b"done");
        server.join().unwrap();
    }
}
