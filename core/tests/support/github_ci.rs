//! Test-only authenticated transport for live Chromium release metadata.
//! The response is relayed unchanged to the production parser. No credential
//! reaches the updater, archive requests, localhost server or shipped binaries.

use std::time::Duration;

const LATEST: &str =
    "https://api.github.com/repos/ungoogled-software/ungoogled-chromium-windows/releases/latest";
const MAX_METADATA: usize = 16 * 1024 * 1024;
type Error = Box<dyn std::error::Error + Send + Sync>;

fn client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent("nomad-ci-upstream-check")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60))
        .build()
}

fn release_request(client: &reqwest::Client, token: &str) -> Result<reqwest::Request, Error> {
    if token.is_empty() {
        return Err("empty CI GitHub token".into());
    }
    let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "invalid CI GitHub token")?;
    authorization.set_sensitive(true);
    Ok(client
        .get(LATEST)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .build()?)
}

async fn read_metadata(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, Error> {
    // error_for_status alone accepts redirects. Never follow or relay one.
    if !response.status().is_success() {
        return Err(format!("GitHub metadata returned HTTP {}", response.status()).into());
    }
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err("GitHub metadata exceeds size limit".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err("GitHub metadata exceeds size limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub async fn chromium_metadata() -> Result<Option<httpmock::MockServer>, Error> {
    let token = match std::env::var("NOMAD_CI_GITHUB_TOKEN") {
        Ok(token) => token,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err("CI GitHub token is not valid text".into()),
    };
    let client = client()?;
    let request = release_request(&client, &token)?;
    drop(token);
    let bytes = read_metadata(client.execute(request).await?, MAX_METADATA).await?;
    let server = httpmock::MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(httpmock::Method::GET).path("/releases/latest");
            then.status(200).body(bytes);
        })
        .await;
    Ok(Some(server))
}

#[test]
fn ci_token_is_sensitive_and_scoped_to_one_fixed_request() {
    let client = client().unwrap();
    let request = release_request(&client, "inert-fixture-token").unwrap();
    assert_eq!(request.url().as_str(), LATEST);
    let header = &request.headers()[reqwest::header::AUTHORIZATION];
    assert_eq!(header, "Bearer inert-fixture-token");
    assert!(header.is_sensitive());
    let archive = client
        .get("https://downloads.invalid/archive.zip")
        .build()
        .unwrap();
    assert!(!archive
        .headers()
        .contains_key(reqwest::header::AUTHORIZATION));
    assert!(release_request(&client, "").is_err());
    assert!(release_request(&client, "invalid\ntoken").is_err());
}

#[tokio::test]
async fn ci_metadata_rejects_redirects_and_oversized_bodies() {
    use httpmock::prelude::*;
    let server = MockServer::start_async().await;
    let destination = server
        .mock_async(|when, then| {
            when.path("/destination");
            then.status(200).body("must not be followed");
        })
        .await;
    server
        .mock_async(|when, then| {
            when.path("/redirect");
            then.status(302)
                .header("location", server.url("/destination"));
        })
        .await;
    server
        .mock_async(|when, then| {
            when.path("/large");
            then.status(200).body(vec![b'x'; 65]);
        })
        .await;
    server
        .mock_async(|when, then| {
            when.path("/forbidden");
            then.status(403).body("rate limited");
        })
        .await;
    let live_bytes = b"{\n  \"tag_name\": \"fixture\"\n}\n";
    server
        .mock_async(|when, then| {
            when.path("/success");
            then.status(200).body(live_bytes);
        })
        .await;
    let client = client().unwrap();
    for path in ["/redirect", "/large", "/forbidden"] {
        let response = client.get(server.url(path)).send().await.unwrap();
        assert!(read_metadata(response, 64).await.is_err());
    }
    let response = client.get(server.url("/success")).send().await.unwrap();
    assert_eq!(read_metadata(response, 64).await.unwrap(), live_bytes);
    destination.assert_calls_async(0).await;
}
