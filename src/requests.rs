use std::time::Duration;

pub fn get(url: impl Into<String>, ssl: bool, timeout: u64) -> Result<String, reqwest::Error> {
    let client = reqwest::blocking::ClientBuilder::new()
        .trust_dns(true)
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(timeout));
    Ok(client
        .build()?
        .get(site(url, ssl))
        .header("Connection", "close")
        .send()?
        .text()?)
}

fn site(url: impl Into<String>, ssl: bool) -> String {
    if ssl {
        return format!("https://{}", url.into());
    }

    format!("http://{}", url.into())
}
