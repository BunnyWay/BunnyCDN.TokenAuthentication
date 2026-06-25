//! Emits canonical e2e tokens produced by the Rust signer.
//!
//! Reads ../e2e/inputs.json (relative to rust/), signs each case with the
//! Rust signer, extracts the token from the returned URL, and prints a single
//! JSON object mapping case name -> token to stdout.
//!
//! Run from the rust/ directory:
//!     cargo run --example emit

use std::collections::BTreeMap;

use bunnycdn_token_authentication::sign_url;
use serde::Deserialize;

#[derive(Deserialize)]
struct Inputs {
    key: String,
    expires: i64,
    host: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    path: String,
    #[serde(rename = "userIp")]
    user_ip: String,
    #[serde(rename = "isDirectory")]
    is_directory: bool,
    #[serde(rename = "pathAllowed")]
    path_allowed: String,
    #[serde(rename = "countriesAllowed")]
    countries_allowed: String,
    #[serde(rename = "countriesBlocked")]
    countries_blocked: String,
    #[serde(rename = "ignoreParams")]
    ignore_params: bool,
    #[serde(rename = "speedLimit")]
    speed_limit: i64,
    // countryCode is intentionally ignored for signing.
}

/// Extract the token from a signed URL: the substring after "bcdn_token="
/// if present, otherwise after "token=", up to the next "&".
fn extract_token(url: &str) -> &str {
    let start = if let Some(idx) = url.find("bcdn_token=") {
        idx + "bcdn_token=".len()
    } else if let Some(idx) = url.find("token=") {
        idx + "token=".len()
    } else {
        return "";
    };
    let rest = &url[start..];
    match rest.find('&') {
        Some(end) => &rest[..end],
        None => rest,
    }
}

fn main() {
    let raw = std::fs::read_to_string("../e2e/inputs.json")
        .expect("failed to read ../e2e/inputs.json (run from the rust/ directory)");
    let inputs: Inputs = serde_json::from_str(&raw).expect("failed to parse inputs.json");

    // BTreeMap keeps output deterministic by name.
    let mut out: BTreeMap<String, String> = BTreeMap::new();

    for case in &inputs.cases {
        let url = format!("{}{}", inputs.host, case.path);
        let signed = sign_url(
            &url,
            &inputs.key,
            86400,
            &case.user_ip,
            case.is_directory,
            &case.path_allowed,
            &case.countries_allowed,
            &case.countries_blocked,
            case.ignore_params,
            Some(inputs.expires),
            case.speed_limit,
        )
        .unwrap_or_else(|e| panic!("sign_url failed for case '{}': {e}", case.name));

        out.insert(case.name.clone(), extract_token(&signed).to_string());
    }

    println!("{}", serde_json::to_string(&out).expect("failed to serialize output"));
}
