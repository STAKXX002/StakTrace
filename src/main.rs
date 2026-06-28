use reqwest::Client;
use anyhow::{Context, Result};
use scraper::{Html, Selector};
use url::Url;
use colored::Colorize;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Semaphore;
use clap::Parser;

/// StakTrace — web security scanner
#[derive(Parser)]
#[command(name = "staktrace", version = "0.1", about = "Scans a webpage for dead links and security issues")]
struct Cli {
    /// URL to scan
    url: String,

    /// Use headless Chromium to render JS-heavy pages
    #[arg(long)]
    headless: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let base_url = Url::parse(&cli.url)
        .context("Invalid URL provided")?;

    println!("Scanning: {}\n", base_url);

    let client = Client::builder()
        .user_agent("StakTrace/0.1 (github.com/STAKXX002/StakTrace)")
        .build()
        .context("Failed to build HTTP client")?;

    let response = client.get(base_url.as_str())
        .send()
        .await
        .with_context(|| format!("Failed to reach {}", base_url))?;

    println!("Status: {}\n", response.status());

    // save headers before consuming the response
    let headers = response.headers().clone();

    // get the HTML — either via headless chromium or plain HTTP
    let body = if cli.headless {
        println!("{}", "Using headless Chromium to render page...".yellow());
        fetch_with_headless(base_url.as_str())
            .context("Headless fetch failed")?
    } else {
        response.text()
            .await
            .context("Failed to read response body")?
    };

    // --- security checks ---

    let issues = check_mixed_content(&body, &base_url);
    if issues.is_empty() {
        println!("{}", "✓ No mixed content found".green());
    } else {
        println!("{}", "✗ Mixed content detected:".red());
        for issue in &issues {
            println!("    {}", issue.yellow());
        }
    }
    println!();

    let leaks = check_internal_leaks(&body);
    if leaks.is_empty() {
        println!("{}", "✓ No internal URL leaks found".green());
    } else {
        println!("{}", "✗ Internal URL leaks detected:".red());
        for leak in &leaks {
            println!("    {}", leak.yellow());
        }
    }
    println!();

    print!("Checking security.txt... ");
    match check_security_txt(&client, &base_url).await {
        Some(contact) => println!("{}", contact.green()),
        None => println!("{}", "✗ No security.txt found".yellow()),
    }
    println!();

    let missing_headers = check_security_headers(&headers);
    if missing_headers.is_empty() {
        println!("{}", "✓ All security headers present".green());
    } else {
        println!("{}", "✗ Missing security headers:".red());
        for (header, reason) in &missing_headers {
            println!("    {} — {}", header.yellow(), reason);
        }
    }
    println!();

    // --- link checking ---

    let links = extract_links(&body, &base_url);
    let unique_links: HashSet<String> = links.into_iter().collect();

    println!("Found {} unique links, checking...\n", unique_links.len());

    let client = Arc::new(client);
    let semaphore = Arc::new(Semaphore::new(10));

    let mut handles = vec![];

    for link in unique_links {
        let client = Arc::clone(&client);
        let semaphore = Arc::clone(&semaphore);

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let result = check_link(&client, &link).await;
            (link, result)
        });

        handles.push(handle);
    }

    let mut dead = 0;
    let mut alive = 0;

    for handle in handles {
        let (link, result) = handle.await.context("Task panicked")?;

        match result {
            Ok(status) => {
                if status.is_success() {
                    println!("  {} {} ({})", "✓".green(), link, status);
                    alive += 1;
                } else {
                    println!("  {} {} ({})", "✗".red(), link, status);
                    dead += 1;
                }
            }
            Err(e) => {
                println!("  {} {} ({})", "✗".red(), link, e);
                dead += 1;
            }
        }
    }

    println!("\n{} alive, {} dead", alive.to_string().green(), dead.to_string().red());

    Ok(())
}

fn fetch_with_headless(url: &str) -> Result<String> {
    let output = std::process::Command::new("chromium-browser")
        .args([
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--virtual-time-budget=5000",
            "--dump-dom",
            url,
        ])
        .output()
        .context("Failed to launch chromium-browser")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Chromium exited with error: {}", stderr);
    }

    let html = String::from_utf8_lossy(&output.stdout).to_string();

    if html.trim().is_empty() {
        anyhow::bail!("Chromium returned empty output");
    }

    Ok(html)
}

async fn check_link(client: &Client, url: &str) -> Result<reqwest::StatusCode> {
    let response = client.head(url)
        .send()
        .await
        .with_context(|| format!("Request failed for {}", url))?;

    // HEAD not allowed — fall back to GET
    if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
        let get_response = client.get(url)
            .send()
            .await
            .with_context(|| format!("GET fallback failed for {}", url))?;
        return Ok(get_response.status());
    }

    // 403 means page exists but blocks bots — not a dead link
    if response.status() == reqwest::StatusCode::FORBIDDEN {
        return Ok(reqwest::StatusCode::OK);
    }

    Ok(response.status())
}

fn extract_links(html: &str, base: &Url) -> Vec<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").unwrap();

    document
        .select(&selector)
        .filter_map(|element| element.value().attr("href"))
        .filter_map(|href| base.join(href).ok())
        .filter(|url| url.scheme() == "http" || url.scheme() == "https")
        .map(|url| url.to_string())
        .collect()
}

fn check_mixed_content(html: &str, base: &Url) -> Vec<String> {
    if base.scheme() != "https" {
        return vec![];
    }

    let document = Html::parse_document(html);
    let mut issues = vec![];

    let checks = vec![
        ("a[href]",     "href"),
        ("img[src]",    "src"),
        ("script[src]", "src"),
        ("link[href]",  "href"),
    ];

    for (selector_str, attr) in checks {
        let selector = Selector::parse(selector_str).unwrap();
        for element in document.select(&selector) {
            if let Some(value) = element.value().attr(attr) {
                if value.starts_with("http://") {
                    issues.push(format!("{} → {}", selector_str, value));
                }
            }
        }
    }

    issues
}

fn check_internal_leaks(html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let mut leaks = vec![];

    let suspicious = vec![
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "192.168.",
        "10.0.",
        "10.1.",
        "172.16.",
        "172.17.",
        "::1",
        ":8080",
        ":3000",
        ":5000",
        ":8000",
        ":9000",
    ];

    let checks = vec![
        ("a[href]",      "href"),
        ("img[src]",     "src"),
        ("script[src]",  "src"),
        ("form[action]", "action"),
        ("iframe[src]",  "src"),
    ];

    for (selector_str, attr) in checks {
        let selector = Selector::parse(selector_str).unwrap();
        for element in document.select(&selector) {
            if let Some(value) = element.value().attr(attr) {
                for pattern in &suspicious {
                    if value.contains(pattern) {
                        leaks.push(format!("{} → {}", selector_str, value));
                        break;
                    }
                }
            }
        }
    }

    leaks
}

async fn check_security_txt(client: &Client, base: &Url) -> Option<String> {
    let well_known = format!(
        "{}://{}/.well-known/security.txt",
        base.scheme(),
        base.host_str().unwrap_or("")
    );

    let legacy = format!(
        "{}://{}/security.txt",
        base.scheme(),
        base.host_str().unwrap_or("")
    );

    for url in [&well_known, &legacy] {
        if let Ok(response) = client.get(url.as_str()).send().await {
            if response.status().is_success() {
                if let Ok(text) = response.text().await {
                    for line in text.lines() {
                        if line.starts_with("Contact:") {
                            return Some(format!("{} → {}", url, line));
                        }
                    }
                }
            }
        }
    }

    None
}

fn check_security_headers(headers: &reqwest::header::HeaderMap) -> Vec<(&'static str, &'static str)> {
    let required = vec![
        ("strict-transport-security", "Missing HSTS — browser may allow HTTP downgrade attacks"),
        ("content-security-policy",   "Missing CSP — XSS attacks can run arbitrary scripts"),
        ("x-frame-options",           "Missing X-Frame-Options — site can be clickjacked via iframe"),
        ("x-content-type-options",    "Missing X-Content-Type-Options — browser may misinterpret file types"),
        ("referrer-policy",           "Missing Referrer-Policy — URLs leak to third parties"),
        ("permissions-policy",        "Missing Permissions-Policy — camera/mic/location not restricted"),
    ];

    required
        .into_iter()
        .filter(|(header, _)| !headers.contains_key(*header))
        .collect()
}