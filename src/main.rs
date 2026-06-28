use reqwest::Client;
use anyhow::{Context, Result};
use scraper::{Html, Selector};
use url::Url;
use colored::Colorize;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: staktrace <url>");
        std::process::exit(1);
    }

    let base_url = Url::parse(&args[1])
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

    let body = response.text()
        .await
        .context("Failed to read response body")?;

    // --- security checks (all use the raw body, run before link checking) ---

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

async fn check_link(client: &Client, url: &str) -> Result<reqwest::StatusCode> {
    let response = client.head(url)
        .send()
        .await
        .with_context(|| format!("Request failed for {}", url))?;

    Ok(response.status())
}

fn extract_links(html: &str, base: &Url) -> Vec<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").unwrap();

    document
        .select(&selector)
        .filter_map(|element| element.value().attr("href"))
        .filter_map(|href| base.join(href).ok())
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