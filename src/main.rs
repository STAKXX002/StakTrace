use reqwest::blocking::Client;
use anyhow::{Context, Result};
use scraper::{Html, Selector};
use url::Url;
use colored::Colorize;
use std::collections::HashSet;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: staktrace <url>");
        std::process::exit(1);
    }

    let base_url = Url::parse(&args[1])
        .context("Invalid URL provided")?;

    println!("Scanning: {}\n", base_url);

    // Build a client with a proper User-Agent
    let client = Client::builder()
        .user_agent("StakTrace/0.1 (github.com/STAKXX002/StakTrace)")
        .build()
        .context("Failed to build HTTP client")?;

    let response = client.get(base_url.as_str())
        .send()
        .with_context(|| format!("Failed to reach {}", base_url))?;

    println!("Status: {}", response.status());

    let body = response.text()
        .context("Failed to read response body")?;

    let links = extract_links(&body, &base_url);

    // Deduplicate using a HashSet
    let unique_links: HashSet<String> = links.into_iter().collect();

    println!("Found {} unique links, checking...\n", unique_links.len());

    let mut dead = 0;
    let mut alive = 0;

    for link in &unique_links {
        match check_link(&client, link) {
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

fn check_link(client: &Client, url: &str) -> Result<reqwest::StatusCode> {
    let response = client.head(url)
        .send()
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