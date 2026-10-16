use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use colored::Colorize;
use futures::{stream, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Url};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum HttpMethod {
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "paramtrace",
    version,
    about = "Fast HTTP parameter discovery for authorized security testing"
)]
struct Args {
    /// Target URL (http/https). May already contain a query string
    #[arg(short, long)]
    url: String,

    /// Wordlist file, one parameter per line ('#' comments allowed)
    #[arg(short, long)]
    wordlist: PathBuf,

    /// HTTP method
    #[arg(short, long, value_enum, default_value_t = HttpMethod::Get, ignore_case = true)]
    method: HttpMethod,

    /// Number of concurrent requests
    #[arg(short, long, default_value_t = 10)]
    threads: usize,

    /// Extra header, repeatable. Example: -H "Cookie: session=abc"
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Delay in milliseconds before each request
    #[arg(long, default_value_t = 0)]
    delay: u64,

    /// Allowed response-size difference (bytes) before a result counts as different
    #[arg(long, default_value_t = 0)]
    tolerance: usize,

    /// Value sent for each parameter (random per run if omitted)
    #[arg(long)]
    value: Option<String>,

    /// Route traffic through a proxy, e.g. http://127.0.0.1:8080 (Caido/Burp)
    #[arg(long)]
    proxy: Option<String>,

    /// Skip TLS certificate verification
    #[arg(short = 'k', long)]
    insecure: bool,

    /// User-Agent header
    #[arg(long, default_value = concat!("paramtrace/", env!("CARGO_PKG_VERSION")))]
    user_agent: String,

    /// Hide the startup banner
    #[arg(short, long)]
    quiet: bool,

    /// Write results to this file (overwrites)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output file format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text, ignore_case = true)]
    format: OutputFormat,
}

struct Ctx {
    client: Client,
    url: Url,
    method: HttpMethod,
    value: String,
    delay_ms: u64,
}

struct Probe {
    status: u16,
    len: usize,
    reflected: bool,
}

struct Baseline {
    statuses: HashSet<u16>,
    min_len: usize,
    max_len: usize,
    reflects: bool,
    tolerance: usize,
}

impl Baseline {
    fn diff(&self, p: &Probe) -> Option<Vec<String>> {
        let mut reasons = Vec::new();
        if !self.statuses.contains(&p.status) {
            reasons.push(format!("status changed to {}", p.status));
        }
        if p.len + self.tolerance < self.min_len || p.len > self.max_len + self.tolerance {
            reasons.push(format!(
                "size {} outside baseline {}-{}",
                p.len, self.min_len, self.max_len
            ));
        }
        if p.reflected && !self.reflects {
            reasons.push("value reflected".to_string());
        }
        if reasons.is_empty() {
            None
        } else {
            Some(reasons)
        }
    }
}

#[derive(Serialize)]
struct Finding {
    param: String,
    status: u16,
    size: usize,
    reasons: Vec<String>,
}

impl Finding {
    fn line(&self) -> String {
        format!(
            "[+] {:<20} | Status: {} | Size: {} | {}",
            self.param,
            self.status,
            self.size,
            self.reasons.join(", ")
        )
    }
}

const BANNER: &str = r#"
╔═╗┌─┐┬─┐┌─┐┌┬┐╔╦╗┬─┐┌─┐┌─┐┌─┐
╠═╝├─┤├┬┘├─┤│││ ║ ├┬┘├─┤│  ├┤
╩  ┴ ┴┴└─┴ ┴┴ ┴ ╩ ┴└─┴ ┴└─┘└─┘"#;

fn print_banner() {
    eprintln!("{}", BANNER.cyan());
    eprintln!(
        "  v{} | by {}\n  github.com/CurioTrace/paramtrace\n",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS")
    );
}

fn build_client(args: &Args) -> Result<Client> {
    let mut headers = HeaderMap::new();
    for raw in &args.headers {
        let (name, value) = raw
            .split_once(':')
            .with_context(|| format!("invalid header '{raw}', expected 'Name: value'"))?;
        headers.insert(
            HeaderName::from_bytes(name.trim().as_bytes())
                .with_context(|| format!("invalid header name in '{raw}'"))?,
            HeaderValue::from_str(value.trim())
                .with_context(|| format!("invalid header value in '{raw}'"))?,
        );
    }

    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(args.timeout))
        .user_agent(args.user_agent.as_str())
        .default_headers(headers)
        .danger_accept_invalid_certs(args.insecure);

    if let Some(proxy) = &args.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy).context("invalid proxy URL")?);
    }

    Ok(builder.build()?)
}

fn load_wordlist(path: &PathBuf) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("could not read wordlist {}", path.display()))?;
    let mut seen = HashSet::new();
    let mut params = Vec::new();
    for line in content.lines() {
        let word = line.trim();
        if word.is_empty() || word.starts_with('#') {
            continue;
        }
        if seen.insert(word.to_string()) {
            params.push(word.to_string());
        }
    }
    Ok(params)
}

async fn probe(ctx: &Ctx, name: &str) -> reqwest::Result<Probe> {
    let request = match ctx.method {
        HttpMethod::Get => {
            let mut url = ctx.url.clone();
            url.query_pairs_mut().append_pair(name, &ctx.value);
            ctx.client.get(url)
        }
        HttpMethod::Post => ctx
            .client
            .post(ctx.url.clone())
            .form(&[(name, ctx.value.as_str())]),
    };

    let response = request.send().await?;
    let status = response.status().as_u16();
    let body = response.bytes().await?;
    let reflected = String::from_utf8_lossy(&body).contains(ctx.value.as_str());

    Ok(Probe {
        status,
        len: body.len(),
        reflected,
    })
}

async fn establish_baseline(ctx: &Ctx, tolerance: usize) -> Result<Baseline> {
    let mut statuses = HashSet::new();
    let mut lengths = Vec::new();
    let mut reflects = false;

    for _ in 0..3 {
        let fake = format!("pt_{}", Uuid::new_v4().simple());
        let p = probe(ctx, &fake)
            .await
            .context("baseline request failed - is the target reachable?")?;
        statuses.insert(p.status);
        lengths.push(p.len);
        reflects |= p.reflected;
    }

    Ok(Baseline {
        statuses,
        min_len: *lengths.iter().min().unwrap_or(&0),
        max_len: *lengths.iter().max().unwrap_or(&0),
        reflects,
        tolerance,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let url = Url::parse(&args.url).context("invalid target URL")?;
    if url.scheme() != "http" && url.scheme() != "https" {
        bail!("URL must start with http:// or https://");
    }

    if !args.quiet {
        print_banner();
    }
    println!("[!] Only scan targets you are authorized to test.");
    println!("[*] Target: {}", url);
    println!("[*] Method: {:?}", args.method);

    let params = load_wordlist(&args.wordlist)?;
    if params.is_empty() {
        bail!("wordlist has no usable entries");
    }
    println!("[*] Loaded {} parameters", params.len().to_string().cyan());

    let value = args
        .value
        .clone()
        .unwrap_or_else(|| format!("pt{}", &Uuid::new_v4().simple().to_string()[..8]));

    let ctx = Arc::new(Ctx {
        client: build_client(&args)?,
        url,
        method: args.method,
        value,
        delay_ms: args.delay,
    });

    println!("{}", "[*] Establishing baseline...".yellow());
    let baseline = Arc::new(establish_baseline(&ctx, args.tolerance).await?);
    println!(
        "[*] Baseline | statuses: {:?} | size: {}-{}",
        baseline.statuses, baseline.min_len, baseline.max_len
    );

    let pb = ProgressBar::new(params.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )?
            .progress_chars("#>-"),
    );

    let errors = Arc::new(AtomicUsize::new(0));
    let concurrency = args.threads.max(1);

    let mut results = stream::iter(params)
        .map(|name| {
            let ctx = Arc::clone(&ctx);
            let baseline = Arc::clone(&baseline);
            let errors = Arc::clone(&errors);
            let pb = pb.clone();
            async move {
                if ctx.delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(ctx.delay_ms)).await;
                }
                let outcome = probe(&ctx, &name).await;
                pb.inc(1);
                match outcome {
                    Ok(p) => baseline.diff(&p).map(|reasons| Finding {
                        param: name,
                        status: p.status,
                        size: p.len,
                        reasons,
                    }),
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }
        })
        .buffer_unordered(concurrency);

    let mut findings: Vec<Finding> = Vec::new();
    while let Some(result) = results.next().await {
        if let Some(finding) = result {
            pb.println(finding.line().green().to_string());
            findings.push(finding);
        }
    }
    pb.finish_and_clear();

    let error_count = errors.load(Ordering::Relaxed);
    if error_count > 0 {
        println!(
            "{}",
            format!("[!] {error_count} requests failed (timeouts/connection errors); results may be incomplete").yellow()
        );
    }

    if let Some(path) = &args.output {
        let content = match args.format {
            OutputFormat::Text => {
                let mut s = findings
                    .iter()
                    .map(Finding::line)
                    .collect::<Vec<_>>()
                    .join("\n");
                s.push('\n');
                s
            }
            OutputFormat::Json => serde_json::to_string_pretty(&findings)?,
        };
        fs::write(path, content).with_context(|| format!("could not write {}", path.display()))?;
        println!(
            "{}",
            format!("[*] Saved results to {}", path.display()).cyan()
        );
    }

    println!(
        "{}",
        format!("[*] Done. {} parameter(s) flagged.", findings.len()).green()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> Baseline {
        Baseline {
            statuses: HashSet::from([200]),
            min_len: 1000,
            max_len: 1010,
            reflects: false,
            tolerance: 0,
        }
    }

    #[test]
    fn same_response_is_ignored() {
        let p = Probe {
            status: 200,
            len: 1005,
            reflected: false,
        };
        assert!(baseline().diff(&p).is_none());
    }

    #[test]
    fn status_change_is_flagged() {
        let p = Probe {
            status: 500,
            len: 1005,
            reflected: false,
        };
        assert!(baseline().diff(&p).is_some());
    }

    #[test]
    fn size_change_is_flagged() {
        let p = Probe {
            status: 200,
            len: 2000,
            reflected: false,
        };
        assert!(baseline().diff(&p).is_some());
    }

    #[test]
    fn reflection_is_flagged() {
        let p = Probe {
            status: 200,
            len: 1005,
            reflected: true,
        };
        assert!(baseline().diff(&p).is_some());
    }

    #[test]
    fn tolerance_absorbs_small_changes() {
        let mut b = baseline();
        b.tolerance = 50;
        let p = Probe {
            status: 200,
            len: 1040,
            reflected: false,
        };
        assert!(b.diff(&p).is_none());
    }
}
