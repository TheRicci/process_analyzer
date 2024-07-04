use clap::Parser;
use std::fs::File;
use std::io::{BufReader, Read};
use sha2::{Sha256, Digest};
use md5;
use sha1::{Sha1, Digest as Sha1Digest};
use chrono::Local;
use reqwest::Client;
use tokio;
use std::fs;
use std::path::Path;
use std::process::Command;
use serde_json::Value;
use std::collections::HashSet;

async fn get_vt_report(api_key: &str, file_hash: &str) -> Result<Value, reqwest::Error> {
    let url = format!("https://www.virustotal.com/api/v3/files/{}", file_hash);
    let client = Client::new();
    
    let response = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await?;
    
    let report = response.json().await?;
    Ok(report)
}

fn summarize_vt_report(report: &Value) {
    if let Some(data) = report.get("data") {
        if let Some(attributes) = data.get("attributes") {
            if let Some(last_analysis_stats) = attributes.get("last_analysis_stats") {
                println!("Analysis Stats:");
                println!("  Harmless: {}", last_analysis_stats["harmless"]);
                println!("  Malicious: {}", last_analysis_stats["malicious"]);
                println!("  Suspicious: {}", last_analysis_stats["suspicious"]);
                println!("  Undetected: {}", last_analysis_stats["undetected"]);
            }

            if let Some(last_analysis_results) = attributes.get("last_analysis_results") {
                println!("\nDetailed Results:");
                for (engine, result) in last_analysis_results.as_object().unwrap() {
                    println!("  {}: {}", engine, result["category"]);
                }
            }
        }
    }
}

fn calculate_hash(file_path: &str) -> std::io::Result<(String, String, String)> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);

    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;

    let md5_hash = format!("{:x}", md5::compute(&buffer));
    let sha1_hash = format!("{:x}", Sha1::digest(&buffer));
    let sha256_hash = format!("{:x}", Sha256::digest(&buffer));

    Ok((md5_hash, sha1_hash, sha256_hash))
}

fn get_process_files(pid: u32) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();
    
    // Get the main executable path
    let exe_path = Command::new("wmic")
        .args(&["process", "where", &format!("ProcessId={}", pid), "get", "ExecutablePath"])
        .output()?;
    
    let exe_path_str = String::from_utf8_lossy(&exe_path.stdout);
    println!("Executable Path Output: {}", exe_path_str); // Debug output
    let exe_file = exe_path_str.lines().nth(1).unwrap_or("").trim();
    
    if !exe_file.is_empty() {
        files.push(exe_file.to_string());
    }
    
    // Get loaded modules (DLLs)
    let modules = Command::new("wmic")
        .args(&["process", "where", &format!("ProcessId={}", pid), "get", "Modules"])
        .output()?;
    
    let modules_str = String::from_utf8_lossy(&modules.stdout);
    println!("Modules Output: {}", modules_str); // Debug output
    for line in modules_str.lines().skip(1) {
        let module = line.trim();
        if !module.is_empty() {
            files.push(module.to_string());
        }
    }
    
    Ok(files)
}

#[derive(Parser)]
#[command(name = "process_analyzer")]
#[command(about = "A tool to analyze a specific process and its related files using VirusTotal")]
struct Cli {
    #[arg(short, long)]
    pid: u32,

    #[arg(short, long)]
    api_key: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    println!("PID: {}", cli.pid); // Debug output
    println!("API Key: {}", cli.api_key); // Debug output
    
    match get_process_files(cli.pid) {
        Ok(files) => {
            println!("Files: {:?}", files); // Debug output
            let mut unique_hashes = HashSet::new();
            
            for file_path in files {
                match calculate_hash(&file_path) {
                    Ok((md5, sha1, sha256)) => {
                        if unique_hashes.insert(md5.clone()) {
                            println!("MD5: {}", md5);
                            println!("SHA-1: {}", sha1);
                            println!("SHA-256: {}", sha256);

                            for file_hash in [&md5, &sha1, &sha256] {
                                match get_vt_report(&cli.api_key, file_hash).await {
                                    Ok(report) => {
                                        println!("VirusTotal Report for Hash ({}):", file_hash);
                                        summarize_vt_report(&report);
                                    },
                                    Err(e) => eprintln!("Failed to retrieve report from VirusTotal for hash {}: {:?}", file_hash, e),
                                }
                            }
                        }
                    },
                    Err(e) => eprintln!("Failed to calculate hash for file {}: {:?}", file_path, e),
                }
            }
        },
        Err(e) => eprintln!("Failed to get process files: {:?}", e),
    }
}
