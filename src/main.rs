use clap::Parser;
use std::fs::File;
use std::io::{BufReader, Read};
use sha2::{Sha256, Digest};
use md5;
use sha1::{Sha1, Digest as Sha1Digest};
use chrono::Local;
use reqwest::Client;
use tokio;
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "windows")] {
        use windows::core::PCSTR;
        use windows::Win32::Foundation::{HANDLE, CloseHandle};
        use windows::Win32::System::Diagnostics::Debug::{MiniDumpWriteDump, MINIDUMP_TYPE};
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,PROCESS_DUP_HANDLE};
        use std::os::windows::io::AsRawHandle;

        fn create_memory_dump(pid: u32, dump_file_path: &str) -> windows::core::Result<()> {
            unsafe {
                let process_handle: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , false, pid)?;

                if process_handle.is_invalid() {
                    return Err(windows::core::Error::from_win32());
                }

                let file = File::create(dump_file_path)?;
                let file_handle = HANDLE(file.as_raw_handle() as isize);

                let result = MiniDumpWriteDump(
                    process_handle,
                    pid,
                    file_handle,
                    MINIDUMP_TYPE(0x00000002), // MINIDUMP_TYPE_MiniDumpWithFullMemory
                    None,
                    None,
                    None,
                );

                CloseHandle(process_handle);

                if result.is_err() {
                    return Err(result.err().unwrap());
                }
            }

            Ok(())
        }
    } else if #[cfg(target_os = "linux")] {
        use std::io::copy;
        use std::fs::OpenOptions;

        fn create_memory_dump(pid: u32, dump_file_path: &str) -> std::io::Result<()> {
            let mem_path = format!("/proc/{}/mem", pid);
            let mut mem_file = OpenOptions::new().read(true).open(mem_path)?;
            let mut dump_file = File::create(dump_file_path)?;

            copy(&mut mem_file, &mut dump_file)?;
            Ok(())
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

async fn get_vt_report(api_key: &str, file_hash: &str) -> Result<serde_json::Value, reqwest::Error> {
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

fn generate_dump_filename(pid: u32) -> String {
    let now = Local::now();
    format!("{}_{}.dmp", pid, now.format("%Y%m%d_%H%M%S"))
}

#[derive(Parser)]
#[command(name = "memory_dumper")]
#[command(about = "A tool to create a memory dump of a specific process and analyze it using VirusTotal")]
struct Cli {
    #[arg(short, long)]
    pid: u32,

    #[arg(short, long)]
    api_key: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let dump_file_path = generate_dump_filename(cli.pid);

    match create_memory_dump(cli.pid, &dump_file_path) {
        Ok(_) => println!("Memory dump created successfully at {}", &dump_file_path),
        Err(e) => {
            eprintln!("Failed to create memory dump: {:?}", e);
            return;
        },
    }

    match calculate_hash(&dump_file_path) {
        Ok((md5, sha1, sha256)) => {
            println!("MD5: {}", md5);
            println!("SHA-1: {}", sha1);
            println!("SHA-256: {}", sha256);

            for file_hash in [&md5, &sha1, &sha256] {
                match get_vt_report(&cli.api_key, file_hash).await {
                    Ok(report) => println!("VirusTotal Report for Hash ({}):\n{:#?}", file_hash, report),
                    Err(e) => eprintln!("Failed to retrieve report from VirusTotal for hash {}: {:?}", file_hash, e),
                }
            }
        },
        Err(e) => eprintln!("Failed to calculate hash: {:?}", e),
    }
}
