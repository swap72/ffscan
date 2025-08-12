use clap::{Parser, Subcommand, ValueEnum};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use walkdir::WalkDir;
use sysinfo::{Disks, Pid, Signal, System};

#[derive(Parser, Debug)]
#[command(
    name = "fscan",
    version,
    about = "Fast directory & process scanner: scan large files/folders, list/kill processes, and print system info."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// About and credits
    About,

    /// Scan a directory
    Scan(ScanArgs),

    /// List running processes sorted by memory (highest first)
    P,

    /// Kill a running process by PID
    Kill(KillArgs),

    /// Print detailed system information (plain key:value lines)
    #[command(name = "sysinfo")]
    SysInfo,
}


#[derive(Parser, Debug)]
struct ScanArgs {
    /// Path to scan
    path: String,

    /// Output format: csv, json, or summary
    #[arg(value_enum)]
    output: OutputFormat,

    /// Minimum size filter: skip64, skip128, skip256, skip512, skip1024, skip2048 (in MB)
    #[arg()]
    skip: Option<SkipLimit>,

    /// Exclude empty folders from final output
    #[arg(long)]
    exclude_empty: bool,
}

#[derive(Parser, Debug)]
struct KillArgs {
    /// PID of the process to kill
    pid: u32,

    /// Force kill (SIGKILL on Unix / Terminate on Windows)
    #[arg(long)]
    force: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    Csv,
    Json,
    Summary,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum SkipLimit {
    Skip64,
    Skip128,
    Skip256,
    Skip512,
    Skip1024,
    Skip2048,
}

#[derive(Serialize)]
struct FileEntry {
    path: String,
    size_bytes: u64,
    size_human: String,
    kind: String,
}

fn format_size(size: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < units.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{:.2} {}", size, units[unit])
}

fn format_duration(secs: u64) -> String {
    let d = Duration::from_secs(secs);
    let days = d.as_secs() / 86_400;
    let hours = (d.as_secs() % 86_400) / 3600;
    let mins = (d.as_secs() % 3600) / 60;
    let s = d.as_secs() % 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m {s}s")
    } else if hours > 0 {
        format!("{hours}h {mins}m {s}s")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::About => {
            println!("name: fscan");
            println!("version: {}", env!("CARGO_PKG_VERSION"));
            println!("description: scan large files/folders, list/kill processes, print system info");
            println!("license: MIT");
            println!("repo: https://github.com/swap72/fscan");
            println!("author: Swapnil Mishra");
        }
        Commands::Scan(args) => run_scan(args),
        Commands::P => scan_processes(),
        Commands::Kill(args) => kill_process(args.pid, args.force),
        Commands::SysInfo => show_system_info(),
    }
}

fn run_scan(cli: &ScanArgs) {
    let min_size = match cli.skip {
        Some(SkipLimit::Skip64) => Some(64 * 1024 * 1024),
        Some(SkipLimit::Skip128) => Some(128 * 1024 * 1024),
        Some(SkipLimit::Skip256) => Some(256 * 1024 * 1024),
        Some(SkipLimit::Skip512) => Some(512 * 1024 * 1024),
        Some(SkipLimit::Skip1024) => Some(1024 * 1024 * 1024),
        Some(SkipLimit::Skip2048) => Some(2048 * 1024 * 1024),
        None => None,
    };

    if let Some(limit) = min_size {
        println!("filter_min_size: {}", format_size(limit));
    }

    let file_sizes: Arc<Mutex<HashMap<PathBuf, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let dir_sizes: Arc<Mutex<HashMap<PathBuf, u64>>> = Arc::new(Mutex::new(HashMap::new()));

    WalkDir::new(&cli.path)
        .into_iter()
        .filter_map(Result::ok)
        .par_bridge()
        .filter(|e| e.file_type().is_file())
        .for_each(|entry| {
            let path = entry.path().to_path_buf();
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

            if let Some(limit) = min_size {
                if size <= limit {
                    return;
                }
            }

            {
                let mut fsizes = file_sizes.lock().unwrap();
                fsizes.insert(path.clone(), size);
            }

            let mut current = path.parent();
            while let Some(parent) = current {
                {
                    let mut dsizes = dir_sizes.lock().unwrap();
                    *dsizes.entry(parent.to_path_buf()).or_insert(0) += size;
                }
                current = parent.parent();
            }
        });

    let fsizes = file_sizes.lock().unwrap();
    let dsizes = dir_sizes.lock().unwrap();

    let mut entries: Vec<FileEntry> = Vec::with_capacity(fsizes.len() + dsizes.len());

    for (path, size) in fsizes.iter() {
        entries.push(FileEntry {
            path: path.display().to_string(),
            size_bytes: *size,
            size_human: format_size(*size),
            kind: "File".to_string(),
        });
    }
    for (path, size) in dsizes.iter() {
        entries.push(FileEntry {
            path: path.display().to_string(),
            size_bytes: *size,
            size_human: format_size(*size),
            kind: "Directory".to_string(),
        });
    }

    if cli.exclude_empty {
        entries.retain(|e| !(e.kind == "Directory" && e.size_bytes == 0));
    }

    entries.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

    for e in &entries {
        println!("size: {}", e.size_human);
        println!("kind: {}", e.kind);
        println!("path: {}", e.path);
        println!();
    }

    match cli.output {
        OutputFormat::Csv => {
            if let Ok(mut file) = File::create("output.csv") {
                writeln!(file, "path,size_bytes,size_human,kind").unwrap();
                for e in &entries {
                    writeln!(file, "\"{}\",{},{},{}", e.path, e.size_bytes, e.size_human, e.kind)
                        .unwrap();
                }
                println!("export: output.csv");
            }
        }
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(&entries) {
                fs::write("output.json", json).unwrap();
                println!("export: output.json");
            }
        }
        OutputFormat::Summary => {
            let total_files = fsizes.len();
            let total_dirs = dsizes.len();
            let total_file_size: u64 = fsizes.values().sum();
            let total_dir_size: u64 = dsizes.values().sum();
            let total_size = total_file_size + total_dir_size;

            println!("summary_total_files: {}", total_files);
            println!("summary_total_dirs: {}", total_dirs);
            println!("summary_total_size: {}", format_size(total_size));

            let mut dir_list: Vec<_> = dsizes.iter().collect();
            dir_list.sort_by(|a, b| b.1.cmp(a.1));
            for (i, (path, size)) in dir_list.iter().take(5).enumerate() {
                println!("top_dir_{}: {} ({})", i + 1, path.display(), format_size(**size));
            }

            let mut file_list: Vec<_> = fsizes.iter().collect();
            file_list.sort_by(|a, b| b.1.cmp(a.1));
            for (i, (path, size)) in file_list.iter().take(5).enumerate() {
                println!("top_file_{}: {} ({})", i + 1, path.display(), format_size(**size));
            }
        }
    }
}

fn scan_processes() {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut processes: Vec<_> = sys.processes().values().collect();
    // In sysinfo 0.30, memory() returns bytes.
    processes.sort_by(|a, b| b.memory().cmp(&a.memory())); // highest memory first

    let total_memory_mb: f64 = processes
        .iter()
        .map(|p| p.memory() as f64 / (1024.0 * 1024.0))
        .sum();

    println!("total_processes: {}", processes.len());
    println!("total_memory_mb: {:.2}", total_memory_mb);
    println!();

    for p in &processes {
        println!("pid: {}", p.pid());
        println!("name: {}", p.name());
        println!("memory_mb: {:.2}", p.memory() as f64 / (1024.0 * 1024.0));
        println!();
    }
}

fn kill_process(pid_u32: u32, force: bool) {
    let mut sys = System::new_all();
    sys.refresh_all();

    let pid = Pid::from_u32(pid_u32);

    if let Some(process) = sys.process(pid) {
        let signal = if force { Signal::Kill } else { Signal::Term };
        let ok = process.kill_with(signal).unwrap_or_else(|| process.kill());
        if ok {
            println!("killed: true");
            println!("pid: {}", pid_u32);
            println!("name: {}", process.name());
            println!("signal: {}", if force { "KILL" } else { "TERM" });
        } else {
            println!("killed: false");
            println!("pid: {}", pid_u32);
            println!("name: {}", process.name());
        }
    } else {
        println!("killed: false");
        println!("pid: {}", pid_u32);
        println!("error: not_found");
    }
}

fn show_system_info() {
    let mut sys = System::new_all();
    sys.refresh_all();

    // CPU info
    let cpus = sys.cpus();
    let logical_cores = cpus.len();
    let physical_cores = sys.physical_core_count().unwrap_or(0);
    let (cpu_brand, cpu_name) = if let Some(c0) = cpus.get(0) {
        (c0.brand(), c0.name())
    } else {
        ("Unknown", "Unknown")
    };

    // OS / host
    let arch = std::env::consts::ARCH;
    let os_name = System::name().unwrap_or_else(|| "Unknown OS".to_string());
    let kernel = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
    let host = System::host_name().unwrap_or_else(|| "Unknown".to_string());
    let uptime = format_duration(System::uptime());

    // Memory (0.30 returns bytes)
    let total_mem_bytes = sys.total_memory();
    let used_mem_bytes = sys.used_memory();
    let total_swap_bytes = sys.total_swap();
    let used_swap_bytes = sys.used_swap();

    println!("host: {}", host);
    println!("os: {} {}", os_name, os_version);
    println!("kernel: {}", kernel);
    println!("arch: {}", arch);
    println!("uptime: {}", uptime);
    println!("cpu_brand: {}", cpu_brand);
    println!("cpu_name: {}", cpu_name);
    println!("physical_cores: {}", physical_cores);
    println!("logical_cores: {}", logical_cores);
    println!("memory_used: {}", format_size(used_mem_bytes));
    println!("memory_total: {}", format_size(total_mem_bytes));
    println!("swap_used: {}", format_size(used_swap_bytes));
    println!("swap_total: {}", format_size(total_swap_bytes));

    // Disks are no longer on System in 0.30; use the Disks collection.
let disks = Disks::new_with_refreshed_list();
for d in &disks {
    let name = d.name().to_string_lossy().to_string();
    let total = d.total_space();
    let avail = d.available_space();
    let used = total.saturating_sub(avail);
    let fs = d.file_system().to_string_lossy().into_owned();

    println!("disk_name: {}", name);
    println!("disk_fs: {}", fs);
    println!("disk_used: {}", format_size(used));
    println!("disk_total: {}", format_size(total));
    println!("disk_free: {}", format_size(avail));
}

}
