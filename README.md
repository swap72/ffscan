# [Fast Ferris Scanner](https://i.ibb.co/39ZjMmC4/2-3.png)⚡[🦀](https://swapnil-mishra.imgbb.com/)

# Scan a directory and print a summary, skipping files smaller than 1024 Megabytes
ffscan scan c:\users summary skip1024

# Exclude empty folders from the scan
ffscan scan /home/user/ summary --exclude-empty

# Display about information and credits
ffscan about

# Show help with available flags and options
ffscan --help

## ⚙️ Features

- 🚀 Fast parallel scanning (Rayon)
- 📏 Minimum-size filter to skip small files
- 📂 Option to exclude empty folders
- 📊 Output formats: `csv`, `json`, `plain text summary`
- 🖥 Processes listed by memory usage (highest first)
- 💀 Kill processes by PID (`--force` supported)
- 🧰 Cross-platform (Windows, Linux, macOS)

# Download and Install :
run `cargo install ffscan` on your termial / cmd / or your fav shell  
register it on the path of you system and start using it

# ffscan

[![Crates.io](https://img.shields.io/crates/v/ffscan.svg)](https://crates.io/crates/ffscan)
[![Downloads](https://img.shields.io/crates/d/ffscan.svg)](https://crates.io/crates/ffscan)


## ⚙️ Output Formats

- **csv**: Save results to `output.csv`
- **json**: Save results to `output.json`
- **summary**: Print a human-readable summary to the console

---

## 📂 Example output

**2.50 GB [Directory] - C:\Users\Tushar\Documents\Projects**  
**1.20 GB [File] - C:\Users\Tushar\Videos\movie.mp4**


---

## 📁 Project Structure
```
fscan/
├── Cargo.toml           # Project metadata & dependencies
├── Cargo.lock           # Locked dependency versions (auto-generated)
├── LICENSE              # LICENSE.txt
├── README.md            # 📄 Project documentation (GitHub flavored)
├── .gitignore           # Ignore build artifacts & output files
├── output.csv           # Example output file (should be gitignored)
├── output.json          # Example output file (should be gitignored)
├── src/
│   ├── main.rs          # Main entry point: parses CLI & calls logic
│   ├── cli.rs           # (Optional) CLI parsing module if you split
│   ├── scanner.rs       # (Optional) Scanning logic module
│   └── utils.rs         # (Optional) Utility functions (e.g., format_size)
└── .github/
    └── workflows/
        └── rust.yml     # (Optional) CI workflow for testing/building
```
---

## 📝 License

This project is licensed under the MIT License.  
See [LICENSE](https://github.com/swap72/fscan/blob/main/LICENSE.txt.txt) for details.

---

## 🙌 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

---

## 💖 Show your support
🌱 Feel free to modify and distribute this CLI tool  
⭐️ Star or fork this repo on GitHub if you find it useful!  
🔗 [Formal Portfolio](https://swap72.github.io/portfolio/)  
🔗 [Not so formal Portfolio](http://swapnil.bio.link/)  
🚀 Built with ❤️ and Rust 🦀⚙️
