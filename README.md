# FileMind

[![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![Build](https://img.shields.io/badge/build-passing-success.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-black.svg)](#)
[![Lines of code](https://img.shields.io/badge/loc-400%2B-brightgreen.svg)](#)

---

## Overview

**FileMind** is a lightweight C++ tool that recursively scans your directories, analyzes file statistics, sorts by size, and generates detailed reports — all while silently judging your storage habits.  
It’s fast, multithreaded, and designed for people who organize files once a year.

---

## Features

- Recursive directory scanning  
- Extension-based file statistics  
- Sorting by size (descending)  
- Automatic `report.txt` generation  
- Parallel scan mode (4 threads)  
- “AI Prediction” of your next questionable download  
- Clean C++17 implementation, zero dependencies  

---

## Example

```bash
$ ./FileMind ~/Downloads
[*] Scanning directory: /home/you/Downloads
[+] Scan complete. You may now feel productive.
[*] Sorting files by size...
[+] Done sorting. Biggest files are judging you now.
[*] Generating report.txt...
[+] Report generated. Now pretend to read it.

[*] Running totally real AI prediction...
Prediction: 83% chance you'll download another 'final_version(5).zip'.
````

**Sample report.txt**

```
================ FileMind Report ================
Scanned Directory: /home/you/Downloads
Total Files: 534

By Extension:
  .png: 97 files, total size 248.51 MB
  .zip: 12 files, total size 4.87 GB
  .cpp: 7 files, total size 420.69 KB

Top 10 Largest Files:
  1. linux.iso (2.10 GB)
  2. final_version(3).zip (1.89 GB)
  3. taxes_2020_realfinal.pdf (850.12 MB)
=================================================
```

---

## Installation

**Linux / macOS**

```bash
git clone https://github.com/yourusername/FileMind.git
cd FileMind
g++ FileMind.cpp -o FileMind -std=c++17 -pthread
./FileMind <directory_path>
```

**Windows**

```bash
g++ FileMind.cpp -o FileMind.exe -std=c++17 -pthread
FileMind.exe C:\Users\You\Downloads
```

---

## Project Structure

```
FileMind/
│
├── FileMind.cpp        # Main source code
├── report.txt          # Generated output file
├── README.md           # Documentation
└── LICENSE             # MIT License
```

---

## Tech Stack

| Component        | Description                                       |
| ---------------- | ------------------------------------------------- |
| **Language**     | C++17                                             |
| **Libraries**    | `<filesystem>`, `<thread>`, `<mutex>`, `<chrono>` |
| **Build System** | Manual (g++)                                      |
| **Runtime**      | Cross-platform                                    |
| **Philosophy**   | “Organized chaos, but compiled.”                  |

---

## Roadmap

* [ ] Duplicate detection
* [ ] Interactive CLI with filters
* [ ] Terminal-based graphs
* [ ] Config file for exclusion rules
* [ ] Real AI analysis (not sarcasm-based)

---

## Contributing

Contributions, bug reports, and PRs are welcome.
Please maintain code style levels.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
