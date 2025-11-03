#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

static std::string human_readable_size(uint64_t bytes) {
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
    double size = static_cast<double>(bytes);
    int unit = 0;
    while (size >= 1024.0 && unit < 5) {
        size /= 1024.0;
        ++unit;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(size < 10.0 ? 2 : (size < 100.0 ? 1 : 0)) << size << " " << units[unit];
    return oss.str();
}

static std::string get_extension_lower(const fs::path& p) {
    std::string ext = p.has_extension() ? p.extension().string() : "NO_EXT";
    if (!ext.empty() && ext.front() == '.') ext.erase(0, 1);
    if (ext.empty()) ext = "NO_EXT";
    for (auto &c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return ext;
}

static std::string file_time_to_string(const fs::file_time_type& ftime) {
    using namespace std::chrono;
    auto sctp = time_point_cast<system_clock::duration>(ftime - fs::file_time_type::clock::now()
                + system_clock::now());
    std::time_t tt = system_clock::to_time_t(sctp);
    std::tm tm{};
    #ifdef _WIN32
        localtime_s(&tm, &tt);
    #else
        localtime_r(&tt, &tm);
    #endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}

enum class LogLevel { INFO, WARN, ERROR, DEBUG };

static void log_msg(LogLevel level, const std::string& msg) {
    const char* levelstr = "INFO";
    if (level == LogLevel::WARN) levelstr = "WARN";
    if (level == LogLevel::ERROR) levelstr = "ERROR";
    if (level == LogLevel::DEBUG) levelstr = "DEBUG";
    std::cout << "[" << levelstr << "] " << msg << std::endl;
}

static uint64_t fnv1a_64(const uint8_t* data, std::size_t len) {
    const uint64_t FNV_OFFSET = 14695981039346656037ULL;
    const uint64_t FNV_PRIME  = 1099511628211ULL;
    uint64_t hash = FNV_OFFSET;
    for (std::size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= FNV_PRIME;
    }
    return hash;
}

static std::optional<uint64_t> fingerprint_file(const fs::path& filepath, std::error_code& ec, size_t chunk_size = 4096) {
    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs.is_open()) {
        ec = std::make_error_code(std::errc::io_error);
        return std::nullopt;
    }
    ifs.seekg(0, std::ios::end);
    std::streamoff size = ifs.tellg();
    if (size < 0) {
        ec = std::make_error_code(std::errc::io_error);
        return std::nullopt;
    }
    ifs.seekg(0, std::ios::beg);

    if (static_cast<uint64_t>(size) <= chunk_size * 3) {
        std::vector<uint8_t> buf(static_cast<std::size_t>(size));
        ifs.read(reinterpret_cast<char*>(buf.data()), size);
        if (!ifs) {
            ec = std::make_error_code(std::errc::io_error);
            return std::nullopt;
        }
        uint64_t h = fnv1a_64(buf.data(), buf.size());
        return h ^ static_cast<uint64_t>(static_cast<uint64_t>(size) << 32);
    } else {
        std::vector<uint8_t> chunk(chunk_size);
        uint64_t combined = 0xcbf29ce484222325ULL;
        ifs.seekg(0);
        ifs.read(reinterpret_cast<char*>(chunk.data()), chunk_size);
        if (!ifs) { ec = std::make_error_code(std::errc::io_error); return std::nullopt; }
        combined ^= fnv1a_64(chunk.data(), chunk_size);
        std::streamoff mid = size / 2;
        ifs.seekg(mid);
        ifs.read(reinterpret_cast<char*>(chunk.data()), chunk_size);
        if (!ifs) { ec = std::make_error_code(std::errc::io_error); return std::nullopt; }
        combined ^= fnv1a_64(chunk.data(), chunk_size) << 1;
        ifs.seekg(size - static_cast<std::streamoff>(chunk_size));
        ifs.read(reinterpret_cast<char*>(chunk.data()), chunk_size);
        if (!ifs) { ec = std::make_error_code(std::errc::io_error); return std::nullopt; }
        combined ^= fnv1a_64(chunk.data(), chunk_size) << 2;
        combined ^= static_cast<uint64_t>(static_cast<uint64_t>(size) << 3);
        return combined;
    }
}

struct FileRecord {
    fs::path path;
    uint64_t size;
    std::string extension;
    std::string modified;
    std::optional<uint64_t> fingerprint;
};

class FileScanner {
public:
    FileScanner(const fs::path& root, bool follow_symlinks = false, size_t concurrent_hashers = 4)
        : root_path(root), follow_symlinks(follow_symlinks), concurrent_hashers(concurrent_hashers) {
        if (concurrent_hashers == 0) this->concurrent_hashers = 1;
    }


    void scan() {
    log_msg(LogLevel::INFO, "Starting scan. I will quietly judge your folder structure.");
    start_time = std::chrono::steady_clock::now();

    uint64_t scanned = 0;
    try {
        auto options = follow_symlinks ? fs::directory_options::follow_directory_symlink : fs::directory_options::none;
        
        for (auto const& dir_entry : fs::recursive_directory_iterator(
            root_path, options, ec)) {
            
            if (ec) {
                log_msg(LogLevel::WARN, std::string("Filesystem iteration error: ") + ec.message());
                ec.clear();
                continue;
            }
            if (dir_entry.is_regular_file(ec)) {
                ++scanned;
                fs::path p = dir_entry.path();
                std::error_code local_ec;
                auto ftime = dir_entry.last_write_time(local_ec);
                if (local_ec) ftime = fs::file_time_type::clock::now();
                uint64_t sz = 0;
                try {
                    sz = static_cast<uint64_t>(dir_entry.file_size());
                } catch (...) {
                    sz = 0;
                }
                FileRecord rec;
                rec.path = p;
                rec.size = sz;
                rec.extension = get_extension_lower(p);
                rec.modified = file_time_to_string(ftime);
                {
                    std::lock_guard<std::mutex> lk(data_mutex);
                    files.push_back(std::move(rec));
                    total_files++;
                    total_size += sz;
                    ext_count[files.back().extension] += 1;
                    ext_size[files.back().extension] += sz;
                }
                if ((scanned & 0xFFF) == 0) {
                    log_msg(LogLevel::DEBUG, "Scanned " + std::to_string(scanned) + " files so far...");
                }
            }
        }
    } catch (const std::exception& ex) {
        log_msg(LogLevel::ERROR, std::string("Exception during scan: ") + ex.what());
    }

    end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> dur = end_time - start_time;
    log_msg(LogLevel::INFO, "Filesystem walk completed: " + std::to_string(total_files) + " files, " + human_readable_size(total_size) + " in " + std::to_string(dur.count()) + "s.");

    {
        std::lock_guard<std::mutex> lk(data_mutex);
        std::sort(files.begin(), files.end(), [](const FileRecord& a, const FileRecord& b){ return a.size > b.size; });
    }
}

    void compute_fingerprints(bool concurrent = true, size_t limit_threads = 0) {
        if (files.empty()) return;
        log_msg(LogLevel::INFO, "Computing fingerprints for files. This may take a while. Bring snacks.");
        auto start = std::chrono::steady_clock::now();

        size_t threads_to_use = concurrent ? (limit_threads > 0 ? limit_threads : concurrent_hashers) : 1;
        if (threads_to_use == 0) threads_to_use = 1;
        std::vector<std::future<void>> futures;
        std::atomic<size_t> index{0};

        auto worker = [this, &index]() {
            for (;;) {
                size_t i = index.fetch_add(1);
                if (i >= files.size()) break;
                FileRecord& rec = files[i];
                std::error_code ec;
                auto f = fingerprint_file(rec.path, ec);
                if (!f.has_value()) {
                    if (ec) {
                        std::lock_guard<std::mutex> lk(data_mutex);
                        fingerprint_errors++;
                    }
                } else {
                    std::lock_guard<std::mutex> lk(data_mutex);
                    rec.fingerprint = f;
                }
                if ((i & 0x3FF) == 0) {
                    log_msg(LogLevel::DEBUG, "Fingerprinted " + std::to_string(i+1) + " / " + std::to_string(files.size()));
                }
            }
        };

        for (size_t t = 0; t < threads_to_use; ++t) {
            futures.push_back(std::async(std::launch::async, worker));
        }
        for (auto &fut : futures) fut.wait();

        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double> dur = end - start;
        log_msg(LogLevel::INFO, "Fingerprinting done in " + std::to_string(dur.count()) + "s. Errors: " + std::to_string(fingerprint_errors));
    }

    std::vector<std::vector<FileRecord>> find_duplicates(size_t min_group = 2) {
        log_msg(LogLevel::INFO, "Detecting duplicates based on size + fingerprint. No deletions will be performed — I'm not a monster.");
        std::vector<std::vector<FileRecord>> result;
        std::unordered_map<uint64_t, std::vector<FileRecord>> map_by_fingerprint;
        {
            std::lock_guard<std::mutex> lk(data_mutex);
            for (const auto& rec : files) {
                if (!rec.fingerprint.has_value()) continue;
                uint64_t key = rec.fingerprint.value() ^ (rec.size * 11400714819323198485ULL);
                map_by_fingerprint[key].push_back(rec);
            }
        }
        for (auto& kv : map_by_fingerprint) {
            if (kv.second.size() >= min_group) {
                result.push_back(std::move(kv.second));
            }
        }
        std::sort(result.begin(), result.end(), [](const std::vector<FileRecord>& a, const std::vector<FileRecord>& b){
            uint64_t sa = 0, sb = 0;
            for (const auto& r : a) sa += r.size;
            for (const auto& r : b) sb += r.size;
            return sa > sb;
        });
        log_msg(LogLevel::INFO, "Found " + std::to_string(result.size()) + " duplicate candidate groups.");
        return result;
    }

    std::vector<FileRecord> top_n_largest(size_t n = 10) {
        std::lock_guard<std::mutex> lk(data_mutex);
        std::vector<FileRecord> out;
        for (size_t i = 0; i < files.size() && i < n; ++i) out.push_back(files[i]);
        return out;
    }

    std::vector<std::pair<std::string, std::pair<uint64_t, uint64_t>>> extension_summary_sorted() {
        std::vector<std::pair<std::string, std::pair<uint64_t, uint64_t>>> items;
        {
            std::lock_guard<std::mutex> lk(data_mutex);
            items.reserve(ext_count.size());
            for (const auto& kv : ext_count) {
                const std::string& ext = kv.first;
                uint64_t cnt = kv.second;
                uint64_t sz = ext_size[ext];
                items.push_back({ext, {cnt, sz}});
            }
        }
        std::sort(items.begin(), items.end(), [](const auto& a, const auto& b){ return a.second.second > b.second.second; });
        return items;
    }

    void export_report(const fs::path& outfile = "report.txt", size_t top_n = 20) {
        std::ofstream ofs(outfile);
        if (!ofs.is_open()) {
            log_msg(LogLevel::ERROR, "Failed to open report file for writing: " + outfile.string());
            return;
        }
        ofs << "FileMind Report\n";
        ofs << "Root: " << root_path.string() << "\n";
        ofs << "Scanned files: " << total_files << "\n";
        ofs << "Total size: " << total_size << " bytes (" << human_readable_size(total_size) << ")\n";
        ofs << "Scan duration: " << std::chrono::duration<double>(end_time - start_time).count() << "s\n\n";

        ofs << "Top " << top_n << " largest files:\n";
        auto top = top_n_largest(top_n);
        for (size_t i = 0; i < top.size(); ++i) {
            const auto& r = top[i];
            ofs << std::setw(3) << (i + 1) << ". " << human_readable_size(r.size) << " | " << r.modified << " | " << r.path.string() << "\n";
        }
        ofs << "\nExtension summary (sorted by total size):\n";
        auto exts = extension_summary_sorted();
        ofs << std::setw(12) << "Extension" << std::setw(12) << "Count" << std::setw(18) << "Total Size" << "\n";
        for (const auto& e : exts) {
            ofs << std::setw(12) << e.first << std::setw(12) << e.second.first << std::setw(18) << e.second.second << " (" << human_readable_size(e.second.second) << ")\n";
        }
        ofs << "\nDuplicate candidate groups (size + fingerprint):\n";
        auto dups = find_duplicates();
        for (size_t g = 0; g < dups.size(); ++g) {
            uint64_t group_total = 0;
            for (const auto& f : dups[g]) group_total += f.size;
            ofs << "Group " << (g+1) << " — " << dups[g].size() << " files, " << human_readable_size(group_total) << "\n";
            for (const auto& f : dups[g]) {
                ofs << "  - " << human_readable_size(f.size) << " | " << f.path.string() << "\n";
            }
            ofs << "\n";
        }
        ofs << "\n--- End of report ---\n";
        ofs.close();
        log_msg(LogLevel::INFO, "Report exported to " + outfile.string());
    }

    void export_csv(const fs::path& outfile = "summary.csv") {
        std::ofstream ofs(outfile);
        if (!ofs.is_open()) {
            log_msg(LogLevel::ERROR, "Failed to write CSV: " + outfile.string());
            return;
        }
        ofs << "extension,count,total_size_bytes\n";
        auto exts = extension_summary_sorted();
        for (const auto& e : exts) {
            ofs << e.first << "," << e.second.first << "," << e.second.second << "\n";
        }
        ofs.close();
        log_msg(LogLevel::INFO, "CSV exported to " + outfile.string());
    }

    void print_summary_console(size_t top_n = 12) {
        std::cout << "================ FileMind Summary ================\n";
        std::cout << "Root: " << root_path << "\n";
        std::cout << "Scanned files: " << total_files << "\n";
        std::cout << "Total size: " << human_readable_size(total_size) << " (" << total_size << " bytes)\n\n";

        std::cout << "Top " << top_n << " largest files:\n";
        auto top = top_n_largest(top_n);
        for (size_t i = 0; i < top.size(); ++i) {
            const auto& r = top[i];
            std::cout << std::setw(2) << (i + 1) << ". " << std::setw(10) << human_readable_size(r.size) << " | " << r.modified << " | " << r.path.filename().string() << "\n";
        }
        std::cout << "\nExtension breakdown (top 10 by size):\n";
        auto exts = extension_summary_sorted();
        for (size_t i = 0; i < exts.size() && i < 10; ++i) {
            std::cout << std::setw(12) << exts[i].first << " : " << std::setw(6) << exts[i].second.first << " files, " << std::setw(10) << human_readable_size(exts[i].second.second) << "\n";
        }
        std::cout << "\nFingerprint stats: attempted on " << files_with_fingerprint() << " / " << total_files << " files. Errors: " << fingerprint_errors << "\n";
        std::cout << "==================================================\n";
    }

    size_t files_with_fingerprint() const {
        size_t cnt = 0;
        std::lock_guard<std::mutex> lk(data_mutex);
        for (const auto& f : files) if (f.fingerprint.has_value()) ++cnt;
        return cnt;
    }

    uint64_t get_total_size() const { return total_size; }
    uint64_t get_total_files() const { return total_files; }
    const fs::path& get_root() const { return root_path; }

private:
    fs::path root_path;
    bool follow_symlinks;
    size_t concurrent_hashers;

    mutable std::mutex data_mutex;
    std::vector<FileRecord> files;
    std::unordered_map<std::string, uint64_t> ext_count;
    std::unordered_map<std::string, uint64_t> ext_size;

    std::error_code ec;

    uint64_t total_files = 0;
    uint64_t total_size = 0;
    std::chrono::steady_clock::time_point start_time, end_time;
    size_t fingerprint_errors = 0;
};

static void print_help(const std::string& prog) {
    std::cout << "FileMind — analyze a folder and shame it for its mess.\n";
    std::cout << "Usage: " << prog << " [path] [options]\n";
    std::cout << "If path is omitted, current directory is scanned.\n\n";
    std::cout << "Options:\n";
    std::cout << "  --no-fingerprint    skip fingerprinting (fast, less duplicate detection)\n";
    std::cout << "  --threads N         use N threads for fingerprinting (default: number of hardware threads or 4)\n";
    std::cout << "  --top N             how many top files to show (default: 12)\n";
    std::cout << "  --export-report     write detailed report to report.txt\n";
    std::cout << "  --export-csv        write extension summary to summary.csv\n";
    std::cout << "  --help              show this help\n";
    std::cout << std::endl;
    std::cout << "Example: " << prog << " ~/projects --threads 8 --export-report\n";
}

int main(int argc, char** argv) {
    std::cout << "FileMind v0.9 — organize chaos, quietly judge your file naming.\n";

    if (argc > 1) {
        std::string arg1 = argv[1];
        if (arg1 == "--help" || arg1 == "-h") {
            print_help(argv[0]);
            return 0;
        }
    }

    fs::path target = fs::current_path();
    bool do_fingerprint = true;
    size_t threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 4;
    size_t top_n = 12;
    bool export_report = false;
    bool export_csv = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--no-fingerprint") {
            do_fingerprint = false;
        } else if (a == "--threads") {
            if (i + 1 < argc) {
                threads = static_cast<size_t>(std::stoul(argv[++i]));
                if (threads == 0) threads = 1;
            } else {
                std::cerr << "--threads requires a number\n";
                return 1;
            }
        } else if (a == "--top") {
            if (i + 1 < argc) {
                top_n = static_cast<size_t>(std::stoul(argv[++i]));
                if (top_n == 0) top_n = 1;
            } else {
                std::cerr << "--top requires a number\n";
                return 1;
            }
        } else if (a == "--export-report") {
            export_report = true;
        } else if (a == "--export-csv") {
            export_csv = true;
        } else if (a == "--help" || a == "-h") {
            print_help(argv[0]);
            return 0;
        } else {
            if (target == fs::current_path() && i == 1) {
                target = fs::path(a);
            }
        }
    }

    if (!fs::exists(target)) {
        std::cerr << "Path does not exist: " << target << "\n";
        return 2;
    }
    if (!fs::is_directory(target)) {
        std::cerr << "Path is not a directory: " << target << "\n";
        return 3;
    }

    FileScanner scanner(target, false, threads);

    auto overall_start = std::chrono::steady_clock::now();
    scanner.scan();

    if (do_fingerprint) {
        scanner.compute_fingerprints(true, threads);
    } else {
        log_msg(LogLevel::INFO, "Skipping fingerprinting as requested. Duplicate detection will be limited.");
    }

    scanner.print_summary_console(top_n);

    if (do_fingerprint) {
        auto duplicates = scanner.find_duplicates();
        if (!duplicates.empty()) {
            std::cout << "\nDuplicate candidate groups (size + fingerprint):\n";
            size_t shown = 0;
            for (const auto& group : duplicates) {
                uint64_t group_total = 0;
                for (const auto& r : group) group_total += r.size;
                std::cout << "  Group (" << group.size() << " files) total " << human_readable_size(group_total) << ":\n";
                for (const auto& f : group) {
                    std::cout << "    - " << human_readable_size(f.size) << " | " << f.path << "\n";
                }
                shown++;
                if (shown >= 6) {
                    std::cout << "  ... " << (duplicates.size() - shown) << " more groups (use export-report to see all)\n";
                    break;
                }
            }
        } else {
            std::cout << "No duplicate candidate groups found. Either you are neat or my hash lied to me.\n";
        }
    }

    if (export_report) scanner.export_report("report.txt", top_n);
    if (export_csv) scanner.export_csv("summary.csv");

    auto overall_end = std::chrono::steady_clock::now();
    std::chrono::duration<double> total_dur = overall_end - overall_start;
    std::cout << "\nAll done. Time spent: " << std::fixed << std::setprecision(2) << total_dur.count() << "s.\n";
    std::cout << "If your folder is still chaotic, blame the laws of physics.\n";

    return 0;
}
