#include "include/lsplt.hpp"

#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <link.h>
#include <sys/stat.h>

#include <array>
#include <cinttypes>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>

#include "elf_util.hpp"
#include "logging.hpp"
#include "syscall.hpp"

namespace {

inline auto PageStart(uintptr_t addr) {
    static const uintptr_t page_size = getpagesize();
    return reinterpret_cast<char *>(addr / page_size * page_size);
}

/*
 * =======================================================================================
 *                            High-Level Data Flow Diagram
 * =======================================================================================
 *
 * This diagram shows the journey from a user's hook request to the final state
 * managed by the global 'hook_info' object.
 *
 *
 *  +-----------------------------+
 *  | 1. User's Hook Requests     |
 *  | (std::vector<HookRequest>) |
 *  |                             |
 *  | [dev, inode, "read",  cb1]  |
 *  | [dev, inode, "write", cb2]  |
 *  +-------------+---------------+
 *                |
 *                |
 *                v
 *  +-------------+---------------+      +--------------------------------+
 *  | 2. CommitHook()             |      | /proc/self/maps                |
 *  |                             +<-----+ (Scanned to find loaded libs)  |
 *  |   - ScanHookInfo()          |      +--------------------------------+
 *  |   - Filter()                |
 *  |   - Merge()                 |
 *  |   - DoHook()                |
 *  +-------------+---------------+
 *                |
 *                |
 *                v
 *  +---------------------------------------------------------------------------------+
 *  | 3. Global State: 'hook_info' (HookInfos -> std::map<start_addr, HookInfo>)      |
 *  |                                                                                 |
 *  |  Key (start_addr)     Value (HookInfo Object)                                   |
 *  | +------------------+----------------------------------------------------------+ |
 *  | | 0x7f... (libc)   | HookInfo for libc (Contains active hook details)         | |
 *  | +------------------+----------------------------------------------------------+ |
 *  | | 0x7f... (ld.so)  | HookInfo for ld.so (No matching hooks, may be empty)     | |
 *  | +------------------+----------------------------------------------------------+ |
 *  | | ...              | ...                                                      | |
 *  | +------------------+----------------------------------------------------------+ |
 *  +---------------------------------------------------------------------------------+
 *
 */

struct HookRequest {
    dev_t dev;
    ino_t inode;
    std::pair<uintptr_t, uintptr_t> offset_range;
    char symbol[128];
    void *callback;
    void **backup;
};

/*
 * =======================================================================================
 *               Detailed `HookInfo` Structure Diagram (Focus on 'backup')
 * =======================================================================================
 *
 * This shows the contents of a single `HookInfo` object for a library (e.g., libc.so.6)
 * where one or more hooks are active. The 'backup' field is central to this state.
 *
 *
 *  HookInfo for libc.so.6 (Address: 0x7fABC000)
 * +--------------------------------------------------------------------+
 * |                                                                    |
 * |  //-- MapInfo fields --//                                          |
 * |  path:  "/usr/lib/libc.so.6"                                       |
 * |  inode: 12345                                                      |
 * |  ...                                                               |
 * |                                                                    |
 * |  //-- Hooking State --//                                           |
 * |                                                                    |
 * |  elf:  std::unique_ptr<Elf> (points to parsed ELF data)            |
 * |                                                                    |
 * |  backup: 0xBAADF00D ---------------------------------------------+ |
 * |       ^                                                            |
 * |       |---- (See full explanation of its roles below) -----------+ |
 * |                                                                    |
 * |  hooks: std::map<uintptr_t, uintptr_t>                             |
 * |        (A record of every active hook in this library)             |
 * |        +-----------------------------+---------------------------+ |
 * |        | Key (Address of PLT entry)  | Value (Original Func Ptr) | |
 * |        +-----------------------------+---------------------------+ |
 * |        | 0x7fABC100 (plt for "read") | 0x7fDEF100 (real_read)    | |
 * |        +-----------------------------+---------------------------+ |
 * |        | 0x7fABC240 (plt for "write")| 0x7fDEF200 (real_write)   | |
 * |        +-----------------------------+---------------------------+ |
 * |                                                                    |
 * +--------------------------------------------------------------------+
 *
 *
 * =======================================================================================
 *                   The Three Critical Roles of the `backup` Field
 * =======================================================================================
 *
 * The `backup` field is more than just a pointer; it's a state machine that governs the
 * entire lifecycle of a hooked library.
 *
 * 1. IT ACTS AS A STATE FLAG:
 *    - If `backup == 0`, it means this library is NOT hooked. The memory at its original
 *      address is the pristine, read-only version from the file on disk.
 *    - If `backup != 0`, it means the library IS actively hooked. It tells us:
 *        a) A writable, private copy of the library now exists at the original address.
 *        b) The pristine, original, read-only memory has been moved to the address
 *           stored in the `backup` field.
 *
 * 2. IT IS THE SOURCE FOR THE FINAL RESTORATION:
 *    - This is its most important role. When the VERY LAST hook is removed from this
 *      library, the `hooks` map becomes empty.
 *    - This emptiness triggers a final `sys_mremap` call that MOVES the pristine memory
 *      segment from the `backup` address BACK to the library's original address.
 *    - This atomically and efficiently restores the library to its exact pre-hook state,
 *      destroying the writable copy and cleaning up all modifications.
 *
 * 3. IT IS THE SOURCE FOR THE INITIAL COPY:
 *    - When the first hook is applied, the kernel first moves the original memory to the
 *      `backup` address.
 *    - The code then immediately `memcpy`s the content FROM this `backup` location TO the
 *      newly created writable mapping at the original address. This populates our
 *      writable "sandbox" with the library's original code.
 *
 */

struct HookInfo : public lsplt::MapInfo {
    std::vector<std::pair<uintptr_t, uintptr_t>> hooks;
    uintptr_t backup;
    std::unique_ptr<Elf> elf;
    bool self;

    HookInfo(lsplt::MapInfo&& map, bool is_self)
        : lsplt::MapInfo(std::move(map)), backup(0), elf(nullptr), self(is_self) {}

    [[nodiscard]] bool Match(const HookRequest &info) const {
        return info.dev == dev && info.inode == inode && offset >= info.offset_range.first &&
               offset < info.offset_range.second;
    }
};

class HookInfos {
public:
    std::vector<HookInfo> data;

    HookInfos() = default;
    HookInfos(HookInfos&&) noexcept = default;
    HookInfos& operator=(HookInfos&&) noexcept = default;
    void reserve(size_t n) { data.reserve(n); }
    auto begin() { return data.begin(); }
    auto end() { return data.end(); }
    auto rbegin() { return data.rbegin(); }
    auto rend() { return data.rend(); }
    bool empty() const { return data.empty(); }
    size_t size() const { return data.size(); }
    void erase(auto it1, auto it2) { data.erase(it1, it2); }
    void push_back(HookInfo&& hi) { data.push_back(std::move(hi)); }
    template <typename... Args>
    void emplace_back(Args&&... args) { 
        data.emplace_back(std::forward<Args>(args)...); 
    }

    static auto CreateTargetsFromMemoryMaps(std::vector<lsplt::MapInfo> &maps) {
        static ino_t kSelfInode = 0;
        static dev_t kSelfDev = 0;
        HookInfos info;
        info.reserve(maps.size());
        const uintptr_t self_addr =
            (kSelfInode == 0) ? reinterpret_cast<uintptr_t>(__builtin_return_address(0)) : 0;
        for (auto &map : maps) {
            if (kSelfInode == 0 && self_addr >= map.start && self_addr < map.end) {
                kSelfInode = map.inode;
                kSelfDev = map.dev;
                LOGV("self inode = %lu", kSelfInode);
                for (auto &i : info.data) {
                    if (i.inode == kSelfInode && i.dev == kSelfDev) i.self = true;
                }
            }
            // we basically only care about r-?p entry
            // and for offset == 0 it's an ELF header
            // and for offset != 0 it's what we hook
            // both of them should not be xom
            if (map.inode == 0 || !map.is_private || !(map.perms & PROT_READ) ||
                map.path[0] == '\0' || map.path[0] == '[') {
                continue;
            }
            const bool self = kSelfInode != 0 && map.inode == kSelfInode && map.dev == kSelfDev;
            info.emplace_back(std::move(map), self);
        }
        return info;
    }

    // filter out ignored
    void Filter(const std::vector<HookRequest> &register_info) {
        // Optimized using erase-remove idiom to achieve O(N) complexity instead of O(N^2)
        auto it = std::remove_if(data.begin(), data.end(), [&](const auto &info) {
            bool matched = std::any_of(register_info.begin(), register_info.end(),
                                       [&](const auto &reg) { return info.Match(reg); });
            if (matched) {
                LOGV("match hook info %s:%lu %" PRIxPTR " %" PRIxPTR "-%" PRIxPTR, info.path,
                     info.inode, info.start, info.end, info.offset);
                return false;
            }
            return true;
        });
        data.erase(it, data.end());
    }

    void Merge(HookInfos &old) {
        // merge with old map info
        if (old.data.empty()) return;

        std::vector<uintptr_t> backups;
        backups.reserve(old.size());
        for (const auto &old_info : old.data) {
            if (old_info.backup) backups.push_back(old_info.backup);
        }
        qsort(backups.data(), backups.size(), sizeof(backups[0]), [](const void* a, const void* b) {
            auto v1 = *(uintptr_t*)a;
            auto v2 = *(uintptr_t*)b;
            return (v1 > v2) - (v1 < v2); // Standard safe comparison for pointers/ints
        });

        if (!backups.empty()) {
            size_t b_idx = 0;
            auto erase_it = std::remove_if(data.begin(), data.end(), [&](const HookInfo& hi) {
                while (b_idx < backups.size() && backups[b_idx] < hi.start) {
                    b_idx++;
                }
                return b_idx < backups.size() && backups[b_idx] == hi.start;
            });
            data.erase(erase_it, data.end());
        }

        HookInfos merged;
        merged.reserve(size() + old.size());

        auto it1 = data.begin();
        auto it2 = old.data.begin();

        while (it1 != data.end() && it2 != old.data.end()) {
            if (it1->start < it2->start) {
                merged.push_back(std::move(*it1));
                ++it1;
            } else if (it1->start > it2->start) {
                if (it2->backup) {
                    merged.push_back(std::move(*it2));
                }
                ++it2;
            } else {
                merged.push_back(std::move(*it2));
                ++it1;
                ++it2;
            }
        }

        while (it1 != data.end()) {
            merged.push_back(std::move(*it1));
            ++it1;
        }

        while (it2 != old.data.end()) {
            if (it2->backup) {
                merged.push_back(std::move(*it2));
            }
            ++it2;
        }

        *this = std::move(merged);
    }

    /**
     * =======================================================================================
     *                      Memory Remapping and Hooking Mechanism
     * =======================================================================================
     *
     * The following diagram illustrates the state of a process's address space before
     * and after hooking an PLT entry.
     *
     *
     * A) BEFORE HOOKING
     * -----------------
     * The library exists as a single, read-only, file-backed mapping.
     *
     *    Address Space
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *  | 0x7f1000         | <-- Original R/O mapping of libc.so
     *  |  .text, .got.plt |
     *  |  [PLT for 'read']| --> Points to original 'read' implementation.
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *
     *
     * B) AFTER HOOKING
     * ----------------
     * The memory layout is rearranged into two distinct segments.
     *
     *    Address Space
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *  | 0x7f1000         | <-- (3) New R/W private anonymous mapping.
     *  |  .text, .got.plt |     This is a mutable copy of the original.
     *  |  [PLT for 'read']| --> OVERWRITTEN to point to our callback function.
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *  | 0xBAADF00D       | <-- (1) Original mapping, moved here via mremap.
     *  |  (Backup Address)|     It remains an unmodified, R/O program image.
     *  |  [PLT for 'read']| --> Still points to original 'read'.
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *
     *
     * Sequence of Operations (Referenced in Diagram B):
     * -------------------------------------------------
     * 1. MREMAP: The original, file-backed memory segment at `0x7f1000` is atomically
     *    moved to a new, kernel-selected address (`0xBAADF00D`). This becomes the backup.
     *    The `HookInfo.backup` field records this new address.
     *
     * 2. MMAP & MEMCPY: A new, writable, private anonymous mapping is created at the
     *    original address (`0x7f1000`). Its contents are immediately populated by copying
     *    the data from the backup segment.
     *
     * 3. OVERWRITE: With a writable copy now in place, the PLT entry for the target
     *    symbol ('read') is safely overwritten with the address of the user's callback.
     *
     * Restoration:
     * ------------
     * When the last hook is removed, this process is efficiently reversed. A single
     * `sys_mremap` call moves the unmodified backup segment from `0xBAADF00D` back to
     * `0x7f1000`, completely discarding the modified, anonymous copy and restoring the
     * process's memory to its original state.
     *
     */

    bool PatchPLTEntry(uintptr_t addr, uintptr_t callback, uintptr_t *backup) {
        LOGV("hooking %p", reinterpret_cast<void *>(addr));
        auto iter = std::find_if(data.begin(), data.end(), [addr](const HookInfo& hi) {
            return addr >= hi.start && addr < hi.end;
        });
        if (iter == data.end()) return false;
        auto &info = *iter;
        const auto len = info.end - info.start;
        if (!info.backup && !info.self) {
            // let os find a suitable address
            auto *backup_addr = sys_mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            LOGD("backup %p to %p", reinterpret_cast<void *>(addr), backup_addr);
            if (backup_addr == MAP_FAILED) return false;
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, backup_addr);
                new_addr == MAP_FAILED || new_addr != backup_addr) {
                new_addr = sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                                      MREMAP_FIXED | MREMAP_MAYMOVE, backup_addr);
                if (new_addr == MAP_FAILED || new_addr != backup_addr) {
                    return false;
                }
                LOGD("backup with MREMAP_DONTUNMAP failed, tried without it");
            }
            int fd = (int)syscall(__NR_openat, AT_FDCWD, info.path, O_RDONLY | O_CLOEXEC);
            void *new_addr = MAP_FAILED;
            if (fd >= 0) {
                new_addr = sys_mmap(reinterpret_cast<void *>(info.start), len,
                                    PROT_READ | PROT_WRITE | info.perms,
                                    MAP_PRIVATE | MAP_FIXED, fd, info.offset);
                syscall(__NR_close, fd);
            }
            if (new_addr == MAP_FAILED) {
                new_addr = sys_mmap(reinterpret_cast<void *>(info.start), len,
                                    PROT_READ | PROT_WRITE | info.perms,
                                    MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
            }
            if (new_addr == MAP_FAILED) {
                return false;
            }
            memcpy(reinterpret_cast<void *>(info.start), backup_addr, len);
            mprotect(reinterpret_cast<void *>(info.start), len, info.perms);
            info.backup = reinterpret_cast<uintptr_t>(backup_addr);
        }

        auto *the_addr = reinterpret_cast<uintptr_t *>(addr);
        auto the_backup = *the_addr;
        if (*the_addr != callback) {
            if (mprotect(PageStart(addr), getpagesize(), info.perms | PROT_WRITE) == 0) {
                *the_addr = callback;
                mprotect(PageStart(addr), getpagesize(), info.perms);
                if (backup) *backup = the_backup;
                __builtin___clear_cache(reinterpret_cast<char *>(the_addr), reinterpret_cast<char *>(the_addr + 1));
            } else {
                PLOGE("mprotect failed to add PROT_WRITE for patching");
                return false;
            }
        } else {
            LOGV("the address already has the expected callback, no need to patch");
        }
        auto hook_iter = std::lower_bound(info.hooks.begin(), info.hooks.end(), addr, [](const auto& p, uintptr_t a){ return p.first < a; });
        if (hook_iter != info.hooks.end() && hook_iter->first == addr) {
            if (hook_iter->second == callback) info.hooks.erase(hook_iter); // Remove if matching
        } else {
            info.hooks.insert(hook_iter, {addr, the_backup}); // Insert in sorted order
        }
        if (info.hooks.empty() && !info.self) {
            LOGV("restore %p from %p", reinterpret_cast<void *>(info.start),
                 reinterpret_cast<void *>(info.backup));
            // Note that we have to always use sys_mremap here, see
            // https://cs.android.com/android/_/android/platform/bionic/+/4200e260d266fd0c176e71fbd720d0bab04b02db
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.backup), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                return false;
            }
            info.backup = 0;
        }
        return true;
    }

    /**
     * ------------------------------------------------------------------
     *                    Direct Hook Restoration Logic
     * ------------------------------------------------------------------
     * This block handles the restoration of a previously applied hook.
     * It operates under the efficient assumption that a corresponding
     * hook is already active within this `HookInfo`'s cache.
     *
     * The strategy is as follows:
     *
     * 1. IDENTIFY THE HOOK FROM CACHE: We iterate through the `info.hooks` map.
     *    This map's `key` is the memory address of the hooked PLT entry,
     *    and its `value` is the original function pointer we saved.
     *
     * 2. IDENTIFICATION CRITERION: A hook is identified as the correct one
     *    to restore if the original function address (the value) matches the
     *    `callback` pointer from the user's restore request (`reg.callback`).
     *
     * 3. RESTORE VIA DoHook: Once the match is found, we call the low-level
     *    `DoHook` function, passing the following parameters:
     *      - 1st arg: `hooked_addr` (the destination PLT entry address)
     *      - 2nd arg: `original_addr` (the source value from our cache)
     *    This writes the original function pointer back, undoing the hook.
     */
    bool RestoreFunction(std::vector<HookRequest> &register_info) {
        LOGV("restoring %zu functions", register_info.size());
        if (register_info.empty()) return true;
        bool res = true;

        qsort(register_info.data(), register_info.size(), sizeof(HookRequest),
            +[](const void* a, const void* b) -> int {
                const auto* req1 = static_cast<const HookRequest*>(a);
                const auto* req2 = static_cast<const HookRequest*>(b);
                auto cb1 = reinterpret_cast<uintptr_t>(req1->callback);
                auto cb2 = reinterpret_cast<uintptr_t>(req2->callback);
                if (cb1 < cb2) return -1;
                if (cb1 > cb2) return 1;
                return 0;
            });

        for (auto info_iter = rbegin(); info_iter != rend(); ++info_iter) {
            auto &info = *info_iter;
            if (info.hooks.empty()) continue;

            for (auto hook_it = info.hooks.begin(); hook_it != info.hooks.end(); ) {
                uintptr_t hook_cb = hook_it->second;

                size_t low = 0, high = register_info.size();
                while (low < high) {
                    size_t mid = low + (high - low) / 2;
                    if (reinterpret_cast<uintptr_t>(register_info[mid].callback) < hook_cb) {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }

                bool matched_and_restored = false;
                size_t req_idx = low;

                while (req_idx < register_info.size() && 
                       reinterpret_cast<uintptr_t>(register_info[req_idx].callback) == hook_cb) {
                    auto &req = register_info[req_idx];
                    if (info.dev == req.dev && info.inode == req.inode) {
                        LOGV("found matching hook for symbol [%s] at address %p.",
                             req.symbol, reinterpret_cast<void *>(hook_cb));
                        bool restored = PatchPLTEntry(hook_it->first, hook_it->second, nullptr);
                        res = restored && res;
                        req.callback = nullptr;
                        matched_and_restored = true;
                    }
                    ++req_idx;
                }

                if (matched_and_restored) {
                    hook_it = info.hooks.erase(hook_it);
                } else {
                    ++hook_it;
                }
            }
        }

        size_t write_idx = 0;
        for (size_t read_idx = 0; read_idx < register_info.size(); ++read_idx) {
            if (register_info[read_idx].callback != nullptr) {
                register_info[write_idx++] = register_info[read_idx];
            }
        }
        register_info.resize(write_idx);

        return res;
    }

    bool ProcessRequest(std::vector<HookRequest> &register_info) {
        bool res = true;
        std::vector<uintptr_t> possible_addr;
        auto iter = std::remove_if(register_info.begin(), register_info.end(), [&](const HookRequest &reg) {
            bool processed = false;
            for (auto info_iter = data.rbegin(); info_iter != data.rend(); ++info_iter) {
                auto &info = *info_iter;
                if (info.offset != reg.offset_range.first || !info.Match(reg)) continue;

                if (!info.elf) info.elf = std::make_unique<Elf>(info.start);
                if (info.elf && info.elf->Valid()) {
                    LOGV("finding symbol %s", reg.symbol);
                    info.elf->FindPltAddr(reg.symbol, possible_addr);
                    if (possible_addr.size() == 0) {
                        LOGW("symbol %s not found in PLT table", reg.symbol);
                        res = false;
                    } else {
                        LOGV("patching PLT entry for %s", reg.symbol);
                        for (auto addr : possible_addr) {
                            res = PatchPLTEntry(addr, reinterpret_cast<uintptr_t>(reg.callback),
                                                reinterpret_cast<uintptr_t *>(reg.backup)) &&
                                  res;
                        }
                    }
                }
                processed = true;
                break;
            }
            return processed;
        });
        register_info.erase(iter, register_info.end());
        return res;
    }

    bool CleanupAllHooks() {
        bool res = true;
        for (auto &info : data) {
            if (!info.backup) continue;
            for (auto &[addr, backup] : info.hooks) {
                // store new address to backup since we don't need backup
                backup = *reinterpret_cast<uintptr_t *>(addr);
            }
            auto len = info.end - info.start;
            if (auto *new_addr =
                    mremap(reinterpret_cast<void *>(info.backup), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                res = false;
                info.hooks.clear();
                continue;
            }
            if (!mprotect(PageStart(info.start), len, info.perms | PROT_WRITE)) {
                for (auto &[addr, backup] : info.hooks) {
                    *reinterpret_cast<uintptr_t *>(addr) = backup;
                }
                mprotect(PageStart(info.start), len, info.perms);
            }
            info.hooks.clear();
            info.backup = 0;
        }
        return res;
    }
};

std::mutex g_hook_state_mutex;
std::vector<HookRequest> g_pending_hooks = {};
HookInfos g_global_hook_state;
}  // namespace

namespace lsplt::inline v2 {

// --- HELPERS (De tu Rama 3) ---
static inline bool IsSpace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static inline void SkipSpace(const char*& p, const char* end) {
    while (p < end && IsSpace(*p)) p++;
}

template<typename T>
static inline bool ParseHex(const char*& p, const char* end, T* val) {
    if (p >= end) return false;
    *val = 0;
    bool parsed_any = false;
    while (p < end) {
        char c = *p;
        if (c >= '0' && c <= '9') { *val = (*val << 4) | (c - '0'); parsed_any = true; }
        else if (c >= 'a' && c <= 'f') { *val = (*val << 4) | (c - 'a' + 10); parsed_any = true; }
        else if (c >= 'A' && c <= 'F') { *val = (*val << 4) | (c - 'A' + 10); parsed_any = true; }
        else break;
        p++;
    }
    return parsed_any;
}

template<typename T>
static inline bool ParseDec(const char*& p, const char* end, T* val) {
    if (p >= end) return false;
    *val = 0;
    bool parsed_any = false;
    while (p < end) {
        char c = *p;
        if (c >= '0' && c <= '9') { *val = (*val * 10) + (c - '0'); parsed_any = true; }
        else break;
        p++;
    }
    return parsed_any;
}

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define PAGE_START(x) ((x) & ~(PAGE_SIZE - 1))
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE - 1))

static int DlIterateCallback(struct dl_phdr_info *info, [[maybe_unused]] size_t size, void *data) {
    auto *info_vec = static_cast<std::vector<MapInfo> *>(data);

    const char *name = info->dlpi_name;
    char exe_path[256];
    if (!name || name[0] == '\0') {
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len != -1) {
            exe_path[len] = '\0';
            name = exe_path;
        } else {
            name = "";
        }
    }

    struct stat st;
    ino_t inode = 0;
    dev_t dev = 0;
    if (name[0] == '/') {
        char clean_name[256];
        snprintf(clean_name, sizeof(clean_name), "%s", name);
        char* exclamation = strstr(clean_name, "!/");
        if (exclamation) {
            *exclamation = '\0';
        }
        if (stat(clean_name, &st) == 0) {
            inode = st.st_ino;
            dev = st.st_dev;
        }
    }

    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD) {
            uintptr_t start = PAGE_START(info->dlpi_addr + phdr->p_vaddr);
            uintptr_t end = PAGE_END(info->dlpi_addr + phdr->p_vaddr + phdr->p_memsz);
            uintptr_t offset = PAGE_START(phdr->p_offset);

            uint8_t perms = 0;
            if (phdr->p_flags & PF_R) perms |= PROT_READ;
            if (phdr->p_flags & PF_W) perms |= PROT_WRITE;
            if (phdr->p_flags & PF_X) perms |= PROT_EXEC;

            MapInfo map_info;
            map_info.start = start;
            map_info.end = end;
            map_info.perms = perms;
            map_info.is_private = true; // dl_iterate_phdr doesn't expose mapping type, but mostly private
            map_info.offset = offset;
            map_info.dev = dev;
            map_info.inode = inode;

            snprintf(map_info.path, sizeof(map_info.path), "%s", name);
            info_vec->push_back(map_info);
        }
    }
    return 0;
}

[[maybe_unused]] std::vector<MapInfo> MapInfo::Scan(std::string_view pid) {
    std::vector<MapInfo> info;
    info.reserve(2048);

    if (pid == "self") {
        dl_iterate_phdr(DlIterateCallback, &info);
        return info;
    }

    if (pid.length() > 64 - 12) return info;
    char path[64];
    if (pid == "self") {
        strlcpy(path, "/proc/self/maps", sizeof(path));
    } else {
        snprintf(path, sizeof(path), "/proc/%.*s/maps", static_cast<int>(pid.length()), pid.data());
    }

    int fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return info;

    char buffer[16384];
    size_t data_len = 0;
    ssize_t bytes_read;

    while (true) {
        bytes_read = (ssize_t)syscall(__NR_read, fd, buffer + data_len, sizeof(buffer) - data_len);
        if (bytes_read < 0 && errno == EINTR) continue;
        if (bytes_read <= 0) break;

        data_len += bytes_read;
        const char *p = buffer;
        const char *end = buffer + data_len;

        while (true) {
            const char *line_end = static_cast<const char *>(memchr(p, '\n', end - p));
            if (!line_end) break;

            const char* line_p = p;
            uintptr_t map_start = 0, map_end = 0, map_off = 0;
            uint64_t map_inode = 0;
            uintptr_t major = 0, minor = 0;
            if (ParseHex(line_p, line_end, &map_start) && line_p < line_end && *line_p == '-') {
                line_p++;
                if (ParseHex(line_p, line_end, &map_end)) {
                    SkipSpace(line_p, line_end);

                    bool read = false, write = false, exec = false, is_private = false;
                    if (line_p < line_end) { read = (*line_p == 'r'); line_p++; }
                    if (line_p < line_end) { write = (*line_p == 'w'); line_p++; }
                    if (line_p < line_end) { exec = (*line_p == 'x'); line_p++; }
                    if (line_p < line_end) { is_private = (*line_p == 'p'); line_p++; }
                    if (line_p < line_end && *line_p != ' ') line_p++;
                    SkipSpace(line_p, line_end);

                    if (ParseHex(line_p, line_end, &map_off)) {
                        SkipSpace(line_p, line_end);

                        if (ParseHex(line_p, line_end, &major) && line_p < line_end && *line_p == ':') {
                            line_p++;
                            if (ParseHex(line_p, line_end, &minor)) {
                                SkipSpace(line_p, line_end);

                                if (ParseDec(line_p, line_end, &map_inode)) {
                                    SkipSpace(line_p, line_end);

                                    uint8_t perms = 0;
                                    if (read) perms |= PROT_READ;
                                    if (write) perms |= PROT_WRITE;
                                    if (exec) perms |= PROT_EXEC;

                                    auto &ref = info.emplace_back(MapInfo{
                                            map_start, map_end, perms, is_private, map_off,
                                            static_cast<dev_t>(makedev(major, minor)),
                                            static_cast<ino_t>(map_inode), {0}
                                    });

                                    size_t path_len = line_end - line_p;
                                    if (path_len >= sizeof(ref.path)) path_len = sizeof(ref.path) - 1;
                                    if (path_len > 0) {
                                        memcpy(ref.path, line_p, path_len);
                                    }
                                    ref.path[path_len] = '\0';
                                }
                            }
                        }
                    }
                }
            }
            p = line_end + 1;
        }

        if (p < end) {
            size_t remaining = end - p;
            memmove(buffer, p, remaining);
            data_len = remaining;
        } else {
            data_len = 0;
        }
    }
    syscall(__NR_close, fd);
    return info;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol, void *callback,
                                   void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(g_hook_state_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    HookRequest req{dev, inode, {std::numeric_limits<uintptr_t>::min(), std::numeric_limits<uintptr_t>::max()}, {0}, callback, backup};
    strlcpy(req.symbol, symbol.data(), sizeof(req.symbol));
    g_pending_hooks.push_back(req);

    LOGV("RegisterHook %lu %s", req.inode, req.symbol);
    return true;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                   std::string_view symbol, void *callback, void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(g_hook_state_mutex);
    HookRequest req{dev, inode, {offset, offset + size}, {0}, callback, backup};
    strlcpy(req.symbol, symbol.data(), sizeof(req.symbol));
    g_pending_hooks.push_back(req);

    LOGV("RegisterHook %lu %" PRIxPTR "-%" PRIxPTR " %s", req.inode, req.offset_range.first,
         req.offset_range.second, req.symbol);
    return true;
}

[[maybe_unused]] bool CommitHook(std::vector<lsplt::MapInfo> &maps, bool unhook) {
    const std::unique_lock lock(g_hook_state_mutex);
    if (g_pending_hooks.empty()) return true;

    auto new_hook_state = HookInfos::CreateTargetsFromMemoryMaps(maps);
    if (new_hook_state.empty()) return false;

    new_hook_state.Filter(g_pending_hooks);

    new_hook_state.Merge(g_global_hook_state);
    // update to new map info
    g_global_hook_state = std::move(new_hook_state);

    if (unhook && g_global_hook_state.RestoreFunction(g_pending_hooks)) {
        return true;
    }
    return g_global_hook_state.ProcessRequest(g_pending_hooks);
}

[[maybe_unused]] bool CommitHook() {
    auto maps = MapInfo::Scan();
    return CommitHook(maps);
}

[[gnu::destructor]] [[maybe_unused]] bool InvalidateBackup() {
    const std::unique_lock lock(g_hook_state_mutex);
    return g_global_hook_state.CleanupAllHooks();
}
}  // namespace lsplt::inline v2
