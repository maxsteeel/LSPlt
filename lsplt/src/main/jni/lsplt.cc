#include "include/lsplt.hpp"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <errno.h>
#include <link.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "elf_util.hpp"
#include "logging.hpp"
#include "syscall.hpp"

namespace {

inline uintptr_t SysPageSize() { static const uintptr_t size = getpagesize(); return size; }
inline uintptr_t SysPageMask() { static const uintptr_t mask = ~(SysPageSize() - 1); return mask; }
inline auto PageStart(uintptr_t addr) { return reinterpret_cast<char *>(addr & SysPageMask()); }

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
    std::optional<Elf> elf;
    bool self;

    HookInfo(lsplt::MapInfo&& map, bool is_self)
        : lsplt::MapInfo(std::move(map)), backup(0), elf(std::nullopt), self(is_self) {}

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
        if (register_info.empty()) {
            data.clear();
            return;
        }

        static std::vector<const HookRequest*> sorted_reg;
        sorted_reg.clear();
        sorted_reg.reserve(register_info.size());
        for (const auto& reg : register_info) {
            sorted_reg.push_back(&reg);
        }

        qsort(sorted_reg.data(), sorted_reg.size(), sizeof(const HookRequest*), [](const void* a, const void* b) -> int {
            const auto* req_a = *static_cast<const HookRequest* const*>(a);
            const auto* req_b = *static_cast<const HookRequest* const*>(b);
            if (req_a->dev != req_b->dev) return (req_a->dev > req_b->dev) - (req_a->dev < req_b->dev);
            return (req_a->inode > req_b->inode) - (req_a->inode < req_b->inode);
        });

        // Optimized using erase-remove idiom and binary search to achieve O(N log M) complexity
        auto it = std::remove_if(data.begin(), data.end(), [&](const auto &info) {
            size_t low = 0, high = sorted_reg.size();
            while (low < high) {
                size_t mid = low + (high - low) / 2;
                const HookRequest* mid_reg = sorted_reg[mid];
                if (mid_reg->dev < info.dev || (mid_reg->dev == info.dev && mid_reg->inode < info.inode)) {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }

            size_t req_idx = low;
            while (req_idx < sorted_reg.size()) {
                const HookRequest* reg = sorted_reg[req_idx];
                if (reg->dev != info.dev || reg->inode != info.inode) {
                    break;
                }
                if (info.Match(*reg)) {
                    LOGV("match hook info %s:%lu %" PRIxPTR " %" PRIxPTR "-%" PRIxPTR, info.path,
                         info.inode, info.start, info.end, info.offset);
                    return false; // keep it
                }
                ++req_idx;
            }
            return true; // remove it
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
        qsort(backups.data(), backups.size(), sizeof(uintptr_t), [](const void* a, const void* b) -> int {
            auto val_a = *static_cast<const uintptr_t*>(a);
            auto val_b = *static_cast<const uintptr_t*>(b);
            return (val_a > val_b) - (val_a < val_b);
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

    struct PendingPatch {
        uintptr_t addr;
        uintptr_t callback;
        uintptr_t *backup;
    };

    bool BatchPatchPLTEntries(HookInfo& info, std::vector<PendingPatch>& patches) {
        if (patches.empty()) return true;

        qsort(patches.data(), patches.size(), sizeof(PendingPatch), [](const void* a, const void* b) -> int {
            auto pa = static_cast<const PendingPatch*>(a)->addr;
            auto pb = static_cast<const PendingPatch*>(b)->addr;
            return (pa > pb) - (pa < pb);
        });

        const auto len = info.end - info.start;
        if (!info.backup && !info.self) {
            // let os find a suitable address
            auto *backup_addr = sys_mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            LOGD("backup %p to %p", reinterpret_cast<void *>(info.start), backup_addr);
            if (backup_addr == MAP_FAILED) return false;
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, backup_addr);
                new_addr == MAP_FAILED || new_addr != backup_addr) {
                if (mprotect(backup_addr, len, PROT_READ | PROT_WRITE) != 0) {
                    LOGD("fallback mprotect backup_addr to RW failed");
                    return false;
                }
                if (mprotect(reinterpret_cast<void *>(info.start), len, info.perms | PROT_READ) != 0) {
                    LOGD("fallback mprotect info.start to include READ failed");
                    return false;
                }
                memcpy(backup_addr, reinterpret_cast<void *>(info.start), len);
                mprotect(reinterpret_cast<void *>(info.start), len, info.perms);
                if (mprotect(backup_addr, len, info.perms) != 0) {
                    LOGD("fallback restore mprotect backup_addr failed");
                    return false;
                }
                __builtin___clear_cache(reinterpret_cast<char *>(backup_addr), reinterpret_cast<char *>(backup_addr) + len);
                LOGD("backup with MREMAP_DONTUNMAP failed, fallback to memcpy");
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
            LOGD("backup %p mapped %p", reinterpret_cast<void *>(info.start), new_addr);
            info.backup = reinterpret_cast<uintptr_t>(backup_addr);
        }

        bool res = true;
        uintptr_t current_page = 0;
        bool page_unprotected = false;
        uintptr_t clear_start = 0;
        uintptr_t clear_end = 0;

        std::vector<std::pair<uintptr_t, uintptr_t>> new_hooks;
        new_hooks.reserve(info.hooks.size() + patches.size());
        auto hook_it = info.hooks.begin();

        for (const auto& patch : patches) {
            uintptr_t addr = patch.addr;
            uintptr_t callback = patch.callback;
            uintptr_t *backup = patch.backup;

            if (addr < info.start || addr >= info.end) {
                res = false;
                continue;
            }

            auto *the_addr = reinterpret_cast<uintptr_t *>(addr);
            auto the_backup = *the_addr;

            if (*the_addr != callback) {
                uintptr_t page_start = reinterpret_cast<uintptr_t>(PageStart(addr));
                
                if (page_start != current_page) {
                    if (page_unprotected) {
                        if (clear_start != 0) {
                            __builtin___clear_cache(reinterpret_cast<char *>(clear_start), reinterpret_cast<char *>(clear_end));
                        }
                        mprotect(reinterpret_cast<void*>(current_page), SysPageSize(), info.perms);
                    }
                    if (mprotect(reinterpret_cast<void*>(page_start), SysPageSize(), info.perms | PROT_WRITE) == 0) {
                        current_page = page_start;
                        page_unprotected = true;
                        clear_start = 0;
                        clear_end = 0;
                    } else {
                        PLOGE("mprotect failed to add PROT_WRITE for patching");
                        page_unprotected = false;
                        res = false;
                        continue;
                    }
                }

                if (page_unprotected) {
                    *the_addr = callback;
                    if (backup) *backup = the_backup;

                    if (clear_start == 0) {
                        clear_start = addr;
                        clear_end = addr + sizeof(uintptr_t);
                    } else {
                        if (addr < clear_start) clear_start = addr;
                        if (addr + sizeof(uintptr_t) > clear_end) clear_end = addr + sizeof(uintptr_t);
                    }
                }
            } else {
                LOGV("the address already has the expected callback, no need to patch");
            }

            while (hook_it != info.hooks.end() && hook_it->first < addr) {
                new_hooks.push_back(*hook_it);
                ++hook_it;
            }

            if (hook_it != info.hooks.end() && hook_it->first == addr) {
                if (hook_it->second != callback) {
                    new_hooks.push_back(*hook_it);
                }
                ++hook_it;
            } else {
                new_hooks.push_back({addr, the_backup});
            }
        }

        while (hook_it != info.hooks.end()) {
            new_hooks.push_back(*hook_it);
            ++hook_it;
        }
        info.hooks = std::move(new_hooks);

        if (page_unprotected) {
            if (clear_start != 0) {
                __builtin___clear_cache(reinterpret_cast<char *>(clear_start), reinterpret_cast<char *>(clear_end));
            }
            mprotect(reinterpret_cast<void*>(current_page), SysPageSize(), info.perms);
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
        return res;
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

        // Sort by callback address for O(log N) binary search
        qsort(register_info.data(), register_info.size(), sizeof(HookRequest), [](const void* a, const void* b) -> int {
            auto ca = reinterpret_cast<uintptr_t>(static_cast<const HookRequest*>(a)->callback);
            auto cb = reinterpret_cast<uintptr_t>(static_cast<const HookRequest*>(b)->callback);
            return (ca > cb) - (ca < cb);
        });

        std::vector<PendingPatch> patches;

        for (auto info_iter = rbegin(); info_iter != rend(); ++info_iter) {
            auto &info = *info_iter;
            if (info.hooks.empty()) continue;

            patches.clear();

            // Iterate using index to prevent iterator invalidation when PatchPLTEntry erases elements
            for (size_t i = 0; i < info.hooks.size(); ++i) {
                uintptr_t hook_addr = info.hooks[i].first;
                uintptr_t hook_cb = info.hooks[i].second;

                size_t low = 0, high = register_info.size();
                while (low < high) {
                    size_t mid = low + (high - low) / 2;
                    if (reinterpret_cast<uintptr_t>(register_info[mid].callback) < hook_cb) {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }

                size_t req_idx = low;
                while (req_idx < register_info.size() && 
                       reinterpret_cast<uintptr_t>(register_info[req_idx].callback) == hook_cb) {
                    auto &req = register_info[req_idx];
                    // Check symbol[0] to ensure we don't process the same request twice
                    if (req.symbol[0] != '\0' && info.dev == req.dev && info.inode == req.inode) {
                        LOGV("found matching hook for symbol [%s] at address %p.",
                             req.symbol, reinterpret_cast<void *>(hook_cb));

                        patches.push_back({hook_addr, hook_cb, nullptr});

                        // Mark as processed using the symbol string.
                        // This preserves the 'callback' value, keeping the array perfectly sorted!
                        req.symbol[0] = '\0';
                    }
                    ++req_idx;
                }
            }

            if (!patches.empty()) {
                res = BatchPatchPLTEntries(info, patches) && res;
            }
        }

        // In-place compression cleanup based on our new marker
        size_t write_idx = 0;
        for (size_t read_idx = 0; read_idx < register_info.size(); ++read_idx) {
            if (register_info[read_idx].symbol[0] != '\0') {
                register_info[write_idx++] = register_info[read_idx];
            }
        }
        register_info.resize(write_idx);

        return res;
    }

    bool ProcessRequest(std::vector<HookRequest> &register_info) {
        bool res = true;
        std::vector<uintptr_t> possible_addr;
        possible_addr.reserve(4); // Pre-reserve capacity to minimize heap allocations

        qsort(register_info.data(), register_info.size(), sizeof(HookRequest), [](const void* a, const void* b) -> int {
            const auto* ra = static_cast<const HookRequest*>(a);
            const auto* rb = static_cast<const HookRequest*>(b);
            if (ra->dev != rb->dev) return (ra->dev > rb->dev) - (ra->dev < rb->dev);
            if (ra->inode != rb->inode) return (ra->inode > rb->inode) - (ra->inode < rb->inode);
            return (ra->offset_range.first > rb->offset_range.first) - (ra->offset_range.first < rb->offset_range.first);
        });

        HookInfo* last_matched_info = nullptr;
        static std::vector<std::vector<PendingPatch>> grouped_patches;

        if (grouped_patches.size() < data.size()) grouped_patches.resize(data.size());
        for (size_t i = 0; i < data.size(); ++i) grouped_patches[i].clear();

        auto iter = std::remove_if(register_info.begin(), register_info.end(), [&](const HookRequest &reg) {
            bool processed = false;

            if (!last_matched_info || last_matched_info->offset != reg.offset_range.first || !last_matched_info->Match(reg)) {
                last_matched_info = nullptr;
                for (auto info_iter = data.rbegin(); info_iter != data.rend(); ++info_iter) {
                    auto &info = *info_iter;
                    if (info.offset != reg.offset_range.first || !info.Match(reg)) continue;
                    last_matched_info = &info;
                    break;
                }
            }

            if (last_matched_info) {
                auto &info = *last_matched_info;
                if (!info.elf) info.elf.emplace(info.start);
                if (info.elf && info.elf->Valid()) {
                    LOGV("finding symbol %s", reg.symbol);
                    info.elf->FindPltAddr(reg.symbol, possible_addr);
                    if (possible_addr.size() == 0) {
                        LOGW("symbol %s not found in PLT table", reg.symbol);
                        res = false;
                    } else {
                        LOGV("patching PLT entry for %s", reg.symbol);
                        for (auto addr : possible_addr) {
                            auto target_iter = std::upper_bound(data.begin(), data.end(), addr, [](uintptr_t a, const HookInfo& hi) {
                                return a < hi.start;
                            });
                            if (target_iter != data.begin()) {
                                --target_iter;
                                if (addr < target_iter->end) {
                                    size_t target_idx = std::distance(data.begin(), target_iter);
                                    grouped_patches[target_idx].push_back({addr, reinterpret_cast<uintptr_t>(reg.callback), reinterpret_cast<uintptr_t*>(reg.backup)});
                                } else { 
                                    res = false; 
                                }
                            } else { 
                                res = false; 
                            }
                        }
                    }
                }
                processed = true;
            }
            return processed;
        });

        register_info.erase(iter, register_info.end());

        for (size_t i = 0; i < data.size(); ++i) {
            if (!grouped_patches[i].empty()) {
                res = BatchPatchPLTEntries(data[i], grouped_patches[i]) && res;
            }
        }

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

inline uintptr_t AlignPageStart(uintptr_t addr) { return addr & SysPageMask(); }
inline uintptr_t AlignPageEnd(uintptr_t addr) { return AlignPageStart(addr + SysPageSize() - 1); }

struct DlIterateData {
    std::vector<MapInfo> *info_vec;
    char cached_path[PATH_MAX];
    bool cached_success;
    ino_t cached_inode;
    dev_t cached_dev;
    char exe_path[PATH_MAX];
    bool exe_path_loaded;
};

static int DlIterateCallback(struct dl_phdr_info *info, [[maybe_unused]] size_t size, void *data) {
    auto *iter_data = static_cast<DlIterateData *>(data);
    auto *info_vec = iter_data->info_vec;

    const char *name = info->dlpi_name;
    if (!name || name[0] == '\0') {
        if (!iter_data->exe_path_loaded) {
            ssize_t len = readlink("/proc/self/exe", iter_data->exe_path, sizeof(iter_data->exe_path) - 1);
            if (len != -1) {
                iter_data->exe_path[len] = '\0';
            } else {
                iter_data->exe_path[0] = '\0';
            }
            iter_data->exe_path_loaded = true;
        }
        name = iter_data->exe_path;
    }

    struct stat st;
    ino_t inode = 0;
    dev_t dev = 0;

    if (name[0] == '/') {
        const char* exclamation = strstr(name, "!/");
        size_t path_len = exclamation ? static_cast<size_t>(exclamation - name) : strlen(name);

        if (path_len < PATH_MAX) {
            if (iter_data->cached_path[0] != '\0' && strncmp(name, iter_data->cached_path, path_len) == 0 && iter_data->cached_path[path_len] == '\0') {
                if (iter_data->cached_success) {
                    inode = iter_data->cached_inode;
                    dev = iter_data->cached_dev;
                }
            } else {
                char clean_name[PATH_MAX];
                memcpy(clean_name, name, path_len);
                clean_name[path_len] = '\0';

                memcpy(iter_data->cached_path, clean_name, path_len + 1);
                if (stat(clean_name, &st) == 0) {
                    inode = st.st_ino;
                    dev = st.st_dev;
                    iter_data->cached_inode = inode;
                    iter_data->cached_dev = dev;
                    iter_data->cached_success = true;
                } else {
                    iter_data->cached_success = false;
                }
            }
        }
    }

    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD) {
            uintptr_t start = AlignPageStart(info->dlpi_addr + phdr->p_vaddr);
            uintptr_t end = AlignPageEnd(info->dlpi_addr + phdr->p_vaddr + phdr->p_memsz);
            uintptr_t offset = AlignPageStart(phdr->p_offset);

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

            if (strlcpy(map_info.path, name, sizeof(map_info.path)) >= sizeof(map_info.path)) {
                map_info.path[0] = '\0';
            }
            info_vec->push_back(map_info);
        }
    }
    return 0;
}

static inline bool ParseMapAddresses(const char*& line_p, const char* line_end, MapInfo& map_info) {
    if (!ParseHex(line_p, line_end, &map_info.start)) return false;
    if (line_p >= line_end || *line_p != '-') return false;
    line_p++;

    if (!ParseHex(line_p, line_end, &map_info.end)) return false;
    SkipSpace(line_p, line_end);
    return true;
}

static inline bool ParseMapPermissions(const char*& line_p, const char* line_end, MapInfo& map_info) {
    bool read = false, write = false, exec = false, is_private = false;
    if (line_p < line_end) { read = (*line_p == 'r'); line_p++; } else return false;
    if (line_p < line_end) { write = (*line_p == 'w'); line_p++; } else return false;
    if (line_p < line_end) { exec = (*line_p == 'x'); line_p++; } else return false;
    if (line_p < line_end) { is_private = (*line_p == 'p'); line_p++; } else return false;
    if (line_p < line_end && *line_p != ' ') line_p++;
    SkipSpace(line_p, line_end);

    map_info.perms = 0;
    if (read) map_info.perms |= PROT_READ;
    if (write) map_info.perms |= PROT_WRITE;
    if (exec) map_info.perms |= PROT_EXEC;
    map_info.is_private = is_private;
    return true;
}

static inline bool ParseMapOffsetDevInode(const char*& line_p, const char* line_end, MapInfo& map_info) {
    uintptr_t major = 0, minor = 0;
    uint64_t map_inode = 0;

    if (!ParseHex(line_p, line_end, &map_info.offset)) return false;
    SkipSpace(line_p, line_end);

    if (!ParseHex(line_p, line_end, &major)) return false;
    if (line_p >= line_end || *line_p != ':') return false;
    line_p++;

    if (!ParseHex(line_p, line_end, &minor)) return false;
    SkipSpace(line_p, line_end);

    if (!ParseDec(line_p, line_end, &map_inode)) return false;
    SkipSpace(line_p, line_end);

    map_info.dev = static_cast<dev_t>(makedev(major, minor));
    map_info.inode = static_cast<ino_t>(map_inode);
    return true;
}

static inline void ParseMapPath(const char* line_p, const char* line_end, MapInfo& map_info) {
    size_t path_len = line_end - line_p;
    if (path_len >= sizeof(map_info.path)) {
        map_info.path[0] = '\0';
    } else {
        if (path_len > 0) {
            memcpy(map_info.path, line_p, path_len);
        }
        map_info.path[path_len] = '\0';
    }
}

static bool ParseMapLine(const char* line_p, const char* line_end, MapInfo& map_info) {
    if (!ParseMapAddresses(line_p, line_end, map_info)) return false;
    if (!ParseMapPermissions(line_p, line_end, map_info)) return false;
    if (!ParseMapOffsetDevInode(line_p, line_end, map_info)) return false;
    ParseMapPath(line_p, line_end, map_info);
    return true;
}

static void ScanSelf(std::vector<MapInfo>& info) {
    DlIterateData iter_data;
    iter_data.info_vec = &info;
    iter_data.cached_path[0] = '\0';
    iter_data.cached_success = false;
    iter_data.cached_inode = 0;
    iter_data.cached_dev = 0;
    iter_data.exe_path_loaded = false;
    dl_iterate_phdr(DlIterateCallback, &iter_data);
}

static void ScanPid(std::vector<MapInfo>& info, std::string_view pid) {
    if (pid.length() > 64 - 12) return;
    char path[64];
    char* ptr = path;
    std::memcpy(ptr, "/proc/", 6);
    ptr += 6;
    std::memcpy(ptr, pid.data(), pid.length());
    ptr += pid.length();
    std::memcpy(ptr, "/maps", 6);

    int fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;

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

            MapInfo map_info;
            if (ParseMapLine(p, line_end, map_info)) {
                info.push_back(map_info);
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
}

[[maybe_unused]] std::vector<MapInfo> MapInfo::Scan(std::string_view pid) {
    std::vector<MapInfo> info;
    info.reserve(2048);

    if (pid == "self") {
        ScanSelf(info);
    } else {
        ScanPid(info, pid);
    }

    return info;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol, void *callback,
                                   void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(g_hook_state_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    HookRequest req{dev, inode, {std::numeric_limits<uintptr_t>::min(), std::numeric_limits<uintptr_t>::max()}, {0}, callback, backup};
    size_t copy_len = std::min(symbol.length(), sizeof(req.symbol) - 1);
    std::memcpy(req.symbol, symbol.data(), copy_len);
    req.symbol[copy_len] = '\0';
    g_pending_hooks.push_back(req);

    LOGV("RegisterHook %lu %s", req.inode, req.symbol);
    return true;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                   std::string_view symbol, void *callback, void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(g_hook_state_mutex);
    HookRequest req{dev, inode, {offset, offset + size}, {0}, callback, backup};
    size_t copy_len = std::min(symbol.length(), sizeof(req.symbol) - 1);
    std::memcpy(req.symbol, symbol.data(), copy_len);
    req.symbol[copy_len] = '\0';
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
