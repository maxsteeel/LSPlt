#include "include/lsplt.hpp"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <link.h>
#include <unistd.h>
#include <pthread.h>
#include <cstring>
#include "elf_util.hpp"
#include "logging.hpp"
#include "syscall.hpp"

#define MIN_VAL(a, b) ((a) < (b) ? (a) : (b))
#define MAX_VAL(a, b) ((a) > (b) ? (a) : (b))

namespace {

struct ActiveHook {
    uintptr_t addr;
    uintptr_t orig_ptr;
};

template <typename T>
struct FastList {
    T* data = nullptr;
    size_t size = 0;
    size_t capacity = 0;
    FastList() = default;
    ~FastList() { 
        if (data) {
            for (size_t i = 0; i < size; i++) data[i].~T();
            free(data); 
        }
    }
    FastList(FastList&& o) noexcept : data(o.data), size(o.size), capacity(o.capacity) { 
        o.data = nullptr; o.size = o.capacity = 0; 
    }
    FastList& operator=(FastList&& o) noexcept {
        if (this != &o) { 
            if (data) { 
                for (size_t i = 0; i < size; i++) data[i].~T(); 
                free(data); 
            }
            data = o.data; size = o.size; capacity = o.capacity; 
            o.data = nullptr; o.size = o.capacity = 0; 
        }
        return *this;
    }
    FastList(const FastList&) = delete;
    FastList& operator=(const FastList&) = delete;
    void reserve(size_t n) {
        if (n > capacity) {
            T* new_data = static_cast<T*>(malloc(n * sizeof(T)));
            if (!new_data) return;
            if (data && size > 0) { __builtin_memcpy((void*)new_data, data, size * sizeof(T)); }
            __builtin_memset(reinterpret_cast<void*>(new_data + size), 0, (n - size) * sizeof(T));
            if (data) free(data);
            data = new_data;
            capacity = n;
        }
    }
    void push_back(const T& val) {
        if (size >= capacity) reserve(capacity == 0 ? 8 : capacity * 2);
        data[size++] = val;
    }
    void push_back(T&& val) {
        if (size >= capacity) reserve(capacity == 0 ? 8 : capacity * 2);
        data[size++] = static_cast<T&&>(val);
    }
    T& emplace_back() {
        if (size >= capacity) reserve(capacity == 0 ? 8 : capacity * 2);
        return data[size++];
    }
    void insert(size_t index, const T& val) {
        if (size >= capacity) reserve(capacity == 0 ? 8 : capacity * 2);
        if (index < size) {
            __builtin_memmove(&data[index + 1], &data[index], (size - index) * sizeof(T));
        }
        data[index] = val;
        size++;
    }
    void clear() { 
        // If T has important destructors (like Regex), 
        // they should be called here before resetting the size.
        for (size_t i = 0; i < size; i++) data[i].~T();
        size = 0; 
    }
    bool empty() const { return size == 0; }
    T* begin() { return data; }
    T* end() { return data + size; }
};

struct PendingPatch { uintptr_t addr; uintptr_t callback; uintptr_t *backup; };

struct HookRequest {
    dev_t dev;
    ino_t inode;
    uintptr_t offset_range_start;
    uintptr_t offset_range_end;
    char symbol[128];
    void *callback;
    void **backup;
};

inline auto PageStart(uintptr_t a) { 
    return reinterpret_cast<char *>(a & lsplt::sys::SysPageMask()); 
}

struct HookInfo : public lsplt::MapInfo {
    FastList<ActiveHook> hooks;
    uintptr_t backup = 0;
    Elf* elf = nullptr;
    bool self;

    HookInfo() = default;
    HookInfo(const lsplt::MapInfo& map, bool is_self) : lsplt::MapInfo(map), self(is_self) {}
    ~HookInfo() { delete elf; }

    HookInfo(HookInfo&& o) noexcept : lsplt::MapInfo(o), hooks(static_cast<FastList<ActiveHook>&&>(o.hooks)), backup(o.backup), elf(o.elf), self(o.self) {
        o.elf = nullptr;
    }
    HookInfo& operator=(HookInfo&& o) noexcept {
        if (this != &o) {
            lsplt::MapInfo::operator=(o);
            hooks = static_cast<FastList<ActiveHook>&&>(o.hooks);
            backup = o.backup;
            delete elf;
            elf = o.elf;
            self = o.self;
            o.elf = nullptr;
        }
        return *this;
    }

    bool Match(const HookRequest &i) const { 
        return i.dev == dev && i.inode == inode && offset >= i.offset_range_start && offset < i.offset_range_end; 
    }
};

template<typename T, typename Func>
static inline size_t lower_bound(const T* arr, size_t size, uintptr_t val, Func comp) {
    size_t low = 0, high = size;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (comp(arr[mid], val)) low = mid + 1;
        else high = mid;
    }
    return low;
}

template<typename T, typename Func>
static inline size_t upper_bound(const T* arr, size_t size, uintptr_t val, Func comp) {
    size_t low = 0, high = size;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (comp(val, arr[mid])) high = mid;
        else low = mid + 1;
    }
    return low;
}

class HookInfos {
public:
    FastList<HookInfo> data;

    static auto CreateTargetsFromMemoryMaps(lsplt::MapInfoList &maps) {
        static ino_t kSelfInode = 0; static dev_t kSelfDev = 0;
        HookInfos info; info.data.reserve(maps.size);
        const uintptr_t self_addr = (kSelfInode == 0) ? reinterpret_cast<uintptr_t>(__builtin_return_address(0)) : 0;
        for (size_t i = 0; i < maps.size; i++) {
            auto& map = maps.data[i];
            if (kSelfInode == 0 && self_addr >= map.start && self_addr < map.end) { kSelfInode = map.inode; kSelfDev = map.dev; }
            if (map.inode == 0 || !map.is_private || !(map.perms & PROT_READ) || map.path[0] == '\0' || map.path[0] == '[') continue;
            HookInfo hi(map, (kSelfInode != 0 && map.inode == kSelfInode && map.dev == kSelfDev));
            info.data.push_back(static_cast<HookInfo&&>(hi));
        }
        return info;
    }

    void Filter(const FastList<HookRequest> &register_info) {
        if (register_info.empty()) { data.clear(); return; }
        static FastList<const HookRequest*> sorted; 
        sorted.clear(); sorted.reserve(register_info.size);
        for (size_t i = 0; i < register_info.size; i++) sorted.push_back(&register_info.data[i]);
        ::sort(sorted.begin(), sorted.end(), [](const HookRequest* a, const HookRequest* b) {
            if (a->dev != b->dev) return a->dev < b->dev;
            return a->inode < b->inode;
        });
        size_t new_size = 0;
        for (size_t i = 0; i < data.size; i++) {
            auto& info = data.data[i];
            bool keep = false;
            size_t low = 0, high = sorted.size;
            while (low < high) {
                size_t mid = low + (high - low) / 2;
                if (sorted.data[mid]->dev < info.dev || (sorted.data[mid]->dev == info.dev && sorted.data[mid]->inode < info.inode)) low = mid + 1;
                else high = mid;
            }
            for (size_t j = low; j < sorted.size && sorted.data[j]->dev == info.dev && sorted.data[j]->inode == info.inode; ++j) {
                if (info.Match(*sorted.data[j])) { keep = true; break; } 
            }
            if (keep) {
                if (new_size != i) {
                    data.data[new_size].~HookInfo();
                    __builtin_memcpy((void*)&data.data[new_size], (void*)&data.data[i], sizeof(HookInfo));
                    __builtin_memset((void*)&data.data[i], 0, sizeof(HookInfo));
                }
                new_size++;
            } else {
                data.data[i].~HookInfo();
                __builtin_memset((void*)&data.data[i], 0, sizeof(HookInfo));
            }
        }
        data.size = new_size;
    }

    void Merge(HookInfos &old) {
        if (old.data.empty()) return;
        FastList<uintptr_t> backups; 
        for (size_t i = 0; i < old.data.size; i++) {
            if (old.data.data[i].backup) backups.push_back(old.data.data[i].backup);
        }
        if (!backups.empty()) {
            ::sort(backups.begin(), backups.end(), [](uintptr_t a, uintptr_t b) { return a < b; });
            size_t dest = 0, it = 0;
            size_t backup_it = 0;
            while (it < data.size && backup_it < backups.size) {
                if (data.data[it].start < backups.data[backup_it]) {
                    if (dest != it) data.data[dest] = static_cast<HookInfo&&>(data.data[it]);
                    dest++; it++;
                }
                else if (data.data[it].start > backups.data[backup_it]) backup_it++;
                else it++;
            }
            while (it < data.size) {
                if (dest != it) data.data[dest] = static_cast<HookInfo&&>(data.data[it]);
                dest++; it++;
            }
            data.size = dest;
        }
        FastList<HookInfo> merged; 
        merged.reserve(data.size + old.data.size);
        size_t it1 = 0, it2 = 0;
        while (it1 < data.size && it2 < old.data.size) {
            if (data.data[it1].start < old.data.data[it2].start) merged.push_back(static_cast<HookInfo&&>(data.data[it1++]));
            else if (data.data[it1].start > old.data.data[it2].start) { 
                if (old.data.data[it2].backup) merged.push_back(static_cast<HookInfo&&>(old.data.data[it2])); 
                it2++; 
            }
            else { merged.push_back(static_cast<HookInfo&&>(old.data.data[it2++])); it1++; }
        }
        while (it1 < data.size) merged.push_back(static_cast<HookInfo&&>(data.data[it1++]));
        while (it2 < old.data.size) { 
            if (old.data.data[it2].backup) merged.push_back(static_cast<HookInfo&&>(old.data.data[it2])); 
            it2++; 
        }
        data = static_cast<FastList<HookInfo>&&>(merged);
    }

    bool BatchPatchPLTEntries(HookInfo& info, FastList<PendingPatch>& patches) {
        if (patches.empty()) return true;
        ::sort(patches.begin(), patches.end(), [](const auto& a, const auto& b) { return a.addr < b.addr; });
        const auto len = info.end - info.start;
        if (!info.backup && !info.self) {
            void *bkp = lsplt::sys::mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            if (bkp == MAP_FAILED) return false;
            if (lsplt::sys::mremap(reinterpret_cast<void *>(info.start), len, len, MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, bkp) == MAP_FAILED) {
                if (lsplt::sys::mprotect(bkp, len, PROT_READ|PROT_WRITE) != 0 || lsplt::sys::mprotect(reinterpret_cast<void*>(info.start), len, info.perms|PROT_READ) != 0) return false;
                __builtin_memcpy(bkp, reinterpret_cast<void*>(info.start), len);
                lsplt::sys::mprotect(reinterpret_cast<void*>(info.start), len, info.perms);
                lsplt::sys::mprotect(bkp, len, info.perms);
                __builtin___clear_cache((char*)bkp, (char*)bkp + len);
            }
            int fd = lsplt::sys::call<int>(SYS_openat, AT_FDCWD, (long)info.path, O_RDONLY | O_CLOEXEC);
            void *nw = (fd >= 0) ? lsplt::sys::mmap(reinterpret_cast<void*>(info.start), len, PROT_READ|PROT_WRITE|info.perms, MAP_PRIVATE|MAP_FIXED, fd, info.offset) : MAP_FAILED;
            if (fd >= 0) lsplt::sys::call(SYS_close, fd);
            if (nw == MAP_FAILED) nw = lsplt::sys::mmap(reinterpret_cast<void*>(info.start), len, PROT_READ|PROT_WRITE|info.perms, MAP_PRIVATE|MAP_FIXED|MAP_ANON, -1, 0);
            if (nw == MAP_FAILED) return false;
            __builtin_memcpy(reinterpret_cast<void*>(info.start), bkp, len);
            lsplt::sys::mprotect(reinterpret_cast<void*>(info.start), len, info.perms);
            info.backup = (uintptr_t)bkp;
        }
        uintptr_t cur_pg = 0, clr_s = 0, clr_e = 0; bool pg_unprot = false, res = true;

        auto restore_page_prot = [&]() {
            if (pg_unprot) {
                if (clr_s) {
                    __builtin___clear_cache(reinterpret_cast<char*>(clr_s), reinterpret_cast<char*>(clr_e));
                }
                lsplt::sys::mprotect(reinterpret_cast<void*>(cur_pg), lsplt::sys::SysPageSize(), info.perms);
            }
        };

        info.hooks.reserve(info.hooks.size + patches.size);
        for (size_t i = 0; i < patches.size; i++) {
            const auto& p = patches.data[i];
            auto *t_addr = reinterpret_cast<uintptr_t *>(p.addr); 
            auto t_bkp = *t_addr;
            if (*t_addr != p.callback) {
                uintptr_t pg_s = (uintptr_t)PageStart(p.addr);
                if (pg_s != cur_pg) {
                    restore_page_prot();
                    if (lsplt::sys::mprotect((void*)pg_s, lsplt::sys::SysPageSize(), info.perms | PROT_WRITE) == 0) {
                        cur_pg = pg_s;
                        pg_unprot = true;
                        clr_s = clr_e = 0;
                    } else {
                        res = false;
                        continue;
                    }
                }
                if (pg_unprot) {
                    *t_addr = p.callback;
                    if (p.backup) {
                        *p.backup = t_bkp;
                    }
                    if (!clr_s) {
                        clr_s = p.addr;
                        clr_e = p.addr + sizeof(uintptr_t);
                    } else {
                        clr_s = MIN_VAL(clr_s, p.addr);
                        clr_e = MAX_VAL(clr_e, p.addr + sizeof(uintptr_t));
                    }
                }
            }
            size_t idx = ::lower_bound(info.hooks.data, info.hooks.size, p.addr, [](const ActiveHook& h, uintptr_t a) { return h.addr < a; });
            if (idx < info.hooks.size && info.hooks.data[idx].addr == p.addr) {
                info.hooks.data[idx].orig_ptr = p.callback;
            } else {
                info.hooks.insert(idx, {p.addr, t_bkp});
            }
        }
        restore_page_prot();
        if (info.hooks.empty() && !info.self) { if (lsplt::sys::mremap((void*)info.backup, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, (void*)info.start) != MAP_FAILED) info.backup = 0; else return false; }
        return res;
    }

    bool RestoreFunction(FastList<HookRequest> &reg_info) {
        if (reg_info.empty()) return true;
        ::sort(reg_info.begin(), reg_info.end(), [](const auto& a, const auto& b) { 
            return reinterpret_cast<uintptr_t>(a.callback) < reinterpret_cast<uintptr_t>(b.callback);
        });
        
        FastList<PendingPatch> patches; bool res = true;
        for (size_t i = data.size; i > 0; --i) {
            auto& hi = data.data[i - 1];
            if (hi.hooks.empty()) continue; 
            patches.clear();
            for (size_t j = 0; j < hi.hooks.size; j++) {
                const auto& h = hi.hooks.data[j];
                size_t req_idx = ::lower_bound(reg_info.data, reg_info.size, h.orig_ptr, [](const HookRequest& r, uintptr_t val) { 
                    return (uintptr_t)r.callback < val; 
                });
                
                while (req_idx < reg_info.size && (uintptr_t)reg_info.data[req_idx].callback == h.orig_ptr) {
                    auto& req = reg_info.data[req_idx];
                    if (req.symbol[0] != '\0' && hi.dev == req.dev && hi.inode == req.inode) { 
                        patches.push_back({h.addr, h.orig_ptr, nullptr}); 
                        req.symbol[0] = '\0'; 
                    }
                    req_idx++;
                }
            }
            if (!patches.empty()) {
                res = BatchPatchPLTEntries(hi, patches) && res;
                size_t new_hooks = 0;
                for (size_t k = 0; k < hi.hooks.size; k++) {
                    if (hi.hooks.data[k].orig_ptr != 0) {
                        hi.hooks.data[new_hooks++] = hi.hooks.data[k];
                    }
                }
                hi.hooks.size = new_hooks;
            }
        }
        size_t new_reg = 0;
        for (size_t k = 0; k < reg_info.size; k++) {
            if (reg_info.data[k].symbol[0] != '\0') reg_info.data[new_reg++] = reg_info.data[k];
        }
        reg_info.size = new_reg;
        return res;
    }

    bool ProcessRequest(FastList<HookRequest> &reg_info) {
        bool res = true; 
        Elf::AddrList p_addr; 
        ::sort(reg_info.begin(), reg_info.end(), [](const auto& a, const auto& b) {
            if (a.dev != b.dev) return a.dev < b.dev;
            if (a.inode != b.inode) return a.inode < b.inode;
            return a.offset_range_start < b.offset_range_start;
        });
        HookInfo* last = nullptr; 
        static FastList<FastList<PendingPatch>> grouped;
        if (grouped.capacity < data.size) grouped.reserve(data.size);
        grouped.size = data.size;
        for (size_t i = 0; i < grouped.size; i++) grouped.data[i].clear();
        size_t new_reg = 0;
        for (size_t i = 0; i < reg_info.size; i++) {
            auto& reg = reg_info.data[i];
            bool remove = false;
            if (!last || last->offset != reg.offset_range_start || !last->Match(reg)) {
                last = nullptr; 
                for (size_t j = 0; j < data.size; j++) {
                    if (data.data[j].offset == reg.offset_range_start && data.data[j].Match(reg)) { last = &data.data[j]; break; }
                }
            }
            if (last) {
                if (!last->elf) last->elf = new Elf(last->start);
                if (last->elf->Valid()) {
                    last->elf->FindPltAddr(reg.symbol, p_addr);
                    if (p_addr.size == 0) res = false;
                    else {
                        for (size_t p = 0; p < p_addr.size; p++) {
                            uintptr_t a = p_addr.data[p];
                            size_t t_idx = ::upper_bound(data.data, data.size, a, [](uintptr_t v, const HookInfo& hi) { return v < hi.start; });
                            if (t_idx > 0 && a < data.data[t_idx - 1].end) {
                                grouped.data[t_idx - 1].push_back({a, (uintptr_t)reg.callback, (uintptr_t*)reg.backup});
                            } else res = false;
                        }
                    }
                }
                remove = true;
            }
            if (!remove) reg_info.data[new_reg++] = reg_info.data[i];
        }
        reg_info.size = new_reg;
        for (size_t i = 0; i < data.size; ++i) {
            if (!grouped.data[i].empty()) res = BatchPatchPLTEntries(data.data[i], grouped.data[i]) && res;
        }
        return res;
    }
};

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER; 
struct MutexGuard {
    pthread_mutex_t* m;
    MutexGuard(pthread_mutex_t* mutex) : m(mutex) { pthread_mutex_lock(m); }
    ~MutexGuard() { pthread_mutex_unlock(m); }
};

FastList<HookRequest> g_pend; 
HookInfos g_state;

} // anonymous namespace

namespace lsplt {
inline namespace v2 {

struct DlIterateData { MapInfoList *info; char c_path[PATH_MAX]; bool c_ok; ino_t c_ino; dev_t c_dev; char exe[PATH_MAX]; bool exe_ok; };
static int DlIterateCallback(struct dl_phdr_info *info, size_t, void *data) {
    auto *d = (DlIterateData *)data; const char *n = info->dlpi_name;
    if (!n || n[0] == '\0') {
        if (!d->exe_ok) { ssize_t l = readlink("/proc/self/exe", d->exe, sizeof(d->exe)-1); if (l != -1) d->exe[l] = '\0'; else d->exe[0] = '\0'; d->exe_ok = true; }
        n = d->exe;
    }
    ino_t ino = 0; dev_t dev = 0;
    if (n && n[0] == '/') {
        const char* ex = __builtin_strstr(n, "!/"); 
        size_t len = ex ? (size_t)(ex - n) : __builtin_strlen(n);
        if (len < PATH_MAX) {
            if (d->c_path[0] != '\0' && __builtin_strncmp(n, d->c_path, len) == 0 && d->c_path[len] == '\0') { if (d->c_ok) { ino = d->c_ino; dev = d->c_dev; } }
            else {
                char cn[PATH_MAX]; __builtin_memcpy(cn, n, len); cn[len] = '\0'; __builtin_memcpy(d->c_path, cn, len+1);
                struct stat st; if (stat(cn, &st) == 0) { ino = st.st_ino; dev = st.st_dev; d->c_ino = ino; d->c_dev = dev; d->c_ok = true; } else d->c_ok = false;
            }
        }
    }
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD) {
            MapInfo m; m.start = (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr) & lsplt::sys::SysPageMask();
            m.end = (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz + lsplt::sys::SysPageSize() - 1) & lsplt::sys::SysPageMask();
            m.offset = info->dlpi_phdr[i].p_offset & lsplt::sys::SysPageMask(); m.perms = 0;
            if (info->dlpi_phdr[i].p_flags & PF_R) m.perms |= PROT_READ;
            if (info->dlpi_phdr[i].p_flags & PF_W) m.perms |= PROT_WRITE;
            if (info->dlpi_phdr[i].p_flags & PF_X) m.perms |= PROT_EXEC;
            m.is_private = true; m.dev = dev; m.inode = ino;
            size_t c_len = __builtin_strlen(n ? n : "");
            if (c_len >= sizeof(m.path)) m.path[0] = '\0';
            else { __builtin_memcpy(m.path, n ? n : "", c_len); m.path[c_len] = '\0'; }
            d->info->push_back(m);
        }
    }
    return 0;
}

MapInfoList Scan() {
    MapInfoList info; 
    DlIterateData d; d.info = &info; d.c_path[0] = '\0'; d.c_ok = d.exe_ok = false;
    dl_iterate_phdr(DlIterateCallback, &d); return info;
}

bool RegisterHook(dev_t d, ino_t i, const char* s, void *c, void **b) {
    if (d == 0 || i == 0 || !s || s[0] == '\0' || !c) return false;
    const MutexGuard lock(&g_mtx); 
    HookRequest& r = g_pend.emplace_back();
    r.dev = d;
    r.inode = i;
    r.offset_range_start = 0;
    r.offset_range_end = (uintptr_t)-1;
    size_t l = MIN_VAL(__builtin_strlen(s), sizeof(r.symbol) - 1); 
    __builtin_memcpy(r.symbol, s, l); 
    r.symbol[l] = '\0';
    r.callback = c;
    r.backup = b;
    return true;
}

bool CommitHook(MapInfoList &m, bool u) {
    const MutexGuard lock(&g_mtx); 
    if (g_pend.empty()) return true;
    auto n = HookInfos::CreateTargetsFromMemoryMaps(m); 
    if (n.data.empty()) return false;
    n.Filter(g_pend); 
    n.Merge(g_state); 
    g_state = static_cast<HookInfos&&>(n);
    if (u && g_state.RestoreFunction(g_pend)) return true;
    return g_state.ProcessRequest(g_pend);
}

bool CommitHook() { auto m = Scan(); return CommitHook(m, false); }

} // namespace v2
} // namespace lsplt
