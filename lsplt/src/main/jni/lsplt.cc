#include "include/lsplt.hpp"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <link.h>
#include <unistd.h>
#include <algorithm>
#include <vector>
#include <mutex>
#include <optional>
#include <cstring>
#include "elf_util.hpp"
#include "logging.hpp"
#include "syscall.hpp"

namespace {

struct ActiveHook {
    uintptr_t addr;
    uintptr_t orig_ptr;
};

struct PendingPatch {
    uintptr_t addr;
    uintptr_t callback;
    uintptr_t *backup;
};

struct HookRequest {
    dev_t dev;
    ino_t inode;
    std::pair<uintptr_t, uintptr_t> offset_range;
    char symbol[128];
    void *callback;
    void **backup;
};

inline auto PageStart(uintptr_t a) { 
    return reinterpret_cast<char *>(a & lsplt::sys::SysPageMask()); 
}

struct HookInfo : public lsplt::MapInfo {
    std::vector<ActiveHook> hooks;
    uintptr_t backup = 0;
    std::optional<Elf> elf;
    bool self;

    HookInfo(lsplt::MapInfo&& map, bool is_self) : lsplt::MapInfo(std::move(map)), self(is_self) {}
    bool Match(const HookRequest &i) const { 
        return i.dev == dev && i.inode == inode && offset >= i.offset_range.first && offset < i.offset_range.second; 
    }
};

class HookInfos {
public:
    std::vector<HookInfo> data;

    static auto CreateTargetsFromMemoryMaps(std::vector<lsplt::MapInfo> &maps) {
        static ino_t kSelfInode = 0; static dev_t kSelfDev = 0;
        HookInfos info; info.data.reserve(maps.size());
        const uintptr_t self_addr = (kSelfInode == 0) ? reinterpret_cast<uintptr_t>(__builtin_return_address(0)) : 0;
        for (auto &map : maps) {
            if (kSelfInode == 0 && self_addr >= map.start && self_addr < map.end) { kSelfInode = map.inode; kSelfDev = map.dev; }
            if (map.inode == 0 || !map.is_private || !(map.perms & PROT_READ) || map.path[0] == '\0' || map.path[0] == '[') continue;
            info.data.emplace_back(std::move(map), (kSelfInode != 0 && map.inode == kSelfInode && map.dev == kSelfDev));
        }
        return info;
    }

    void Filter(const std::vector<HookRequest> &register_info) {
        if (register_info.empty()) { data.clear(); return; }
        static std::vector<const HookRequest*> sorted; sorted.clear(); sorted.reserve(register_info.size());
        for (const auto& reg : register_info) sorted.push_back(&reg);
        qsort(sorted.data(), sorted.size(), sizeof(HookRequest*), [](const void* a, const void* b) -> int {
            auto ra = *(const HookRequest**)a, rb = *(const HookRequest**)b;
            if (ra->dev != rb->dev) return (ra->dev > rb->dev) - (ra->dev < rb->dev);
            return (ra->inode > rb->inode) - (ra->inode < rb->inode);
        });
        auto it = std::remove_if(data.begin(), data.end(), [&](const auto &info) {
            size_t low = 0, high = sorted.size();
            while (low < high) {
                size_t mid = low + (high - low) / 2;
                if (sorted[mid]->dev < info.dev || (sorted[mid]->dev == info.dev && sorted[mid]->inode < info.inode)) low = mid + 1;
                else high = mid;
            }
            for (size_t i = low; i < sorted.size() && sorted[i]->dev == info.dev && sorted[i]->inode == info.inode; ++i)
                if (info.Match(*sorted[i])) return false;
            return true;
        });
        data.erase(it, data.end());
    }

    void Merge(HookInfos &old) {
        if (old.data.empty()) return;
        std::vector<uintptr_t> backups; for (const auto &i : old.data) if (i.backup) backups.push_back(i.backup);
        if (!backups.empty()) {
            qsort(backups.data(), backups.size(), sizeof(uintptr_t), [](const void* a, const void* b) { 
                uintptr_t va = *(uintptr_t*)a, vb = *(uintptr_t*)b;
                return (va > vb) - (va < vb);
            });
            data.erase(std::remove_if(data.begin(), data.end(), [&](const auto& hi) { 
                return std::binary_search(backups.begin(), backups.end(), hi.start); 
            }), data.end());
        }
        std::vector<HookInfo> merged; merged.reserve(data.size() + old.data.size());
        auto it1 = data.begin(), it2 = old.data.begin();
        while (it1 != data.end() && it2 != old.data.end()) {
            if (it1->start < it2->start) merged.push_back(std::move(*it1++));
            else if (it1->start > it2->start) { if (it2->backup) merged.push_back(std::move(*it2)); it2++; }
            else { merged.push_back(std::move(*it2++)); it1++; }
        }
        while (it1 != data.end()) merged.push_back(std::move(*it1++));
        while (it2 != old.data.end()) { if (it2->backup) merged.push_back(std::move(*it2)); it2++; }
        data = std::move(merged);
    }

    bool BatchPatchPLTEntries(HookInfo& info, std::vector<PendingPatch>& patches) {
        if (patches.empty()) return true;
        qsort(patches.data(), patches.size(), sizeof(PendingPatch), [](const void* a, const void* b) { 
            uintptr_t va = ((PendingPatch*)a)->addr, vb = ((PendingPatch*)b)->addr;
            return (va > vb) - (va < vb);
        });
        const auto len = info.end - info.start;
        if (!info.backup && !info.self) {
            void *bkp = lsplt::sys::mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            if (bkp == MAP_FAILED) return false;
            if (lsplt::sys::mremap(reinterpret_cast<void *>(info.start), len, len, MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, bkp) == MAP_FAILED) {
                if (lsplt::sys::mprotect(bkp, len, PROT_READ|PROT_WRITE) != 0 || lsplt::sys::mprotect(reinterpret_cast<void*>(info.start), len, info.perms|PROT_READ) != 0) return false;
                memcpy(bkp, reinterpret_cast<void*>(info.start), len);
                lsplt::sys::mprotect(reinterpret_cast<void*>(info.start), len, info.perms);
                lsplt::sys::mprotect(bkp, len, info.perms);
                __builtin___clear_cache((char*)bkp, (char*)bkp + len);
            }
            int fd = lsplt::sys::call<int>(SYS_openat, AT_FDCWD, (long)info.path, O_RDONLY | O_CLOEXEC);
            void *nw = (fd >= 0) ? lsplt::sys::mmap(reinterpret_cast<void*>(info.start), len, PROT_READ|PROT_WRITE|info.perms, MAP_PRIVATE|MAP_FIXED, fd, info.offset) : MAP_FAILED;
            if (fd >= 0) lsplt::sys::call(SYS_close, fd);
            if (nw == MAP_FAILED) nw = lsplt::sys::mmap(reinterpret_cast<void*>(info.start), len, PROT_READ|PROT_WRITE|info.perms, MAP_PRIVATE|MAP_FIXED|MAP_ANON, -1, 0);
            if (nw == MAP_FAILED) return false;
            memcpy(reinterpret_cast<void*>(info.start), bkp, len);
            lsplt::sys::mprotect(reinterpret_cast<void*>(info.start), len, info.perms);
            info.backup = (uintptr_t)bkp;
        }
        uintptr_t cur_pg = 0, clr_s = 0, clr_e = 0; bool pg_unprot = false, res = true;
        info.hooks.reserve(info.hooks.size() + patches.size());
        for (const auto& p : patches) {
            auto *t_addr = reinterpret_cast<uintptr_t *>(p.addr); 
            auto t_bkp = *t_addr;
            if (*t_addr != p.callback) {
                uintptr_t pg_s = (uintptr_t)PageStart(p.addr);
                if (pg_s != cur_pg) {
                    if (pg_unprot) { if (clr_s) __builtin___clear_cache((char*)clr_s, (char*)clr_e); lsplt::sys::mprotect((void*)cur_pg, lsplt::sys::SysPageSize(), info.perms); }
                    if (lsplt::sys::mprotect((void*)pg_s, lsplt::sys::SysPageSize(), info.perms | PROT_WRITE) == 0) { cur_pg = pg_s; pg_unprot = true; clr_s = clr_e = 0; }
                    else { res = false; continue; }
                }
                if (pg_unprot) {
                    *t_addr = p.callback; if (p.backup) *p.backup = t_bkp;
                    if (!clr_s) { clr_s = p.addr; clr_e = p.addr + sizeof(uintptr_t); }
                    else { clr_s = std::min(clr_s, p.addr); clr_e = std::max(clr_e, p.addr + sizeof(uintptr_t)); }
                }
            }

            auto it = std::lower_bound(info.hooks.begin(), info.hooks.end(), p.addr, 
                [](const ActiveHook& h, uintptr_t a) { return h.addr < a; });

            if (it != info.hooks.end() && it->addr == p.addr) {
                it->orig_ptr = p.callback; // Update
            } else {
                info.hooks.insert(it, {p.addr, t_bkp});
            }
        }
        
        if (pg_unprot) { if (clr_s) __builtin___clear_cache((char*)clr_s, (char*)clr_e); lsplt::sys::mprotect((void*)cur_pg, lsplt::sys::SysPageSize(), info.perms); }
        if (info.hooks.empty() && !info.self) { if (lsplt::sys::mremap((void*)info.backup, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, (void*)info.start) != MAP_FAILED) info.backup = 0; else return false; }
        return res;
    }

    bool RestoreFunction(std::vector<HookRequest> &reg_info) {
        if (reg_info.empty()) return true;
        qsort(reg_info.data(), reg_info.size(), sizeof(HookRequest), [](const void* a, const void* b) { 
            uintptr_t ca = (uintptr_t)((const HookRequest*)a)->callback;
            uintptr_t cb = (uintptr_t)((const HookRequest*)b)->callback;
            return (ca > cb) - (ca < cb);
        });
        std::vector<PendingPatch> patches; bool res = true;
        for (auto it = data.rbegin(); it != data.rend(); ++it) {
            if (it->hooks.empty()) continue; patches.clear();
            for (const auto& h : it->hooks) {
                auto req = std::lower_bound(reg_info.begin(), reg_info.end(), h.orig_ptr, [](const HookRequest& r, uintptr_t val) { 
                    return (uintptr_t)r.callback < val; 
                });
                while (req != reg_info.end() && (uintptr_t)req->callback == h.orig_ptr) {
                    if (req->symbol[0] != '\0' && it->dev == req->dev && it->inode == req->inode) { 
                        patches.push_back({h.addr, h.orig_ptr, nullptr}); req->symbol[0] = '\0'; 
                    }
                    ++req;
                }
            }
            if (!patches.empty()) {
                res = BatchPatchPLTEntries(*it, patches) && res;
                it->hooks.erase(std::remove_if(it->hooks.begin(), it->hooks.end(), [](const ActiveHook& ah) {
                    return ah.orig_ptr == 0; // Assume we mark it 0 if fully removed
                }), it->hooks.end());
            }
        }
        reg_info.erase(std::remove_if(reg_info.begin(), reg_info.end(), [](const auto& r) { return r.symbol[0] == '\0'; }), reg_info.end());
        return res;
    }

    bool ProcessRequest(std::vector<HookRequest> &reg_info) {
        bool res = true; std::vector<uintptr_t> p_addr; p_addr.reserve(4);
        qsort(reg_info.data(), reg_info.size(), sizeof(HookRequest), [](const void* a, const void* b) -> int {
            auto ra = (const HookRequest*)a, rb = (const HookRequest*)b;
            if (ra->dev != rb->dev) return (ra->dev > rb->dev) - (ra->dev < rb->dev);
            if (ra->inode != rb->inode) return (ra->inode > rb->inode) - (ra->inode < rb->inode);
            return (ra->offset_range.first > rb->offset_range.first) - (ra->offset_range.first < rb->offset_range.first);
        });
        HookInfo* last = nullptr; static std::vector<std::vector<PendingPatch>> grouped;
        if (grouped.size() < data.size()) grouped.resize(data.size());
        for (auto &g : grouped) g.clear();
        auto iter = std::remove_if(reg_info.begin(), reg_info.end(), [&](const auto &reg) {
            if (!last || last->offset != reg.offset_range.first || !last->Match(reg)) {
                last = nullptr; for (auto &i : data) if (i.offset == reg.offset_range.first && i.Match(reg)) { last = &i; break; }
            }
            if (last) {
                if (!last->elf) last->elf.emplace(last->start);
                if (last->elf->Valid()) {
                    last->elf->FindPltAddr(reg.symbol, p_addr);
                    if (p_addr.empty()) res = false;
                    else for (auto a : p_addr) {
                        auto t = std::upper_bound(data.begin(), data.end(), a, [](uintptr_t v, const auto& hi) { return v < hi.start; });
                        if (t != data.begin() && a < (--t)->end) grouped[std::distance(data.begin(), t)].push_back({a, (uintptr_t)reg.callback, (uintptr_t*)reg.backup});
                        else res = false;
                    }
                }
                return true;
            }
            return false;
        });
        reg_info.erase(iter, reg_info.end());
        for (size_t i = 0; i < data.size(); ++i) if (!grouped[i].empty()) res = BatchPatchPLTEntries(data[i], grouped[i]) && res;
        return res;
    }
};

std::mutex g_mtx; std::vector<HookRequest> g_pend = {}; HookInfos g_state;

}

namespace lsplt {
inline namespace v2 {

struct DlIterateData { std::vector<MapInfo> *info; char c_path[PATH_MAX]; bool c_ok; ino_t c_ino; dev_t c_dev; char exe[PATH_MAX]; bool exe_ok; };

static int DlIterateCallback(struct dl_phdr_info *info, size_t, void *data) {
    auto *d = (DlIterateData *)data; const char *n = info->dlpi_name;
    if (!n || n[0] == '\0') {
        if (!d->exe_ok) { ssize_t l = readlink("/proc/self/exe", d->exe, sizeof(d->exe)-1); if (l != -1) d->exe[l] = '\0'; else d->exe[0] = '\0'; d->exe_ok = true; }
        n = d->exe;
    }
    ino_t ino = 0; dev_t dev = 0;
    if (n && n[0] == '/') {
        const char* ex = strstr(n, "!/"); size_t len = ex ? (size_t)(ex - n) : strlen(n);
        if (len < PATH_MAX) {
            if (d->c_path[0] != '\0' && strncmp(n, d->c_path, len) == 0 && d->c_path[len] == '\0') { if (d->c_ok) { ino = d->c_ino; dev = d->c_dev; } }
            else {
                char cn[PATH_MAX]; memcpy(cn, n, len); cn[len] = '\0'; memcpy(d->c_path, cn, len+1);
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
            if (strlcpy(m.path, n ? n : "", sizeof(m.path)) >= sizeof(m.path)) m.path[0] = '\0';
            d->info->push_back(m);
        }
    }
    return 0;
}

std::vector<MapInfo> MapInfo::Scan() {
    std::vector<MapInfo> info; info.reserve(2048); DlIterateData d; d.info = &info; d.c_path[0] = '\0'; d.c_ok = d.exe_ok = false;
    dl_iterate_phdr(DlIterateCallback, &d); return info;
}

bool RegisterHook(dev_t d, ino_t i, std::string_view s, void *c, void **b) {
    if (d == 0 || i == 0 || s.empty() || !c) return false;
    const std::unique_lock lock(g_mtx); HookRequest r{d, i, {0, (uintptr_t)-1}, {0}, c, b};
    size_t l = std::min(s.length(), sizeof(r.symbol) - 1); memcpy(r.symbol, s.data(), l); r.symbol[l] = '\0';
    g_pend.push_back(r); return true;
}

bool CommitHook(std::vector<MapInfo> &m, bool u) {
    const std::unique_lock lock(g_mtx); if (g_pend.empty()) return true;
    auto n = HookInfos::CreateTargetsFromMemoryMaps(m); if (n.data.empty()) return false;
    n.Filter(g_pend); n.Merge(g_state); g_state = std::move(n);
    if (u && g_state.RestoreFunction(g_pend)) return true;
    return g_state.ProcessRequest(g_pend);
}

bool CommitHook() { auto m = MapInfo::Scan(); return CommitHook(m, false); }

} // namespace v2
} // namespace lsplt
