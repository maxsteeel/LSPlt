#include "include/lsplt.hpp"

#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

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
struct PendingPatch {
    uintptr_t addr;
    uintptr_t callback;
    uintptr_t* backup;
};
struct HookRequest {
    dev_t dev;
    ino_t inode;
    char symbol[128];
    void* callback;
    void** backup;
};


inline auto PageStart(uintptr_t a) {
    return reinterpret_cast<char*>(a & lsplt::sys::SysPageMask());
}

struct HookInfo : public lsplt::MapInfo {
    lsplt::FastList<ActiveHook> hooks;
    Elf* elf = nullptr;
    HookInfo() = default;
    HookInfo(const lsplt::MapInfo& map) : lsplt::MapInfo(map) {}
    ~HookInfo() { delete elf; }
    HookInfo(HookInfo&& o) noexcept
        : lsplt::MapInfo(o),
          hooks(static_cast<lsplt::FastList<ActiveHook>&&>(o.hooks)),
          elf(o.elf) {
        o.elf = nullptr;
    }
    HookInfo& operator=(HookInfo&& o) noexcept {
        if (this != &o) {
            lsplt::MapInfo::operator=(o);
            hooks = static_cast<lsplt::FastList<ActiveHook>&&>(o.hooks);
            delete elf;
            elf = o.elf;
            o.elf = nullptr;
        }
        return *this;
    }

    bool Match(const HookRequest& i) const { return i.dev == dev && i.inode == inode; }
};

class HookInfos {
public:
    lsplt::FastList<HookInfo> data;

    __attribute__((noinline)) static auto CreateTargetsFromMemoryMaps(
        lsplt::MapInfoList& maps, const lsplt::FastList<HookRequest>& reg_info) {
        HookInfos info;
        info.data.reserve(reg_info.size * 4);

        for (size_t i = 0; i < maps.size; i++) {
            auto& map = maps.data[i];
            if (map.inode == 0 || !map.is_private || !(map.perms & PROT_READ) ||
                map.path[0] == '\0' || map.path[0] == '[')
                continue;

            bool keep = false;
            for (size_t j = 0; j < reg_info.size; j++) {
                if (map.dev == reg_info.data[j].dev && map.inode == reg_info.data[j].inode) {
                    keep = true;
                    break;
                }
            }

            if (keep) {
                HookInfo hi(map);
                info.data.push_back(static_cast<HookInfo&&>(hi));
            }
        }
        return info;
    }

    __attribute__((noinline)) void Merge(HookInfos& old) {
        if (old.data.empty()) return;
        for (size_t i = 0; i < data.size; i++) {
            for (size_t j = 0; j < old.data.size; j++) {
                if (data.data[i].start == old.data.data[j].start) {
                    data.data[i].elf = old.data.data[j].elf;
                    old.data.data[j].elf = nullptr;
                    data.data[i].hooks =
                        static_cast<lsplt::FastList<ActiveHook>&&>(old.data.data[j].hooks);
                    break;
                }
            }
        }
        for (size_t j = 0; j < old.data.size; j++) {
            if (!old.data.data[j].hooks.empty()) 
                data.push_back(static_cast<HookInfo&&>(old.data.data[j]));
        }
    }

    __attribute__((noinline)) bool BatchPatchPLTEntries(HookInfo& info,
                                                        lsplt::FastList<PendingPatch>& patches) {
        if (patches.empty()) return true;

        uintptr_t cur_pg = 0, clr_s = 0, clr_e = 0;
        int cur_perms = 0;
        bool pg_unprot = false, res = true;

        auto restore_page_prot = [&]() {
            if (pg_unprot) {
                if (clr_s)
                    __builtin___clear_cache(reinterpret_cast<char*>(clr_s),
                                            reinterpret_cast<char*>(clr_e));
                lsplt::sys::mprotect(reinterpret_cast<void*>(cur_pg), lsplt::sys::SysPageSize(),
                                     cur_perms);
            }
        };

        info.hooks.reserve(info.hooks.size + patches.size);
        for (size_t i = 0; i < patches.size; i++) {
            const auto& p = patches.data[i];
            auto* t_addr = reinterpret_cast<uintptr_t*>(p.addr);

            uintptr_t pg_s = (uintptr_t)PageStart(p.addr);
            if (pg_s != cur_pg) {
                restore_page_prot();
                int exact_perms = info.elf ? info.elf->GetExactProtection(pg_s) : -1;
                cur_perms = exact_perms != -1 ? exact_perms : info.perms;

                if (lsplt::sys::mprotect((void*)pg_s, lsplt::sys::SysPageSize(),
                                         (cur_perms & ~PROT_EXEC) | PROT_WRITE | PROT_READ) == 0) {
                    cur_pg = pg_s;
                    pg_unprot = true;
                    clr_s = clr_e = 0;
                } else {
                    res = false;
                    continue; // Skip silently if mprotect fails
                }
            }

            if (pg_unprot) {
                auto t_bkp = *t_addr; 
                
                if (t_bkp != p.callback) {
                    *t_addr = p.callback;
                    if (p.backup) *p.backup = t_bkp;
                    if (!clr_s) {
                        clr_s = p.addr;
                        clr_e = p.addr + sizeof(uintptr_t);
                    } else {
                        clr_s = MIN_VAL(clr_s, p.addr);
                        clr_e = MAX_VAL(clr_e, p.addr + sizeof(uintptr_t));
                    }
                }

                // Track hook
                bool found = false;
                for (size_t k = 0; k < info.hooks.size; k++) {
                    if (info.hooks.data[k].addr == p.addr) {
                        found = true;
                        break;
                    }
                }
                if (!found) info.hooks.push_back({p.addr, t_bkp});
            }
        }
        restore_page_prot();
        return res;
    }

    template <typename MatchLogic>
    __attribute__((noinline)) bool ApplyPatches(MatchLogic match_logic, bool is_restore = false) {
        bool res = true;
        lsplt::FastList<PendingPatch> patches;

        for (size_t i = 0; i < data.size; i++) {
            auto& hi = data.data[i];
            patches.clear();

            if (!match_logic(hi, patches)) {
                res = false;
            }

            if (!patches.empty()) {
                res = BatchPatchPLTEntries(hi, patches) && res;
                if (is_restore) {
                    size_t new_hooks = 0;
                    for (size_t k = 0; k < hi.hooks.size; k++) {
                        bool removed = false;
                        for (size_t p = 0; p < patches.size; p++) {
                            if (hi.hooks.data[k].addr == patches.data[p].addr) {
                                removed = true;
                                break;
                            }
                        }
                        if (!removed) hi.hooks.data[new_hooks++] = hi.hooks.data[k];
                    }
                    hi.hooks.size = new_hooks;
                }
            }
        }
        return res;
    }

    __attribute__((noinline)) bool RestoreFunction(lsplt::FastList<HookRequest>& reg_info) {
        if (reg_info.empty()) return true;
        return ApplyPatches(
            [&](HookInfo& hi, lsplt::FastList<PendingPatch>& patches) {
                if (hi.hooks.empty()) return true;
                for (size_t k = 0; k < reg_info.size; k++) {
                    auto& req = reg_info.data[k];
                    if (req.symbol[0] != '\0' && hi.dev == req.dev && hi.inode == req.inode) {
                        for (size_t j = 0; j < hi.hooks.size; j++) {
                            const auto& h = hi.hooks.data[j];
                            if ((uintptr_t)req.callback == h.orig_ptr) {
                                patches.push_back({h.addr, h.orig_ptr, nullptr});
                                req.symbol[0] = '\0';
                                break;
                            }
                        }
                    }
                }
                return true;
            },
            true); // is_restore = true
    }

    __attribute__((noinline)) bool ProcessRequest(lsplt::FastList<HookRequest>& reg_info) {
        // Pre-calculate the PLT addresses for each hook request.
        Elf::AddrList* cached_addrs = new Elf::AddrList[reg_info.size];

        for (size_t j = 0; j < reg_info.size; j++) {
            auto& reg = reg_info.data[j];
            HookInfo* base_hi = nullptr;
            for (size_t k = 0; k < data.size; k++) {
                if (data.data[k].Match(reg)) {
                    if (data.data[k].offset == 0) {
                        if (!data.data[k].elf) {
                            data.data[k].elf = new Elf(data.data[k].start);
                        }
                        if (data.data[k].elf->Valid()) {
                            base_hi = &data.data[k];
                            break;
                        }
                    }
                }
            }
            if (base_hi) {
                base_hi->elf->FindPltAddr(reg.symbol, cached_addrs[j]);
            }
        }

        // We iterate each memory segment and check if any of
        // the requested PLT addresses physically fall within it.
        bool res = ApplyPatches([&](HookInfo& hi, lsplt::FastList<PendingPatch>& patches) {
            bool ok = true;
            for (size_t j = 0; j < reg_info.size; j++) {
                auto& reg = reg_info.data[j];
                if (hi.Match(reg)) {
                    auto& cached = cached_addrs[j];
                    if (!cached.empty()) {
                        for (size_t p = 0; p < cached.size; p++) {
                            uintptr_t a = cached.data[p];
                            if (a >= hi.start && a < hi.end) {
                                patches.push_back(
                                    {a, (uintptr_t)reg.callback, (uintptr_t*)reg.backup});
                            }
                        }
                    } else {
                        ok = false;
                    }
                }
            }
            return ok;
        });

        delete[] cached_addrs;
        return res;
    }
};

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
struct MutexGuard {
    pthread_mutex_t* m;
    MutexGuard(pthread_mutex_t* mutex) : m(mutex) { pthread_mutex_lock(m); }
    ~MutexGuard() { pthread_mutex_unlock(m); }
};

static lsplt::FastList<HookRequest>* g_pend = nullptr;
static HookInfos* g_state = nullptr;

}  // anonymous namespace

namespace lsplt {
inline namespace v2 {

static int DlIterateCallback(struct dl_phdr_info* info, size_t, void* data) {
    auto* info_list = static_cast<MapInfoList*>(data);
    const char* n = info->dlpi_name;
    ino_t ino = 0;
    dev_t dev = 0;

    if (n && n[0] == '/') {
        struct stat st;
        if (stat(n, &st) == 0) {
            ino = st.st_ino;
            dev = st.st_dev;
        }
    }

    const char* c_str = n ? n : "";
    size_t c_len = __builtin_strlen(c_str);

    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD) {
            MapInfo m;
            m.start = (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr) & lsplt::sys::SysPageMask();
            m.end = (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz +
                     lsplt::sys::SysPageSize() - 1) &
                    lsplt::sys::SysPageMask();
            m.offset = info->dlpi_phdr[i].p_offset & lsplt::sys::SysPageMask();
            m.perms = 0;
            if (info->dlpi_phdr[i].p_flags & PF_R) m.perms |= PROT_READ;
            if (info->dlpi_phdr[i].p_flags & PF_W) m.perms |= PROT_WRITE;
            if (info->dlpi_phdr[i].p_flags & PF_X) m.perms |= PROT_EXEC;
            m.is_private = true;
            m.dev = dev;
            m.inode = ino;
            if (c_len >= sizeof(m.path)) {
                m.path[0] = '\0';
            } else {
                __builtin_memcpy(m.path, c_str, c_len);
                m.path[c_len] = '\0';
            }
            info_list->push_back(m);
        }
    }
    return 0;
}

MapInfoList Scan() {
    MapInfoList info;
    dl_iterate_phdr(DlIterateCallback, &info);
    return info;
}

bool RegisterHook(dev_t d, ino_t i, const char* s, void* c, void** b) {
    if (d == 0 || i == 0 || !s || s[0] == '\0' || !c) return false;
    const MutexGuard lock(&g_mtx);
    if (!g_pend) g_pend = new lsplt::FastList<HookRequest>();
    HookRequest r;
    r.dev = d;
    r.inode = i;
    size_t l = MIN_VAL(__builtin_strlen(s), sizeof(r.symbol) - 1);
    __builtin_memcpy(r.symbol, s, l);
    r.symbol[l] = '\0';
    r.callback = c;
    r.backup = b;
    g_pend->push_back(r);
    return true;
}

bool CommitHook(MapInfoList& m, bool u) {
    const MutexGuard lock(&g_mtx);
    if (!g_pend || g_pend->empty()) return true;
    auto n = HookInfos::CreateTargetsFromMemoryMaps(m, *g_pend);
    if (n.data.empty()) {
        g_pend->clear();
        return false;
    }
    if (!g_state) g_state = new HookInfos();
    n.Merge(*g_state);
    *g_state = static_cast<HookInfos&&>(n);
    bool res = u ? g_state->RestoreFunction(*g_pend) : g_state->ProcessRequest(*g_pend);
    g_pend->clear();
    return res;
}

}  // namespace v2
}  // namespace lsplt
