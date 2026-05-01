#pragma once

#include <sys/types.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdlib.h>

static void* memalloc(void* old_data, size_t old_size, size_t new_cap, size_t elem_size, bool reserve) {
    if (old_size > new_cap) return nullptr;
    size_t alloc_size;
    if (__builtin_mul_overflow(new_cap, elem_size, &alloc_size)) return nullptr;
    void* new_data = malloc(alloc_size);
    if (!new_data) return nullptr;
    if (old_data && old_size > 0) __builtin_memcpy(new_data, old_data, old_size * elem_size);
    if (reserve) __builtin_memset(reinterpret_cast<char*>(new_data) + (old_size * elem_size), 0, (new_cap - old_size) * elem_size);
    if (old_data) free(old_data);
    return new_data;
}

namespace lsplt {
inline namespace v2 {
struct MapInfo {
    uintptr_t start;
    uintptr_t end;
    uint8_t perms;
    bool is_private;
    uintptr_t offset;
    dev_t dev;
    ino_t inode;
    char path[PATH_MAX];
};

struct MapInfoList {
    MapInfo* data = nullptr;
    size_t size = 0;
    size_t capacity = 0;
    MapInfoList() = default;
    MapInfoList(const MapInfoList&) = delete;
    MapInfoList& operator=(const MapInfoList&) = delete;
    MapInfoList(MapInfoList&& o) noexcept : data(o.data), size(o.size), capacity(o.capacity) {
        o.data = nullptr; 
        o.size = o.capacity = 0;
    }
    MapInfoList& operator=(MapInfoList&& o) noexcept {
        if (this != &o) { 
            if (data) free(data); 
            data = o.data; 
            size = o.size; 
            capacity = o.capacity; 
            o.data = nullptr; 
            o.size = o.capacity = 0; 
        }
        return *this;
    }
    ~MapInfoList() { 
        if (data) free(data); 
    }
    void push_back(const MapInfo& m) {
        if (size >= capacity) {
            size_t n = capacity == 0 ? 64 : capacity * 2;
            void* nd = memalloc(data, size, n, sizeof(MapInfo), false);
            if (nd) { data = static_cast<MapInfo*>(nd); capacity = n; }
            else return;
        }
        data[size++] = m;
    }
    void clear() { size = 0; }
};

[[maybe_unused, gnu::visibility("default")]] MapInfoList Scan();
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(dev_t dev, ino_t inode, const char* symbol, void *callback, void **backup);
[[maybe_unused, gnu::visibility("default")]] bool CommitHook(MapInfoList &maps, bool unhook = false);

} // namespace v2
} // namespace lsplt
