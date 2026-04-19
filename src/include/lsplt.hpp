#pragma once

#include <sys/types.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdlib.h>

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
    ~MapInfoList() { free(data); }
    MapInfoList() = default;
    MapInfoList(MapInfoList&& o) noexcept : data(o.data), size(o.size), capacity(o.capacity) {
        o.data = nullptr; o.size = o.capacity = 0;
    }
    MapInfoList& operator=(MapInfoList&& o) noexcept {
        if (this != &o) { 
            free(data); data = o.data; size = o.size; capacity = o.capacity; 
            o.data = nullptr; o.size = o.capacity = 0; 
        }
        return *this;
    }
    void push_back(const MapInfo& m) {
        if (size >= capacity) {
            capacity = capacity == 0 ? 64 : capacity * 2;
            data = (MapInfo*)realloc(data, capacity * sizeof(MapInfo));
        }
        data[size++] = m;
    }
};

[[maybe_unused, gnu::visibility("default")]] MapInfoList Scan();
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(dev_t dev, ino_t inode, const char* symbol, void *callback, void **backup);
[[maybe_unused, gnu::visibility("default")]] bool CommitHook();
[[maybe_unused, gnu::visibility("default")]] bool CommitHook(MapInfoList &maps, bool unhook = false);

} // namespace v2
} // namespace lsplt
