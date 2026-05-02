#pragma once

#include <sys/mman.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdlib.h>

static void* memalloc(void* old_data, size_t old_size, size_t new_cap, size_t elem_size) {
    if (old_size > new_cap) return nullptr;
    size_t alloc_size;
    if (__builtin_mul_overflow(new_cap, elem_size, &alloc_size)) return nullptr;
    void* new_data = malloc(alloc_size);
    if (!new_data) return nullptr;
    if (old_data && old_size > 0) {
        __builtin_memcpy(new_data, old_data, old_size * elem_size);
    }
    if (old_data) free(old_data);
    return new_data;
}

namespace lsplt {
inline namespace v2 {
template <typename T>
struct FastList {
    T* data = nullptr;
    size_t size = 0;
    size_t capacity = 0;
    FastList() = default;
    ~FastList() {
        clear();
        free(data);
    }
    FastList(FastList&& o) noexcept : data(o.data), size(o.size), capacity(o.capacity) {
        o.data = nullptr;
        o.size = o.capacity = 0;
    }
    FastList& operator=(FastList&& o) noexcept {
        if (this != &o) {
            clear();
            free(data);
            data = o.data;
            size = o.size;
            capacity = o.capacity;
            o.data = nullptr;
            o.size = o.capacity = 0;
        }
        return *this;
    }
    FastList(const FastList&) = delete;
    FastList& operator=(const FastList&) = delete;
    void reserve(size_t n) {
        if (n > capacity) {
            void* nd = memalloc(data, size, n, sizeof(T));
            if (nd) {
                data = static_cast<T*>(nd);
                capacity = n;
            }
        }
    }
    void push_back(const T& val) {
        if (size >= capacity) reserve(capacity == 0 ? 8 : capacity * 2);
        if (size < capacity) {
            __builtin_memset(&data[size], 0, sizeof(T));
            data[size++] = val;
        }
    }
    void push_back(T&& val) {
        if (size >= capacity) reserve(capacity == 0 ? 8 : capacity * 2);
        if (size < capacity) {
            __builtin_memset((void*)&data[size], 0, sizeof(T));
            data[size++] = static_cast<T&&>(val);
        }
    }
    void clear() {
        if (data)
            for (size_t i = 0; i < size; i++) data[i].~T();
        size = 0;
    }
    bool empty() const { return size == 0; }
};

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

using MapInfoList = FastList<MapInfo>;

[[maybe_unused, gnu::visibility("default")]] MapInfoList Scan();
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(dev_t dev, ino_t inode, const char* symbol, void *callback, void **backup);
[[maybe_unused, gnu::visibility("default")]] bool CommitHook(MapInfoList &maps, bool unhook = false);

} // namespace v2
} // namespace lsplt
