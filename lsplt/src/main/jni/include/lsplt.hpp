#pragma once

#include <sys/types.h>
#include <linux/limits.h>
#include <string_view>
#include <vector>

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

    [[maybe_unused, gnu::visibility("default")]] static std::vector<MapInfo> Scan();
};

[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol,
                                                               void *callback, void **backup);
[[maybe_unused, gnu::visibility("default")]] bool CommitHook();
[[maybe_unused, gnu::visibility("default")]] bool CommitHook(std::vector<MapInfo> &maps, bool unhook = false);

} // namespace v2
} // namespace lsplt
