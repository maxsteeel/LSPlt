#pragma once
#include <link.h>
#include <stdint.h>
#include <string_view>
#include <vector>

struct SymName {
    std::string_view name;
    uint32_t gnu_hash = 5381;
    uint32_t elf_hash = 0;

    explicit SymName(std::string_view n) : name(n) {
        for (unsigned char chr : n) {
            gnu_hash = (gnu_hash << 5) + gnu_hash + chr;
            elf_hash = (elf_hash << 4) + chr;
            uint32_t tmp = elf_hash & 0xf0000000;
            if (tmp) elf_hash ^= tmp | (tmp >> 24);
        }
    }
};

class Elf {
    struct Reloc { uint32_t sym; ElfW(Addr) addr; };
    
    ElfW(Addr) base_addr_ = 0, bias_addr_ = 0;
    ElfW(Ehdr) *header_ = nullptr;
    ElfW(Dyn)  *dynamic_ = nullptr;
    ElfW(Sym)  *dyn_sym_ = nullptr;
    const char *dyn_str_ = nullptr;
    
    ElfW(Addr) rel_plt_ = 0, rel_dyn_ = 0;
    ElfW(Word) rel_plt_size_ = 0, rel_dyn_size_ = 0, dynamic_size_ = 0;

    uint32_t *bucket_ = nullptr, *chain_ = nullptr, bucket_count_ = 0, sym_offset_ = 0;
    ElfW(Addr) *bloom_ = nullptr;
    uint32_t bloom_size_ = 0, bloom_shift_ = 0;

    bool is_use_rela_ = false, valid_ = false;
    std::vector<Reloc> plt_relocs_, dyn_relocs_;

    template <typename T> void ProcessReloc(ElfW(Addr) begin, ElfW(Word) size, bool is_plt);
    void DoReloc(ElfW(Addr) rel, ElfW(Word) size, bool is_plt);
    void BuildRelocIndex();
    bool ParseHeader();
    bool ParseDynamicTable();
    uint32_t GnuLookup(const SymName& name) const;
    uint32_t ElfLookup(const SymName& name) const;
    uint32_t LinearLookup(const SymName& name) const;

public:
    explicit Elf(uintptr_t base_addr);
    void FindPltAddr(std::string_view name, std::vector<uintptr_t> &res) const;
    bool Valid() const { return valid_; }
};
