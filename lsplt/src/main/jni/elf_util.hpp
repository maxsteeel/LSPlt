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
            gnu_hash += (gnu_hash << 5) + chr;
            elf_hash = (elf_hash << 4) + chr;
            uint32_t tmp = elf_hash & 0xf0000000;
            elf_hash ^= tmp | (tmp >> 24);
        }
    }
};

class Elf {
    ElfW(Addr) base_addr_ = 0;
    ElfW(Addr) bias_addr_ = 0;

    ElfW(Ehdr) *header_ = nullptr;
    ElfW(Phdr) *program_header_ = nullptr;

    ElfW(Dyn) *dynamic_ = nullptr;  //.dynamic
    ElfW(Word) dynamic_size_ = 0;

    const char *dyn_str_ = nullptr;  //.dynstr (string-table)
    ElfW(Sym) *dyn_sym_ = nullptr;   //.dynsym (symbol-index to string-table's offset)

    ElfW(Addr) rel_plt_ = 0;  //.rel.plt or .rela.plt
    ElfW(Word) rel_plt_size_ = 0;

    ElfW(Addr) rel_dyn_ = 0;  //.rel.dyn or .rela.dyn
    ElfW(Word) rel_dyn_size_ = 0;

    // for ELF hash
    uint32_t *bucket_ = nullptr;
    uint32_t bucket_count_ = 0;
    uint32_t *chain_ = nullptr;

    // append for GNU hash
    uint32_t sym_offset_ = 0;
    ElfW(Addr) *bloom_ = nullptr;
    uint32_t bloom_size_ = 0;
    uint32_t bloom_shift_ = 0;

    bool is_use_rela_ = false;
    bool valid_ = false;

    struct Reloc {
        uint32_t sym;
        ElfW(Addr) addr;
    };
    std::vector<Reloc> plt_relocs_;
    std::vector<Reloc> dyn_relocs_;

    template <typename T>
    void ProcessReloc(ElfW(Addr) begin, ElfW(Word) size, bool is_plt);
    void DoReloc(ElfW(Addr) rel, ElfW(Word) size, bool is_plt);
    static int CmpReloc(const void* a, const void* b);
    size_t FindLowerBound(const std::vector<Reloc>& relocs, uint32_t target_sym) const;

    bool ParseHeader();
    bool ParseDynamicTable();
    void BuildRelocIndex();
    uint32_t GnuLookup(const SymName& name) const;
    uint32_t ElfLookup(const SymName& name) const;
    uint32_t LinearLookup(const SymName& name) const;
public:
    void FindPltAddr(std::string_view name, std::vector<uintptr_t> &res) const;
    Elf(uintptr_t base_addr);
    bool Valid() const { return valid_; };
};
