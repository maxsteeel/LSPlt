#pragma once
#include <link.h>
#include <stdint.h>
#include <stdlib.h> // malloc, free
#include "include/lsplt.hpp"

class Elf {
public:
    using AddrList = lsplt::FastList<uintptr_t>;

private:
    ElfW(Addr) base_addr_ = 0, bias_addr_ = 0;
    ElfW(Ehdr) *header_ = nullptr;
    ElfW(Phdr) *program_header_ = nullptr;
    uint16_t phnum_ = 0;
    
    ElfW(Dyn)  *dynamic_ = nullptr;
    ElfW(Sym)  *dyn_sym_ = nullptr;
    const char *dyn_str_ = nullptr;
    
    ElfW(Addr) rel_plt_ = 0, rel_dyn_ = 0;
    ElfW(Word) rel_plt_size_ = 0, rel_dyn_size_ = 0, dynamic_size_ = 0;

    bool is_use_rela_ = false, valid_ = false;

    bool ParseHeader();
    bool ParseDynamicTable();

public:
    explicit Elf(uintptr_t base_addr);
    void FindPltAddr(const char* name, AddrList& res) const;
    int GetExactProtection(uintptr_t addr) const;
    bool Valid() const { return valid_; }
};
