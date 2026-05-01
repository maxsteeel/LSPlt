#pragma once
#include <link.h>
#include <stdint.h>
#include <stdlib.h> // malloc, free
#include "include/lsplt.hpp"

struct SymName {
    const char* name;
    explicit SymName(const char* n) : name(n) {}
};

class Elf {
    struct Reloc { uint32_t sym; ElfW(Addr) addr; };

    struct RelocList {
        Reloc* data = nullptr;
        size_t size = 0;
        size_t capacity = 0;
        ~RelocList() { if (data) free(data); }
        RelocList() = default;
        RelocList(const RelocList&) = delete;
        RelocList& operator=(const RelocList&) = delete;
        void reserve(size_t n) {
            if (n > capacity) {
                void* nd = memalloc(data, size, n, sizeof(Reloc));
                if (nd) { data = static_cast<Reloc*>(nd); capacity = n; }
            }
        }
        void push_back(Reloc r) {
            if (size >= capacity) {
                size_t n = capacity == 0 ? 64 : capacity * 2;
                void* nd = memalloc(data, size, n, sizeof(Reloc));
                if (nd) { data = static_cast<Reloc*>(nd); capacity = n; }
                else return;
            }
            data[size++] = r;
        }
    };

public:
    struct AddrList {
        uintptr_t* data = nullptr;
        size_t size = 0;
        size_t capacity = 0;
        ~AddrList() { if (data) free(data); }
        AddrList() = default;
        AddrList(const AddrList&) = delete;
        AddrList& operator=(const AddrList&) = delete;
        void push_back(uintptr_t addr) {
            if (size >= capacity) {
                size_t n = capacity == 0 ? 4 : capacity * 2;
                void* nd = memalloc(data, size, n, sizeof(uintptr_t));
                if (nd) { data = static_cast<uintptr_t*>(nd); capacity = n; }
                else return;
            }
            data[size++] = addr;
        }
        void clear() { size = 0; }
        bool empty() const { return size == 0; }
    };

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
    RelocList plt_relocs_, dyn_relocs_;

    void ProcessReloc(ElfW(Addr) begin, ElfW(Word) size, bool is_plt);
    void BuildRelocIndex();
    bool ParseHeader();
    bool ParseDynamicTable();

public:
    explicit Elf(uintptr_t base_addr);
    void FindPltAddr(const char* name, AddrList& res) const;
    int GetExactProtection(uintptr_t addr) const;
    bool Valid() const { return valid_; }
};
