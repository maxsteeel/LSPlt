#pragma once
#include <link.h>
#include <stdint.h>
#include <stdlib.h> // malloc, free, realloc

struct SymName {
    const char* name;
    size_t len;
    uint32_t gnu_hash = 5381;

    explicit SymName(const char* n) : name(n) {
        len = 0;
        // Calcula el hash y la longitud en un solo recorrido de caché L1
        for (const char* ptr = n; *ptr != '\0'; ++ptr) {
            gnu_hash = (gnu_hash << 5) + gnu_hash + *ptr;
            len++;
        }
    }

    uint32_t GetElfHash() const {
        uint32_t elf_hash = 0;
        for (size_t i = 0; i < len; ++i) {
            elf_hash = (elf_hash << 4) + name[i];
            uint32_t tmp = elf_hash & 0xf0000000;
            if (tmp) elf_hash ^= tmp | (tmp >> 24);
        }
        return elf_hash;
    }
};

class Elf {
    struct Reloc { uint32_t sym; ElfW(Addr) addr; };

    struct RelocList {
        Reloc* data = nullptr;
        size_t size = 0;
        size_t capacity = 0;
        ~RelocList() { free(data); }
        void reserve(size_t n) {
            if (n > capacity) {
                capacity = n;
                data = (Reloc*)realloc(data, capacity * sizeof(Reloc));
            }
        }
        void push_back(Reloc r) {
            if (size >= capacity) {
                capacity = capacity == 0 ? 64 : capacity * 2;
                data = (Reloc*)realloc(data, capacity * sizeof(Reloc));
            }
            data[size++] = r;
        }
    };

public:
    struct AddrList {
        uintptr_t* data = nullptr;
        size_t size = 0;
        size_t capacity = 0;
        ~AddrList() { free(data); }
        void push_back(uintptr_t addr) {
            if (size >= capacity) {
                capacity = capacity == 0 ? 4 : capacity * 2;
                data = (uintptr_t*)realloc(data, capacity * sizeof(uintptr_t));
            }
            data[size++] = addr;
        }
        void clear() { size = 0; }
    };

private:
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
    RelocList plt_relocs_, dyn_relocs_;

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
    void FindPltAddr(const char* name, AddrList& res) const;
    bool Valid() const { return valid_; }
};

template<class It, class Compare>
inline void sort(It first, It last, Compare comp) {
    size_t n = last - first;
    if (n <= 1) return;
    
    if (n < 32) {
        for (size_t i = 1; i < n; i += 1) {
            auto temp = *(first + i);
            size_t j;
            for (j = i; j > 0 && comp(temp, *(first + (j - 1))); j -= 1) {
                *(first + j) = *(first + (j - 1));
            }
            *(first + j) = temp;
        }
        return;
    }
    
    size_t gap = 1;
    while (gap < n / 3) gap = 3 * gap + 1;
    
    for (; gap > 0; gap /= 3) {
        for (size_t i = gap; i < n; i += 1) {
            auto temp = *(first + i);
            size_t j;
            for (j = i; j >= gap && comp(temp, *(first + (j - gap))); j -= gap) {
                *(first + j) = *(first + (j - gap));
            }
            *(first + j) = temp;
        }
    }
}
