#include "elf_util.hpp"

#if defined(__aarch64__)
#define R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GLOB_DAT  R_AARCH64_GLOB_DAT
#define R_ABS       R_AARCH64_ABS64
#elif defined(__arm__)
#define R_JUMP_SLOT R_ARM_JUMP_SLOT
#define R_GLOB_DAT  R_ARM_GLOB_DAT
#define R_ABS       R_ARM_ABS32
#elif defined(__i386__)
#define R_JUMP_SLOT R_386_JMP_SLOT
#define R_GLOB_DAT  R_386_GLOB_DAT
#define R_ABS       R_386_32
#elif defined(__x86_64__)
#define R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define R_GLOB_DAT  R_X86_64_GLOB_DAT
#define R_ABS       R_X86_64_64
#elif defined(__riscv)
#define R_JUMP_SLOT R_RISCV_JUMP_SLOT
#define R_GLOB_DAT  R_RISCV_64
#define R_ABS       R_RISCV_64
#endif

#if defined(__LP64__)
#define ELF_R_SYM(i)  ELF64_R_SYM(i)
#define ELF_R_TYPE(i) ELF64_R_TYPE(i)
#else
#define ELF_R_SYM(i)  ELF32_R_SYM(i)
#define ELF_R_TYPE(i) ELF32_R_TYPE(i)
#endif

namespace {
    inline __attribute__((always_inline)) bool MatchSym(const SymName& n, const char* s) {
        return s[0] == n.name[0] && __builtin_strcmp(n.name, s) == 0;
    }
}

__attribute__((noinline))
Elf::Elf(uintptr_t base_addr) : base_addr_(base_addr) {
    header_ = reinterpret_cast<ElfW(Ehdr)*>(base_addr);
    if (ParseHeader() && ParseDynamicTable()) {
        valid_ = true;
        BuildRelocIndex();
    }
}

bool Elf::ParseHeader() {
    if (*reinterpret_cast<uint32_t*>(header_->e_ident) != *reinterpret_cast<const uint32_t*>(ELFMAG)) return false;
    if (header_->e_type != ET_EXEC && header_->e_type != ET_DYN) return false;
    
    uint16_t m = header_->e_machine;
#if defined(__aarch64__)
    return m == EM_AARCH64;
#elif defined(__arm__)
    return m == EM_ARM;
#elif defined(__i386__)
    return m == EM_386;
#elif defined(__x86_64__)
    return m == EM_X86_64;
#elif defined(__riscv)
    return m == EM_RISCV;
#else
    return false;
#endif
}

__attribute__((noinline))
bool Elf::ParseDynamicTable() {
    program_header_ = reinterpret_cast<ElfW(Phdr)*>(base_addr_ + header_->e_phoff);
    phnum_ = header_->e_phnum;
    
    for (int i = 0; i < phnum_; i++) {
        if (program_header_[i].p_type == PT_LOAD && program_header_[i].p_offset == 0) {
            bias_addr_ = base_addr_ - program_header_[i].p_vaddr;
        } else if (program_header_[i].p_type == PT_DYNAMIC) { 
            dynamic_ = reinterpret_cast<ElfW(Dyn)*>(program_header_[i].p_vaddr); 
            dynamic_size_ = program_header_[i].p_memsz; 
        }
    }
    if (!dynamic_ || !bias_addr_) return false;
    dynamic_ = reinterpret_cast<ElfW(Dyn)*>(bias_addr_ + reinterpret_cast<uintptr_t>(dynamic_));

    for (auto* d = dynamic_; d->d_tag != DT_NULL; ++d) {
        uintptr_t val = bias_addr_ + d->d_un.d_ptr;
        switch (d->d_tag) {
            case DT_STRTAB: dyn_str_ = reinterpret_cast<const char*>(val); break;
            case DT_SYMTAB: dyn_sym_ = reinterpret_cast<ElfW(Sym)*>(val); break;
            case DT_PLTREL: is_use_rela_ = (d->d_un.d_val == DT_RELA); break;
            case DT_JMPREL: rel_plt_ = val; break;
            case DT_PLTRELSZ: rel_plt_size_ = d->d_un.d_val; break;
            case DT_REL: case DT_RELA: rel_dyn_ = val; break;
            case DT_RELSZ: case DT_RELASZ: rel_dyn_size_ = d->d_un.d_val; break;
            case DT_HASH: sysv_hash_ = reinterpret_cast<uint32_t*>(val); break;
            case DT_GNU_HASH: { 
                auto* r = reinterpret_cast<ElfW(Word)*>(val); 
                bucket_count_ = r[0]; sym_offset_ = r[1]; bloom_size_ = r[2]; bloom_shift_ = r[3];
                bloom_ = reinterpret_cast<ElfW(Addr)*>(r + 4); 
                bucket_ = reinterpret_cast<uint32_t*>(bloom_ + bloom_size_); 
                chain_ = bucket_ + bucket_count_ - sym_offset_; 
            } break;
        }
    }
    return dyn_str_ && dyn_sym_;
}

__attribute__((noinline, cold))
void Elf::ProcessReloc(ElfW(Addr) begin, ElfW(Word) size, bool is_plt) {
    if (!begin || !size) return;
    size_t stride = is_use_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
    uintptr_t end = begin + size;
    
    for (uintptr_t ptr = begin; ptr < end; ptr += stride) {
        auto* r = reinterpret_cast<const ElfW(Rel)*>(ptr);
        auto type = ELF_R_TYPE(r->r_info);
        if (is_plt ? (type == R_JUMP_SLOT) : (type == R_ABS || type == R_GLOB_DAT)) {
            ElfW(Addr) addr = bias_addr_ + r->r_offset;
            if (addr > base_addr_) (is_plt ? plt_relocs_ : dyn_relocs_).push_back({(uint32_t)ELF_R_SYM(r->r_info), addr});
        }
    }
}

__attribute__((noinline))
void Elf::BuildRelocIndex() {
    size_t r_sz = is_use_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
    plt_relocs_.reserve(rel_plt_size_ / r_sz); 
    dyn_relocs_.reserve(rel_dyn_size_ / r_sz);
    ProcessReloc(rel_plt_, rel_plt_size_, true); 
    ProcessReloc(rel_dyn_, rel_dyn_size_, false);
}

__attribute__((noinline))
uint32_t Elf::GnuLookup(const SymName& name) const {
    if (!bloom_) return 0;
    constexpr uint32_t ADDR_BITS = sizeof(ElfW(Addr)) * 8;
    constexpr uint32_t ADDR_MASK = ADDR_BITS - 1;

    uint32_t word_num = (name.gnu_hash / ADDR_BITS) & (bloom_size_ - 1);
    uint32_t h2 = name.gnu_hash >> bloom_shift_;

    ElfW(Addr) mask = (((ElfW(Addr))1) << (name.gnu_hash & ADDR_MASK)) |
                      (((ElfW(Addr))1) << (h2 & ADDR_MASK));

    // Fast-Reject via Bloom Filter
    if ((bloom_[word_num] & mask) != mask) return 0;

    for (uint32_t i = bucket_[name.gnu_hash % bucket_count_]; i >= sym_offset_ && i != 0; ++i) {
        if (((chain_[i] ^ name.gnu_hash) >> 1) == 0 && MatchSym(name, dyn_str_ + dyn_sym_[i].st_name)) return i;
        if (chain_[i] & 1) break;
    }
    return 0;
}

__attribute__((noinline))
uint32_t Elf::SysVLookup(const SymName& name) const {
    if (!sysv_hash_) return 0;
    uint32_t nbucket = sysv_hash_[0];
    uint32_t* bucket = sysv_hash_ + 2;
    uint32_t* chain = bucket + nbucket;

    for (uint32_t i = bucket[name.sysv_hash % nbucket]; i != 0; i = chain[i]) {
        if (MatchSym(name, dyn_str_ + dyn_sym_[i].st_name)) return i;
    }
    return 0;
}

__attribute__((noinline))
void Elf::FindPltAddr(const char* name, AddrList& res) const {
    res.clear(); 
    SymName sn(name);
    
    // Priority: DT_GNU_HASH -> DT_HASH
    uint32_t idx = GnuLookup(sn);
    if (!idx) idx = SysVLookup(sn);
    if (!idx) return;

    for (size_t i = 0; i < plt_relocs_.size; i++) {
        if (plt_relocs_.data[i].sym == idx) {
            res.push_back(plt_relocs_.data[i].addr);
            break;
        }
    }
    for (size_t i = 0; i < dyn_relocs_.size; i++) {
        if (dyn_relocs_.data[i].sym == idx) {
            res.push_back(dyn_relocs_.data[i].addr);
        }
    }
}

__attribute__((noinline))
int Elf::GetExactProtection(uintptr_t addr) const {
    int prot = 0;
    bool found = false;
    
    // 1. Resolve base permissions from PT_LOAD segments
    for (size_t i = 0; i < phnum_; i++) {
        const auto* ph = &program_header_[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) continue;
        
        uintptr_t seg_start = bias_addr_ + ph->p_vaddr;
        uintptr_t seg_end = seg_start + ph->p_memsz;
        if (addr >= seg_start && addr < seg_end) {
            if (ph->p_flags & PF_R) prot |= PROT_READ;
            if (ph->p_flags & PF_W) prot |= PROT_WRITE;
            if (ph->p_flags & PF_X) prot |= PROT_EXEC;
            found = true;
            break;
        }
    }
    if (!found || prot == 0) return -1;

    // 2. Apply security hardening: PT_GNU_RELRO
    for (size_t i = 0; i < phnum_; i++) {
        const auto* ph = &program_header_[i];
        if (ph->p_type != 0x6474e552 /* PT_GNU_RELRO */ || ph->p_memsz == 0) continue;
        
        uintptr_t relro_start = bias_addr_ + ph->p_vaddr;
        uintptr_t relro_end = relro_start + ph->p_memsz;
        if (addr >= relro_start && addr < relro_end) {
            prot &= ~PROT_WRITE;
            break;
        }
    }
    return prot;
}
