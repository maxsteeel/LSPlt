#include "elf_util.hpp"

#include <cstring>
#include <type_traits>
#include <vector>
#include <tuple>
#include <algorithm>

#if defined(__arm__)
#define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT  //.rel.plt
#define ELF_R_GENERIC_GLOB_DAT R_ARM_GLOB_DAT    //.rel.dyn
#define ELF_R_GENERIC_ABS R_ARM_ABS32            //.rel.dyn
#elif defined(__aarch64__)
#define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_AARCH64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_AARCH64_ABS64
#elif defined(__i386__)
#define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_386_GLOB_DAT
#define ELF_R_GENERIC_ABS R_386_32
#elif defined(__x86_64__)
#define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_X86_64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_X86_64_64
#elif defined(__riscv)
#define ELF_R_GENERIC_JUMP_SLOT R_RISCV_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_RISCV_64
#define ELF_R_GENERIC_ABS R_RISCV_64
#endif

#if defined(__LP64__)
#define ELF_R_SYM(info) ELF64_R_SYM(info)
#define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define ELF_R_SYM(info) ELF32_R_SYM(info)
#define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

namespace {
template <typename T>
inline constexpr auto OffsetOf(ElfW(Ehdr) * head, ElfW(Off) off) {
    return reinterpret_cast<std::conditional_t<std::is_pointer_v<T>, T, T *>>(
        reinterpret_cast<uintptr_t>(head) + off);
}

template <typename T>
inline constexpr auto SetByOffset(T &ptr, ElfW(Addr) base, ElfW(Addr) bias, ElfW(Addr) off) {
    if (auto val = bias + off; val > base) {
        ptr = reinterpret_cast<T>(val);
        return true;
    }
    ptr = 0;
    return false;
}

inline bool MatchSymName(const SymName& name, const char* sym_name) {
    return sym_name[0] == name.name[0] &&
           strncmp(name.name.data(), sym_name, name.name.size()) == 0 &&
           sym_name[name.name.size()] == '\0';
}

}  // namespace

Elf::Elf(uintptr_t base_addr) : base_addr_(base_addr) {
    header_ = reinterpret_cast<decltype(header_)>(base_addr);

    // check magic
    if (0 != memcmp(header_->e_ident, ELFMAG, SELFMAG)) return;

        // check class (64/32)
#if defined(__LP64__)
    if (ELFCLASS64 != header_->e_ident[EI_CLASS]) return;
#else
    if (ELFCLASS32 != header_->e_ident[EI_CLASS]) return;
#endif

    // check endian (little/big)
    if (ELFDATA2LSB != header_->e_ident[EI_DATA]) return;

    // check version
    if (EV_CURRENT != header_->e_ident[EI_VERSION]) return;

    // check type
    if (ET_EXEC != header_->e_type && ET_DYN != header_->e_type) return;

        // check machine
#if defined(__arm__)
    if (EM_ARM != header_->e_machine) return;
#elif defined(__aarch64__)
    if (EM_AARCH64 != header_->e_machine) return;
#elif defined(__i386__)
    if (EM_386 != header_->e_machine) return;
#elif defined(__x86_64__)
    if (EM_X86_64 != header_->e_machine) return;
#elif defined(__riscv)
    if (EM_RISCV != header_->e_machine) return;
#else
    return;
#endif

    // check version
    if (EV_CURRENT != header_->e_version) return;

    program_header_ = OffsetOf<decltype(program_header_)>(header_, header_->e_phoff);

    auto ph_off = reinterpret_cast<uintptr_t>(program_header_);
    for (int i = 0; i < header_->e_phnum; i++, ph_off += header_->e_phentsize) {
        auto *program_header = reinterpret_cast<ElfW(Phdr) *>(ph_off);
        if (program_header->p_type == PT_LOAD && program_header->p_offset == 0) {
            if (base_addr_ >= program_header->p_vaddr) {
                bias_addr_ = base_addr_ - program_header->p_vaddr;
            }
        } else if (program_header->p_type == PT_DYNAMIC) {
            dynamic_ = reinterpret_cast<decltype(dynamic_)>(program_header->p_vaddr);
            dynamic_size_ = program_header->p_memsz;
        }
    }
    if (!dynamic_ || !bias_addr_) return;
    dynamic_ =
        reinterpret_cast<decltype(dynamic_)>(bias_addr_ + reinterpret_cast<uintptr_t>(dynamic_));

    for (auto *dynamic = dynamic_, *dynamic_end = dynamic_ + (dynamic_size_ / sizeof(dynamic[0]));
         dynamic < dynamic_end; ++dynamic) {
        switch (dynamic->d_tag) {
        case DT_NULL:
            // the end of the dynamic-section
            dynamic = dynamic_end;
            break;
        case DT_STRTAB: {
            if (!SetByOffset(dyn_str_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_SYMTAB: {
            if (!SetByOffset(dyn_sym_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_PLTREL:
            // use rel or rela?
            is_use_rela_ = dynamic->d_un.d_val == DT_RELA;
            break;
        case DT_JMPREL: {
            if (!SetByOffset(rel_plt_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_PLTRELSZ:
            rel_plt_size_ = dynamic->d_un.d_val;
            break;
        case DT_REL:
        case DT_RELA: {
            if (!SetByOffset(rel_dyn_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_RELSZ:
        case DT_RELASZ:
            rel_dyn_size_ = dynamic->d_un.d_val;
            break;
        case DT_HASH: {
            // ignore DT_HASH when ELF contains DT_GNU_HASH hash table
            if (bloom_) continue;
            auto *raw = reinterpret_cast<ElfW(Word) *>(bias_addr_ + dynamic->d_un.d_ptr);
            bucket_count_ = raw[0];
            bucket_ = raw + 2;
            chain_ = bucket_ + bucket_count_;
            break;
        }
        case DT_GNU_HASH: {
            auto *raw = reinterpret_cast<ElfW(Word) *>(bias_addr_ + dynamic->d_un.d_ptr);
            bucket_count_ = raw[0];
            sym_offset_ = raw[1];
            bloom_size_ = raw[2];
            bloom_shift_ = raw[3];
            bloom_ = reinterpret_cast<decltype(bloom_)>(raw + 4);
            bucket_ = reinterpret_cast<decltype(bucket_)>(bloom_ + bloom_size_);
            chain_ = bucket_ + bucket_count_ - sym_offset_;
            break;
        }
        default:
            break;
        }
    }

    valid_ = true;
    BuildRelocIndex();
}

template <typename T>
void Elf::ProcessReloc(ElfW(Addr) begin, ElfW(Word) size, bool is_plt) {
    const auto *rel_end = reinterpret_cast<const T *>(begin + size);
    for (const auto *rel = reinterpret_cast<const T *>(begin); rel < rel_end; ++rel) {
        auto r_info = rel->r_info;
        auto r_offset = rel->r_offset;
        auto r_sym = ELF_R_SYM(r_info);
        auto r_type = ELF_R_TYPE(r_info);

        if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
        if (!is_plt && r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT) continue;

        auto addr = bias_addr_ + r_offset;
        if (addr > base_addr_) {
            if (is_plt) {
                plt_relocs_.push_back({(uint32_t)r_sym, addr});
            } else {
                dyn_relocs_.push_back({(uint32_t)r_sym, addr});
            }
        }
    }
}

void Elf::DoReloc(ElfW(Addr) rel, ElfW(Word) size, bool is_plt) {
    if (!rel) return;
    if (is_use_rela_) {
        ProcessReloc<ElfW(Rela)>(rel, size, is_plt);
    } else {
        ProcessReloc<ElfW(Rel)>(rel, size, is_plt);
    }
}

int Elf::CmpReloc(const void* a, const void* b) {
    auto sym_a = static_cast<const Reloc*>(a)->sym;
    auto sym_b = static_cast<const Reloc*>(b)->sym;
    return (sym_a > sym_b) - (sym_a < sym_b);
}

void Elf::BuildRelocIndex() {
    size_t rel_size = is_use_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
    if (rel_size > 0) {
        plt_relocs_.reserve(rel_plt_size_ / rel_size);
        dyn_relocs_.reserve(rel_dyn_size_ / rel_size);
    }

    DoReloc(rel_plt_, rel_plt_size_, true);
    DoReloc(rel_dyn_, rel_dyn_size_, false);

    if (!plt_relocs_.empty()) {
        qsort(plt_relocs_.data(), plt_relocs_.size(), sizeof(Reloc), CmpReloc);
    }
    if (!dyn_relocs_.empty()) {
        qsort(dyn_relocs_.data(), dyn_relocs_.size(), sizeof(Reloc), CmpReloc);
    }
}

uint32_t Elf::GnuLookup(const SymName& name) const {
    static constexpr auto kBloomMaskBits = sizeof(ElfW(Addr)) * 8;

    if (!bucket_ || !bloom_) return 0;

    uint32_t hash = name.gnu_hash;
    auto bloom_word = bloom_[(hash / kBloomMaskBits) % bloom_size_];
    uintptr_t mask = 0 | uintptr_t{1} << (hash % kBloomMaskBits) |
                     uintptr_t{1} << ((hash >> bloom_shift_) % kBloomMaskBits);
    if ((mask & bloom_word) == mask) {
        auto idx = bucket_[hash % bucket_count_];
        if (idx >= sym_offset_) {
            if (name.name.empty()) return 0;
            const char *strings = dyn_str_;
            do {
                auto *sym = dyn_sym_ + idx;
                const char *sym_name = strings + sym->st_name;
                if (((chain_[idx] ^ hash) >> 1) == 0 && MatchSymName(name, sym_name)) {
                    return idx;
                }
            } while ((chain_[idx++] & 1) == 0);
        }
    }
    return 0;
}

uint32_t Elf::ElfLookup(const SymName& name) const {
    if (!bucket_ || bloom_) return 0;

    uint32_t hash = name.elf_hash;

    if (name.name.empty()) return 0;

    const char *strings = dyn_str_;

    for (auto idx = bucket_[hash % bucket_count_]; idx != 0; idx = chain_[idx]) {
        auto *sym = dyn_sym_ + idx;
        const char *sym_name = strings + sym->st_name;
        if (MatchSymName(name, sym_name)) {
            return idx;
        }
    }
    return 0;
}

uint32_t Elf::LinearLookup(const SymName& name) const {
    if (!dyn_sym_ || !sym_offset_ || name.name.empty()) return 0;
    for (uint32_t idx = 0; idx < sym_offset_; idx++) {
        auto *sym = dyn_sym_ + idx;
        const char *sym_name = dyn_str_ + sym->st_name;
        if (MatchSymName(name, sym_name)) {
            return idx;
        }
    }
    return 0;
}

size_t Elf::FindLowerBound(const std::vector<Reloc>& relocs, uint32_t target_sym) const {
    size_t low = 0, high = relocs.size();
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (relocs[mid].sym < target_sym) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    return low;
}

void Elf::FindPltAddr(std::string_view name, std::vector<uintptr_t> &res) const {
    res.clear();

    SymName sym_name(name);
    uint32_t idx = GnuLookup(sym_name);
    if (!idx) idx = ElfLookup(sym_name);
    if (!idx) idx = LinearLookup(sym_name);
    if (!idx) return;

    size_t plt_idx = FindLowerBound(plt_relocs_, idx);
    while (plt_idx < plt_relocs_.size() && plt_relocs_[plt_idx].sym == idx) {
        res.push_back(plt_relocs_[plt_idx].addr);
        break; // original logic breaks on first is_plt
    }

    size_t dyn_idx = FindLowerBound(dyn_relocs_, idx);
    while (dyn_idx < dyn_relocs_.size() && dyn_relocs_[dyn_idx].sym == idx) {
        res.push_back(dyn_relocs_[dyn_idx].addr);
        ++dyn_idx;
    }
}
