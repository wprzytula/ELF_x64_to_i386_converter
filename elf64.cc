#include "converter.h"
#include <cstring>

namespace converter::elf64 {
    Header64::Header64(std::ifstream &elf_stream) : Elf64_Ehdr{} {
        read_to_field(elf_stream, e_ident);
        if (strncmp(reinterpret_cast<char const *>(e_ident), ELFMAG, SELFMAG) != 0 ||
            e_ident[EI_CLASS] != ELFCLASS64 ||
            e_ident[EI_OSABI] != ELFOSABI_SYSV) {
            throw UnsupportedFileContent{"Can only convert x64 object files conforming to System V ABI.\n"};
        }

        read_to_field(elf_stream, e_type);
        if (e_type != ET_REL) {
            throw UnsupportedFileContent{"Can only convert ET_REL executable files.\n"};
        }

        read_to_field(elf_stream, e_machine);
        if (e_machine != EM_X86_64) {
            throw UnsupportedFileContent{"Can only convert x86-64 arch executable files.\n"};
        }

        read_to_field(elf_stream, e_version);
        read_to_field(elf_stream, e_entry);
        read_to_field(elf_stream, e_phoff);
        read_to_field(elf_stream, e_shoff);
        read_to_field(elf_stream, e_flags);
        read_to_field(elf_stream, e_ehsize);
        if (e_ehsize != sizeof(Elf64_Ehdr)) {
            throw UnsupportedFileContent{"e_ehsize is different than expected header size."};
        }
        read_to_field(elf_stream, e_phentsize);
        read_to_field(elf_stream, e_phnum);
        if (e_phnum > 0 && e_phentsize != sizeof(Elf64_Phdr)) {
            throw UnsupportedFileContent{"e_phnum is non-0, but e_phentsize is different than expected size."};
        } else if (e_phnum == 0 && e_phentsize != 0) {
            throw UnsupportedFileContent{"e_phnum is 0, but e_phentsize is different than 0."};
        }
        read_to_field(elf_stream, e_shentsize);
        read_to_field(elf_stream, e_shnum);
        if (e_shnum > 0 && e_shentsize != sizeof(Elf64_Shdr)) {
            throw UnsupportedFileContent{"e_shnum is non-0, but e_shentsize is different than expected size."};
        } else if (e_shnum == 0 && e_shentsize != 0) {
            throw UnsupportedFileContent{"e_shnum is 0, but e_shentsize is different than 0."};
        }
        read_to_field(elf_stream, e_shstrndx);
        if (e_shstrndx >= e_shnum) {
            throw UnsupportedFileContent{"e_shstrndx is bigger than sections array size."};
        }
    }

    Symbol64::Symbol64(std::ifstream &elf_stream) : Elf64_Sym{} {
        read_to_field(elf_stream, st_name);
        read_to_field(elf_stream, st_info);
        read_to_field(elf_stream, st_other);
        read_to_field(elf_stream, st_shndx);
        read_to_field(elf_stream, st_value);
        read_to_field(elf_stream, st_size);
        special_section = st_shndx >= 0xff00;
    }

    Rela64::Rela64(std::ifstream &elf_stream) : Elf64_Rela{} {
        static_assert(sizeof(*this) == sizeof(Elf64_Rela));
        read_to_field(elf_stream, *this);
    }

    Section64::Section64(std::ifstream &elf_stream) {
        read_to_field(elf_stream, header);
    }

    Section64WithGenericData::Section64WithGenericData(Section64 section64, std::ifstream& elf_stream)
            : Section64{std::move(section64)}, data{std::make_unique<char[]>(header.sh_size)} {
        elf_stream.seekg(static_cast<ssize_t>(header.sh_offset));
        elf_stream.read(data.get(), static_cast<ssize_t>(header.sh_size));
    }

    Section64Rela::Section64Rela(Section64 section64, std::ifstream& elf_stream)  : Section64(std::move(section64)) {
        elf_stream.seekg(static_cast<ssize_t>(header.sh_offset));
        for (size_t i = 0; i < header.sh_size; i += sizeof(Elf64_Rela)) {
            relocations.emplace_back(elf_stream);
        }
    }

    Section64Symtab::Section64Symtab(Section64 section64, std::ifstream& elf_stream) : Section64(std::move(section64)) {
        elf_stream.seekg(static_cast<ssize_t>(header.sh_offset));
        for (size_t i = 0; i < header.sh_size; i += sizeof(Elf64_Sym)) {
            symbols.emplace_back(elf_stream);
            auto const& symbol = *std::prev(std::end(symbols));
        }
    }

    std::unique_ptr<Section64> Section64::parse_section(std::ifstream& elf_stream, Elf64_Ehdr const& elf_header) {
        Section64 header_phase{elf_stream};

        if (header_phase.header.sh_size > 0) {
            char const* type = "other";
            switch (header_phase.header.sh_type) {
                case SHT_NULL:
                    type = "NULL";
                    break;
                case SHT_PROGBITS:
                    type = "SHT_PROGBITS";
                    break;
                case SHT_NOBITS:
                    type = "SHT_NOBITS";
                    break;
                case SHT_SYMTAB:
                    type = "SHT_SYMTAB";
                    return std::make_unique<Section64Symtab>(std::move(header_phase), elf_stream);
                case SHT_STRTAB:
                    type = "SHT_STRTAB";
                    return std::make_unique<Section64Strtab>(Section64WithGenericData{std::move(header_phase), elf_stream});
                case SHT_DYNAMIC:
                    type = "SHT_DYNAMIC";
                    break;
                case SHT_RELA:
                    type = "SHT_RELA";
                    return std::make_unique<Section64Rela>(Section64Rela{std::move(header_phase), elf_stream});
                case SHT_REL:
                    type = "SHT_REL";
                    break;
                default:
                    break;
            }

            return std::make_unique<Section64WithGenericData>(Section64WithGenericData{std::move(header_phase), elf_stream});
        } else {
            return std::make_unique<Section64WithoutData>(Section64WithoutData{std::move(header_phase)});
        }
    }

    Elf64::Elf64(std::ifstream &elf_stream) : header{elf_stream} {
        for (size_t i = 0; i < header.e_shnum; ++i) {
            elf_stream.seekg(static_cast<ssize_t>(header.e_shoff + i * header.e_shentsize));
            sections.push_back(Section64::parse_section(elf_stream, header));
        }
    }
}