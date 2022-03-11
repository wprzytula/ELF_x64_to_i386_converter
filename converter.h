#ifndef ZAD1_ELF_CONVERTER_CONVERTER_H
#define ZAD1_ELF_CONVERTER_CONVERTER_H

#include <elf.h>
#include <fstream>
#include <memory>
#include <vector>

namespace converter {
    namespace elf64 {
        struct Header64;
        struct Rela64;
        struct Symbol64;
        struct Section64;
        struct Section64WithoutData;
        struct Section64WithGenericData;
        struct Section64Strtab;
        struct Section64Symtab;
    }

    namespace elf32 {
        struct Header32 : Elf32_Ehdr {
            explicit Header32(elf64::Header64 const& header64);
        };


        struct Rel32 : Elf32_Rel {
            explicit Rel32(elf64::Rela64 const& rela64);
        };

        struct Symbol32 : Elf32_Sym {
            explicit Symbol32(elf64::Symbol64 const& symbol64);
        };

        struct Section32 {
            Elf32_Shdr header{};

            explicit Section32(elf64::Section64 const &section64, Elf32_Ehdr const &elf_header);
        };
    }

    namespace elf64 {
        struct Header64 : Elf64_Ehdr {
            explicit Header64(std::ifstream &elf_stream);
        };

        struct Symbol64 : Elf64_Sym {
            explicit Symbol64(std::ifstream &elf_stream);
        };

        struct Rela64 : Elf64_Rela {
            explicit Rela64(std::ifstream &elf_stream);
        };


        struct Section64 {
//            Elf64_Ehdr const& elf_header{};
            Elf64_Shdr header{};

            explicit Section64(std::ifstream &elf_stream, Elf64_Ehdr const& elf_header);

            Section64(Section64&& section) = default;
            virtual ~Section64() = default;

            [[nodiscard]] char const* name(Section64Strtab const &str_table) const;
            static std::unique_ptr<Section64> parse_section(std::ifstream& elf_stream, Elf64_Ehdr const& elf_header);

            virtual std::unique_ptr<elf32::Section32> to_32(Elf32_Ehdr const& elf32_header) {
                return std::make_unique<elf32::Section32>(elf32::Section32{*this, elf32_header});
            };
        };

        struct Section64WithoutData : public Section64 {
            explicit Section64WithoutData(Section64 section64) : Section64(std::move(section64)) {}
            ~Section64WithoutData() override = default;
            Section64WithoutData(Section64WithoutData&&) = default;
        };

        struct Section64WithGenericData : public Section64 {
            explicit Section64WithGenericData(Section64 section64, std::ifstream& elf_stream)
                    : Section64{std::move(section64)}, data{std::make_unique<char[]>(header.sh_size)} {
                elf_stream.seekg(static_cast<ssize_t>(header.sh_offset));
                elf_stream.read(data.get(), static_cast<ssize_t>(header.sh_size));
            }

            ~Section64WithGenericData() override = default;
            Section64WithGenericData(Section64WithGenericData&&) = default;

            std::unique_ptr<char[]> data;

        };

        struct Section64Rela : public Section64 {

        };

        struct Section64Strtab final : public Section64WithGenericData {
            explicit Section64Strtab(Section64WithGenericData section64_with_data) : Section64WithGenericData(std::move(section64_with_data)) {}
            ~Section64Strtab() final = default;
            Section64Strtab(Section64Strtab&&) = default;

            [[nodiscard]] char const* name_of(Elf64_Word i) const {
                return &data.get()[i];
            }
        };

        struct Section64Symtab final : public Section64 {
            std::vector<Symbol64> symbols;

            explicit Section64Symtab(Section64 section64, std::ifstream& elf_stream);
            ~Section64Symtab() final = default;
            Section64Symtab(Section64Symtab&&) = default;
        };

        struct Elf64 {
            Header64 header;
            std::vector<std::unique_ptr<Section64>> sections;

            explicit Elf64(std::ifstream &elf_stream);
        };
    }
}

#endif //ZAD1_ELF_CONVERTER_CONVERTER_H
