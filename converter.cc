#include <elf.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include <optional>
#include <cstring>
#include <vector>
#include <memory>
#include <cassert>

constexpr char const* elf_file_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_x64.o";
constexpr char const* elf_copy_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_i386_copy.o";

class NonsupportedFileContent : public std::invalid_argument {
public:
    explicit NonsupportedFileContent(char const* what) : std::invalid_argument(what) {}
};

namespace converter {

    namespace elf64 {
#define read_to_field(elf_stream, field) elf_stream.read(reinterpret_cast<char*>(&field), sizeof(field))

        struct Header64 : Elf64_Ehdr {
            explicit Header64(std::ifstream &elf_stream) : Elf64_Ehdr{} {
                read_to_field(elf_stream, e_ident);
                if (strncmp(reinterpret_cast<char const *>(e_ident), ELFMAG, SELFMAG) != 0 ||
                    e_ident[EI_CLASS] != ELFCLASS64 ||
                    e_ident[EI_OSABI] != ELFOSABI_SYSV) {
                    throw NonsupportedFileContent{"Can only convert x64 object files conforming to System V ABI.\n"};
                }

                read_to_field(elf_stream, e_type);
                if (e_type != ET_REL) {
                    throw NonsupportedFileContent{"Can only convert ET_REL executable files.\n"};
                }

                read_to_field(elf_stream, e_machine);
                if (e_machine != EM_X86_64) {
                    throw NonsupportedFileContent{"Can only convert x86-64 arch executable files.\n"};
                }

                read_to_field(elf_stream, e_version);
                read_to_field(elf_stream, e_entry);
                read_to_field(elf_stream, e_phoff);
                read_to_field(elf_stream, e_shoff);
                read_to_field(elf_stream, e_flags);
                read_to_field(elf_stream, e_ehsize);
                if (e_ehsize != sizeof(Elf64_Ehdr)) {
                    throw NonsupportedFileContent{"e_ehsize is different than expected header size."};
                }
                read_to_field(elf_stream, e_phentsize);
                read_to_field(elf_stream, e_phnum);
                if (e_phnum > 0 && e_phentsize != sizeof(Elf64_Phdr)) {
                    throw NonsupportedFileContent{"e_phnum is non-0, but e_phentsize is different than expected size."};
                } else if (e_phnum == 0 && e_phentsize != 0) {
                    throw NonsupportedFileContent{"e_phnum is 0, but e_phentsize is different than 0."};
                }
                read_to_field(elf_stream, e_shentsize);
                read_to_field(elf_stream, e_shnum);
                if (e_shnum > 0 && e_shentsize != sizeof(Elf64_Shdr)) {
                    throw NonsupportedFileContent{"e_shnum is non-0, but e_shentsize is different than expected size."};
                } else if (e_shnum == 0 && e_shentsize != 0) {
                    throw NonsupportedFileContent{"e_shnum is 0, but e_shentsize is different than 0."};
                }
                read_to_field(elf_stream, e_shstrndx);
                if (e_shstrndx >= e_shnum) {
                    throw NonsupportedFileContent{"e_shstrndx is bigger than sections array size."};
                }
            }
        };

        struct Section64 {
            Elf64_Shdr header{};
            std::optional<std::unique_ptr<char[]>> data;

            explicit Section64(std::ifstream &elf_stream, Elf64_Ehdr const &elf_header) {
                static int i = 0;
                std::cout << "Extracting Section no " << i++ << " from start_idx " << elf_stream.tellg() << '\n';

                read_to_field(elf_stream, header.sh_name);
                read_to_field(elf_stream, header.sh_type);
                read_to_field(elf_stream, header.sh_flags);
                read_to_field(elf_stream, header.sh_addr);
                read_to_field(elf_stream, header.sh_offset);
                read_to_field(elf_stream, header.sh_size);
                read_to_field(elf_stream, header.sh_info);
                read_to_field(elf_stream, header.sh_addralign);
                read_to_field(elf_stream, header.sh_entsize);

                char const *type = "other";
                switch (header.sh_type) {
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
                        break;
                    case SHT_STRTAB:
                        type = "SHT_STRTAB";
                        break;
                    case SHT_RELA:
                        type = "SHT_RELA";
                        break;
                    case SHT_DYNAMIC:
                        type = "SHT_DYNAMIC";
                        break;
                    case SHT_REL:
                        type = "SHT_REL";
                        break;
                    default:
                        break;
                }
                std::cout << "Section type: " << type << '\n';

                if (header.sh_size) {
                    std::cout << "Data found in section, at " << header.sh_offset << '\n';
                    data = std::make_optional(std::make_unique<char[]>(header.sh_size));
                    elf_stream.seekg(static_cast<ssize_t>(header.sh_offset));
                    elf_stream.read(data.value().get(), static_cast<ssize_t>(header.sh_size));
                }
            }

            [[nodiscard]] char const *name(Section64 const &str_table) const {
                return &str_table.data.value().get()[header.sh_name];
            }
        };

        struct Symbol64 : Elf64_Sym {
            explicit Symbol64(std::ifstream &elf_stream) : Elf64_Sym{} {
                read_to_field(elf_stream, st_name);
                read_to_field(elf_stream, st_info);
                read_to_field(elf_stream, st_other);
                read_to_field(elf_stream, st_shndx);
                read_to_field(elf_stream, st_value);
                read_to_field(elf_stream, st_size);

                // TODO: should we consider SYMINFO additional table?
            }
        };

        struct Rela64 : Elf64_Rela {
            explicit Rela64(std::ifstream &elf_stream) : Elf64_Rela{} {
                read_to_field(elf_stream, r_offset);
                read_to_field(elf_stream, r_info);
                read_to_field(elf_stream, r_addend);
            }
        };

        struct Elf64 {
            Header64 header;
            std::vector<Section64> sections;

            explicit Elf64(std::ifstream &elf_stream) : header{elf_stream} {

                for (size_t i = 0; i < header.e_shnum; ++i) {
                    elf_stream.seekg(static_cast<ssize_t>(header.e_shoff + i * header.e_shentsize));
                    sections.emplace_back(elf_stream, header);
                }

                for (Section64 const &section: sections) {
                    std::cout << section.name(sections[header.e_shstrndx]) << '\n';
                }
            }
        };
    }

    namespace elf32 {
        struct Header32 : Elf32_Ehdr {
            explicit Header32(elf64::Header64 const& header64) : Elf32_Ehdr() {
                std::copy(std::begin(header64.e_ident), std::end(header64.e_ident), std::begin(e_ident));
                e_type = header64.e_type; // ET_REL
                e_machine = EM_386;
                e_version = EV_CURRENT;
                e_entry = header64.e_entry; // FIXME: address translation
                e_phoff = header64.e_phoff; // FIXME
                e_shoff = header64.e_shoff; // FIXME
                e_flags = header64.e_flags;
                e_ehsize = sizeof(Elf32_Ehdr);
                e_phentsize = header64.e_phentsize; // FIXME
                e_phnum = header64.e_phnum;
                e_shentsize = header64.e_shentsize; // FIXME
                e_shnum = header64.e_shnum;
                e_shstrndx = header64.e_shstrndx;
            }
        };

        struct Rel32 : Elf32_Rel{
            explicit Rel32(elf64::Rela64 const& rela_64) : Elf32_Rel{} {
                // TODO
            }
        };
    }
}

int main() {
    std::ifstream elf_stream;
    elf_stream.exceptions(/*std::ifstream::eofbit | *//*std::ifstream::failbit | */std::ifstream::badbit);
    elf_stream.open(elf_file_name, std::ifstream::in | std::ifstream::binary);

    std::ofstream elf_copy_stream;
    elf_copy_stream.open(elf_copy_name, std::ofstream::out | std::ofstream::binary);

//    std::copy(std::istreambuf_iterator<char>(elf_stream), std::istreambuf_iterator<char>(),
//              std::ostreambuf_iterator<char>(elf_copy_stream));

    int retcode = 0;

    try {
        converter::elf64::Elf64{elf_stream};
    } catch (std::ifstream::failure const&) {
        std::cerr << "Error when processing file: read error or unexpected EOF.\n";
        retcode = 1;
    } catch (NonsupportedFileContent const& e) {
        std::cerr << "Nonsupported file content was found in the ELF.\n";
        std::cerr << e.what();
        retcode = 1;
    }

    elf_stream.close();
    elf_copy_stream.close();

    return retcode;
}
