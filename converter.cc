#include <elf.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include <optional>
#include <cstring>
#include <vector>
#include <memory>
#include <cassert>
#include <sys/stat.h>
#include <wait.h>
#include <fcntl.h>
#include "err.h"

constexpr char const* elf_file_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_x64.o";
constexpr char const* elf_copy_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_i386_copy.o";

class NonsupportedFileContent : public std::invalid_argument {
public:
    explicit NonsupportedFileContent(char const* what) : std::invalid_argument(what) {}
};

namespace converter {

    namespace assembly {
        static char const* FIFO_PREFIX = "fifo_";

        class FIFO {
            std::string fifo_name{FIFO_PREFIX};
        public:
            explicit FIFO() {
                for (size_t i = 0;; ++i) {
                    fifo_name.append(std::to_string(i));
                    if (mkfifo(fifo_name.c_str(), 0755) == -1) {
                        if (errno == EEXIST) {
                            fifo_name = FIFO_PREFIX;
                            continue;
                        } else {
                            syserr("Error in mkfifo()");
                        }
                    }
                    return;
                }
            }

            ~FIFO() {
                unlink(fifo_name.c_str());
            }

            std::string const& name() {
                return fifo_name;
            }
        };

        std::string assemble(std::string const& asm_code) {
            static char const* AS = "as";
            static char const* OBJCOPY = "objcopy";

            // open fifo for as -> objcopy communication
            FIFO as_to_objcopy;
            // open fifo for objcopy -> us communication
            FIFO objcopy_to_us;

            int us_to_as[2];
            if (pipe(us_to_as) != 0) {
                std::cerr << "Error in pipe().\n";
            }

            // fork AS process
            switch (fork()) {
                case 0: // child
                    if (close(0) == -1)
                        syserr("Error in child, close(0)");
                    if (dup(us_to_as[0]) != 0)
                        syserr("Error in child, dup(us_to_as[0])");
                    if (close (us_to_as[0]) == -1)
                        syserr("Error in child, close(us_to_as[0])");
                    if (close (us_to_as[1]) == -1)
                        syserr("Error in child, close (us_to_us[1])");

                    execlp(AS, AS, "-o", as_to_objcopy.name().c_str(), "-", nullptr);
                    syserr("exec() failed");
                default: // parent
                    break;
            }

            // fork OBJCOPY process
            switch (fork()) {
                case 0: // child
                    execlp(OBJCOPY, OBJCOPY, "-j", ".text", "-O", "binary", as_to_objcopy.name().c_str(), objcopy_to_us.name().c_str(), nullptr);
                    syserr("exec() failed");
                default: // parent
                    break;
            }

            if (write(us_to_as[1], asm_code.c_str(), asm_code.length()) == -1) {
                syserr("Error in write()");
            }
            if (close(us_to_as[1]) == -1)
                syserr("Error in parent, us_to_as(1)");

            std::ifstream rx{objcopy_to_us.name(), std::ios_base::binary | std::ios_base::in};
            std::istreambuf_iterator<char> eos;
            std::string machine_code(std::istreambuf_iterator<char>(rx), eos);

            if (wait(nullptr) == -1)
                syserr("Error in wait");
            if (wait(nullptr) == -1)
                syserr("Error in wait");

            return machine_code;
        }
    }

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


        struct Section64 { // TODO: class hierarchy to avoid ugly std::optionals
                           // honestly, a mix of inheritance and Rust enums would fit the best.
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
                    case SHT_DYNAMIC:
                        type = "SHT_DYNAMIC";
                        break;
                    case SHT_RELA:
                        type = "SHT_RELA";
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
            explicit Rel32(elf64::Rela64 const& rela64) : Elf32_Rel{} {
                // TODO
            }
        };

        struct Symbol32 : Elf32_Sym {
            explicit Symbol32(elf64::Symbol64 const& symbol64) : Elf32_Sym{} {
                // TODO
            }
        };

        struct Section32 { // TODO: class hierarchy to avoid ugly std::optionals
            // honestly, a mix of inheritance and Rust enums would fit best.
            Elf32_Shdr header{};
            std::optional<std::unique_ptr<char[]>> data;

            explicit Section32(elf64::Section64 const &section64, Elf32_Ehdr const &elf_header) {
                header.sh_name = section64.header.sh_name;
            }
        };
    }
}

int main2() {
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

int main() {
    std::ofstream ret{"ret.test"};
    auto machine_code{converter::assembly::assemble(R"(mov %eax, %eax)")};
    ret.write(machine_code.c_str(), static_cast<ssize_t>(machine_code.length()));
}