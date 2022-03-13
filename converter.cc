#include <elf.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include <optional>
#include <cstring>
#include <utility>
#include <vector>
#include <memory>
#include <cassert>
#include <sstream>

#include "assemblage.h"
#include "converter.h"

constexpr char const* elf_file_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_x64.o";
constexpr char const* elf_copy_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_i386_copy.o";

constexpr char const* func_file_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/example/test.flist";

namespace converter {
    class NonsupportedFileContent : public std::invalid_argument {
    public:
        explicit NonsupportedFileContent(char const* what) : std::invalid_argument(what) {}
    };

    uint32_t truncate_addr(uint64_t addr) {
        return static_cast<uint32_t>(addr);
    }

    namespace functions {
        ArgType Arg::parse_arg_type(char const* argtype) {
//            std::cout << "argtype: " << argtype << '\n';
            if (strcmp(argtype, "int") == 0) return int_t;
            if (strcmp(argtype, "uint") == 0) return uint_t;
            if (strcmp(argtype, "long") == 0) return long_t;
            if (strcmp(argtype, "ulong") == 0) return ulong_t;
            if (strcmp(argtype, "longlong") == 0) return longlong_t;
            if (strcmp(argtype, "ulonglong") == 0) return ulonglong_t;
            if (strcmp(argtype, "ptr") == 0) return ptr_t;
            throw std::invalid_argument{"invalid argument specified for function."};
        }

        size_t Arg::bits_32() const {
            switch (type) {
                case longlong_t:
                case ulonglong_t:
                    return 64;
                default:
                    return 32;
            }
        }

        size_t Arg::bits_64() const {
            switch (type) {
                case int_t:
                case uint_t:
                    return 32;
                default:
                    return 64;
            }
        }

        std::optional<ArgType> Ret::parse_ret_type(char const* argtype) {
            if (strcmp(argtype, "void") == 0) return {};
            return std::make_optional<>(Arg::parse_arg_type(argtype));
        }

        Function Function::from_line_decl(std::string& decl) {
            std::istringstream iss{decl};

            std::string name;
            iss >> name;

            std::string ret_type;
            iss >> ret_type;
            Ret ret{ret_type.c_str()};

            std::vector<Arg> args;
            std::copy(std::istream_iterator<std::string>(iss),
                      std::istream_iterator<std::string>(),
                      std::back_inserter(args));

            return Function(std::move(name), std::move(ret), std::move(args));
        }

        Functions::Functions(std::ifstream& func_stream) {
//            constexpr size_t const LINE_MAX_LEN = 100;
            std::string buff;
            while (!func_stream.eof()) {
                std::getline(func_stream, buff);
                if (buff.empty())
                    break;
                functions.insert(Function::from_line_decl(buff));

                buff.clear();
            }
        }
    }

    namespace elf64 {
#define read_to_field(elf_stream, field) elf_stream.read(reinterpret_cast<char*>(&(field)), sizeof(field))

        Header64::Header64(std::ifstream &elf_stream) : Elf64_Ehdr{} {
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

        Symbol64::Symbol64(std::ifstream &elf_stream) : Elf64_Sym{} {
            read_to_field(elf_stream, st_name);
            read_to_field(elf_stream, st_info);
            read_to_field(elf_stream, st_other);
            read_to_field(elf_stream, st_shndx);
            read_to_field(elf_stream, st_value);
            read_to_field(elf_stream, st_size);
            special_section = st_shndx >= 0xff00;

            // TODO: should we consider SYMINFO additional table?
        }

        Rela64::Rela64(std::ifstream &elf_stream) : Elf64_Rela{} {
            read_to_field(elf_stream, r_offset);
            read_to_field(elf_stream, r_info);
            read_to_field(elf_stream, r_addend);
        }

        Section64::Section64(std::ifstream &elf_stream, Elf64_Ehdr const &elf_header) {
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

            /*char const *type = "other";
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
            std::cout << "Section type: " << type << '\n';*/
        }

        [[nodiscard]] char const* Section64::name(Section64Strtab const &str_table) const {
            return str_table.name_of(header.sh_name);
        }

        Section64Rela::Section64Rela(Section64 section64, std::ifstream& elf_stream)  : Section64(std::move(section64)) {
            elf_stream.seekg(static_cast<ssize_t>(header.sh_offset));
            for (size_t i = 0; i < header.sh_size; i += sizeof(Elf64_Rela)) {
                relocations.emplace_back(elf_stream);
            }
        }

        Section64Symtab::Section64Symtab(Section64 section64, std::ifstream& elf_stream) : Section64(std::move(section64)) {
            elf_stream.seekg(static_cast<ssize_t>(header.sh_offset));
            std::cout << "Symbol entry size: " << sizeof(Elf64_Sym) << "\n";
            for (size_t i = 0; i < header.sh_size; i += sizeof(Elf64_Sym)) {
                symbols.emplace_back(elf_stream);
                auto const& symbol = *std::prev(std::end(symbols));
                printf("Symbol: name=%u, shndx=0x%x, size=%lu\n", symbol.st_name, symbol.st_shndx, symbol.st_size);
            }
        }


        std::unique_ptr<Section64> Section64::parse_section(std::ifstream& elf_stream, Elf64_Ehdr const& elf_header) {
            Section64 header_phase{elf_stream, elf_header};

            if (header_phase.header.sh_size) {
                std::cout << "Data found in section, at " << header_phase.header.sh_offset << '\n';
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
                        std::cout << "Section type: " << type << '\n';
                        return std::make_unique<Section64Symtab>(std::move(header_phase), elf_stream);
                    case SHT_STRTAB:
                        type = "SHT_STRTAB";
                        std::cout << "Section type: " << type << '\n';
                        return std::make_unique<Section64Strtab>(Section64WithGenericData{std::move(header_phase), elf_stream});
                    case SHT_DYNAMIC:
                        type = "SHT_DYNAMIC";
                        break;
                    case SHT_RELA:
                        type = "SHT_RELA";
                        std::cout << "Section type: " << type << '\n';
                        return std::make_unique<Section64Rela>(Section64Rela{std::move(header_phase), elf_stream});
                    case SHT_REL:
                        type = "SHT_REL";
                        break;
                    default:
                        break;
                }
                std::cout << "Section type: " << type << '\n';

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

            auto const* secstrtab = dynamic_cast<Section64Strtab*>(sections[header.e_shstrndx].get());
            assert(secstrtab != nullptr);

            // print section names
            {
                size_t i = 0;
                for (std::unique_ptr<Section64> const& section: sections) {
                    std::cout << "Section "<< i++ << " " << section->name(*secstrtab) << '\n';
                }
            }

            // find Symbol String Table
            Section64Strtab const* symstrtab = [&](){
                for (auto const& section: sections) {
                    auto* cast = dynamic_cast<Section64Strtab*>(section.get());
                    if (cast != nullptr && cast->header.sh_offset != sections[header.e_shstrndx]->header.sh_offset)
                        return cast;
                }
            }();

            // print symbol names
            Section64Symtab* symtab;
            for (std::unique_ptr<Section64> const& section: sections) {
                auto* cast = dynamic_cast<Section64Symtab*>(section.get());
                if (cast != nullptr) {
                    // found SYMTAB
                    for (auto const& symbol: cast->symbols) {
                        size_t idx = symbol.st_shndx;
                        std::unique_ptr<Section64> const& section = sections[idx];
//                        section->name(*secstrtab);
                        std::cout << "Symbol: <" << symstrtab->name_of(symbol.st_name) << ">,\t"
                        "relevant to section no=" << symbol.st_shndx << " : " <<
                            (symbol.special_section ? "" : section->name(*secstrtab) )
                        << '\n';
                    }
                    symtab = cast;
                }
            }

            // print relocations
            std::cout << "Relocations time!\n";
            for (std::unique_ptr<Section64> const& section: sections) {
                auto* cast = dynamic_cast<Section64Rela*>(section.get());
                if (cast != nullptr) {
                    // found RELA
                    std::cout << "Found RELA: " << cast->name(*secstrtab) << "\n";
                    for (auto const& relocation: cast->relocations) {
                        Symbol64 const& symbol = symtab->symbols[ELF64_R_SYM(relocation.r_info)];
                        std::cout << "Relocation: offset=" << relocation.r_offset <<
                            ", SYM(info)=" << ELF64_R_SYM(relocation.r_info) <<
                            "<" << symstrtab->name_of(symbol.st_name) << ">" <<
                            ", TYPE(info)=" << ELF64_R_TYPE(relocation.r_info) <<
                            "\n";
                    }
                }
            }
        }
# undef read_to_field
    }

    namespace elf32 {
        Header32::Header32(elf64::Header64 const& header64) : Elf32_Ehdr() {
            std::copy(std::begin(header64.e_ident), std::end(header64.e_ident), std::begin(e_ident));
            e_type = header64.e_type; // ET_REL
            e_machine = EM_386;
            e_version = EV_CURRENT;
            e_entry = truncate_addr(header64.e_entry);
            e_phoff = truncate_addr(header64.e_phoff); // FIXME
            e_shoff = truncate_addr(header64.e_shoff); // FIXME
            e_flags = header64.e_flags;
            e_ehsize = sizeof(Elf32_Ehdr);
            e_phentsize = 0; // ET_REL justifies this.
            e_phnum = header64.e_phnum;
            e_shentsize = header64.e_shentsize == 0 ? 0 : sizeof(Elf32_Shdr);
            e_shnum = header64.e_shnum;
            e_shstrndx = header64.e_shstrndx;
        }

        Rel32::Rel32(elf64::Rela64 const& rela64) : Elf32_Rel{} {
            // TODO
        }

        Symbol32::Symbol32(elf64::Symbol64 const& symbol64) : Elf32_Sym{} {
            // TODO
        }

        Section32::Section32(elf64::Section64 const &section64, Elf32_Ehdr const &elf_header) {
            header.sh_name = section64.header.sh_name;
            // TODO
        }
    }
}

int main4() {
    std::ifstream func_stream;
    func_stream.exceptions(/*std::ifstream::eofbit | *//*std::ifstream::failbit | */std::ifstream::badbit);
    func_stream.open(func_file_name, std::ifstream::in);

    converter::functions::Functions functions{func_stream};
    functions.print_one("f");
    functions.print();

    func_stream.close();
    return 0;
}

int main(int argc, char const* argv[]) {
/*    if (argc != 4) {
        std::cerr << "Wrong number of arguments.\n";
        return 1;
    }

    char const* elf64_file_name = argv[1];
    char const* functions_file_name = argv[2];
    char const* elf32_file_name = argv[3];*/

    std::ifstream func_stream;
    func_stream.exceptions(/*std::ifstream::eofbit | *//*std::ifstream::failbit | */std::ifstream::badbit);
    func_stream.open(func_file_name, std::ifstream::in);

    std::ifstream elf_stream;
    elf_stream.exceptions(/*std::ifstream::eofbit | *//*std::ifstream::failbit | */std::ifstream::badbit);
    elf_stream.open(elf_file_name, std::ifstream::in | std::ifstream::binary);

//    std::ofstream elf_copy_stream;
//    elf_copy_stream.open(elf_copy_name, std::ofstream::out | std::ofstream::binary);

//    std::copy(std::istreambuf_iterator<char>(elf_stream), std::istreambuf_iterator<char>(),
//              std::ostreambuf_iterator<char>(elf_copy_stream));

    try {
        converter::functions::Functions functions{func_stream};
        functions.print();
        std::cout << "\n\n#############################\n\n";

        converter::elf64::Elf64 elf64{elf_stream};

    } catch (std::ifstream::failure const&) {
        std::cerr << "Error when processing file: read error or unexpected EOF.\n";
        return 1;
    } catch (converter::NonsupportedFileContent const& e) {
        std::cerr << "Nonsupported file content was found in the ELF.\n";
        std::cerr << e.what();
        return 1;
    }

    return 0;
}

int main2() {
    std::ofstream ret{"ret.test", std::ios_base::app | std::ios_base::binary};
    auto machine_code{converter::assembly::assemble(R"(
mov %eax, %eax
)")};
    ret.write(machine_code.c_str(), static_cast<ssize_t>(machine_code.length()));

    return 0;
}

/*
 * UWAGA do treści: sekcję .text TRZEBA zmodyfikować, bo wszystkim relokacjom trzeba powstawiać addendy
 *
 * */