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

//constexpr char const* elf_file_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_x64.o";
//constexpr char const* elf_copy_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_i386_copy.o";
constexpr char const* func_file_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/example/test.flist";

namespace converter {
    class UnsupportedFileContent : public std::invalid_argument {
    public:
        explicit UnsupportedFileContent(std::string const& what) : std::invalid_argument(what) {}
    };

    uint32_t truncate_addr(uint64_t addr) {
        return static_cast<uint32_t>(addr);
    }

    namespace func_spec {
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

    namespace stubs {
        std::string const thunkin = R"(
# long long fun(void *ptr, int x, long long y)

.code32
fun_stub:
# zapis rejestrów
pushl %edi
pushl %esi
# wyrównanie stosu
subl $4, %esp
# zmiana trybu
ljmpl *fun_addr_32to64

# część 64-bitowa
.code64
fun_stub_64:
# bierzemy argumenty ze stosu
movl 0x10(%rsp), %edi
movslq 0x14(%rsp), %rsi
movq 0x18(%rsp), $rdx
# wołamy właściwą funkcję
call fun
# konwersja wartości zwracanej
movq %rax, %rdx
shrq $32, %rdx
# powrót
ljmpl *fun_addr_64to32

.code32
fun_stub_32:
addl $4, %esp
popl %esi
popl %edi
retl

fun_addr_64to32:
.long fun_stub_32
.long 0x23

fun_addr_32to64:
.long fun_stub_64
.long 0x33
)";
        /* *
         * 00000000  57 56 83 ec 04 ff 2d 00  00 00 00 48 63 7c 24 10
         * 00000010  48 63 74 24 14 48 63 54  24 18 48 63 4c 24 1c 4c
         * 00000020  63 44 24 20 4c 63 4c 24  24 e8 00 00 00 00 48 89
         * 00000030  c2 48 c1 ea 20 ff 2c 25  00 00 00 00 83 c4 04 5e
         * 00000040  5f c3 00 00 00 00 23 00  00 00 00 00 00 00 33 00
         * 00000050  00 00
         * */
        unsigned char const thunkin_code[] = {
            /* 00 */   0x57, 0x56, 0x83, 0xec, 0x04, 0xff, 0x2d, 0x00, // 7: R_X86_64_32        .text+0x4a
            /* 08 */   0x00, 0x00, 0x00, 0x48, 0x63, 0x7c, 0x24, 0x10,
            /* 10 */   0x48, 0x63, 0x74, 0x24, 0x14, 0x48, 0x63, 0x54,
            /* 18 */   0x24, 0x18, 0x48, 0x63, 0x4c, 0x24, 0x1c, 0x4c,
            /* 20 */   0x63, 0x44, 0x24, 0x20, 0x4c, 0x63, 0x4c, 0x24,
            /* 28 */   0x24, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, // 2a: R_X86_64_PLT32    fun-0x4
            /* 30 */   0xc2, 0x48, 0xc1, 0xea, 0x20, 0xff, 0x2c, 0x25,
            /* 38 */   0x00, 0x00, 0x00, 0x00, 0x83, 0xc4, 0x04, 0x5e, // 38: R_X86_64_32S      .text+0x42
            /* 40 */   0x5f, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x23, 0x00, // 42: R_X86_64_32       .text+0x3c
            /* 48 */   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, // 4a: R_X86_64_32       .text+0xb
            /* 50 */   0x00, 0x00 };

        std::vector<elf32::ThunkPreRel32> relocations {
                {.local_symbol=false, .offset=0x7,   .addend=0x4a},
                {.local_symbol=true,  .offset=0x2a,  .addend=-0x4},
                {.local_symbol=false, .offset=0x38,  .addend=0x42},
                {.local_symbol=false, .offset=0x42,  .addend=0x3c},
                {.local_symbol=false, .offset=0x4a,  .addend=0xb },
        };
    }

    namespace elf64 {
#define read_to_field(elf_stream, field) elf_stream.read(reinterpret_cast<char*>(&(field)), sizeof(field))

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

            printf("Extracted Header64: e_shoff=%lu, e_shentsize=%u\n", e_shoff, e_shentsize);
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
//            read_to_field(elf_stream, r_offset);
//            read_to_field(elf_stream, r_info);
//            read_to_field(elf_stream, r_addend);
            static_assert(sizeof(*this) == sizeof(Elf64_Rela));
            read_to_field(elf_stream, *this);
        }

        Section64::Section64(std::ifstream &elf_stream) {
            static int i = 0;

            read_to_field(elf_stream, header);

//            std::cout << "Extracting Section no " << i++ << " from start_idx " << elf_stream.tellg() <<
//                ", align=" << header.sh_addralign << ", size=" << header.sh_size << '\n';

//            std::cout << "Section type: " << type << '\n';
        }

        [[nodiscard]] char const* Section64::name(Section64Strtab const &str_table) const {
            return str_table.name_of(header.sh_name);
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
            std::cout << "Symbol entry size: " << sizeof(Elf64_Sym) << "\n";
            for (size_t i = 0; i < header.sh_size; i += sizeof(Elf64_Sym)) {
                symbols.emplace_back(elf_stream);
                auto const& symbol = *std::prev(std::end(symbols));
//                printf("Symbol: name=%u, shndx=0x%x, size=%lu\n", symbol.st_name, symbol.st_shndx, symbol.st_size);
            }
        }

        std::unique_ptr<Section64> Section64::parse_section(std::ifstream& elf_stream, Elf64_Ehdr const& elf_header) {
            Section64 header_phase{elf_stream};

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
                    std::cout << "Section "<< i++ << " " << section->name(*secstrtab) << ", entrysize=" << section->header.sh_entsize << '\n';
                }
            }

            // find Symbol String Table
            Section64Strtab const* symstrtab = [&](){
                for (auto const& section: sections) {
                    auto* cast = dynamic_cast<Section64Strtab*>(section.get());
                    if (cast != nullptr && cast->header.sh_offset != sections[header.e_shstrndx]->header.sh_offset)
                        return cast;
                }
                assert(false);
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
                        auto const& symtab2 = dynamic_cast<Section64Symtab const&>(*sections[section->header.sh_link]);
                        Symbol64 const& symbol = symtab2.symbols[ELF64_R_SYM(relocation.r_info)];
                        std::cout << "Relocation: offset=" << relocation.r_offset <<
                            ", SYM(info)=" << ELF64_R_SYM(relocation.r_info) <<
                            "<" << symstrtab->name_of(symbol.st_name) << ">" <<
                            "(section=<" << sections[cast->header.sh_info]->name(*secstrtab) <<
                            ">, size=" << sections[cast->header.sh_info]->header.sh_size << ")" <<
                            ", TYPE(info)=" << ELF64_R_TYPE(relocation.r_info) <<
                            "\n";
                    }
                }
            }
        }

# undef read_to_field
    }

    namespace elf32 {
        void align_offset_to(size_t& offset, size_t const alignment) {
            auto const rem = offset % alignment;
            assert(rem >= 0);
            if (rem > 0) offset += alignment - rem;
        }
        void align_offset_to(size_t& offset, size_t const alignment, std::ofstream& elf_file) {
            size_t const offset_before = offset;

            align_offset_to(offset, alignment);

            size_t const stuffing = offset - offset_before;
            for (uint32_t i = 0; i < stuffing; ++i) {
                static char zero;
                elf_file.write(&zero, 1);
            }
        }

#define write_from_field(elf_stream, field) elf_stream.write(reinterpret_cast<char const*>(&(field)), sizeof(field))
        Header32::Header32(elf64::Header64 const& header64) : Elf32_Ehdr{} {
            std::copy(std::begin(header64.e_ident), std::end(header64.e_ident), std::begin(e_ident));
            e_ident[EI_CLASS] = ELFCLASS32;
            e_type = header64.e_type; // ET_REL
            e_machine = EM_386;
            e_version = EV_CURRENT;
            e_entry = truncate_addr(header64.e_entry);
            e_phoff = 0;
            e_shoff = truncate_addr(header64.e_shoff); // FIXME
            e_flags = header64.e_flags;
            e_ehsize = sizeof(Elf32_Ehdr);
            e_phentsize = 0; // ET_REL justifies this.
            e_phnum = 0;
            e_shentsize = header64.e_shentsize == 0 ? 0 : sizeof(Elf32_Shdr);
            e_shnum = header64.e_shnum;
            e_shstrndx = header64.e_shstrndx;
        }

        void Header32::write_out(std::ofstream& elf_stream, size_t& offset) const {
            static_assert(sizeof(*this) == sizeof(Elf32_Ehdr));
            printf("e_shoff: %u\n", e_shoff);
            printf("e_phoff: %u\n", e_phoff);
            write_from_field(elf_stream, *this);
            offset += size();
        }

        Rela32::Rela32(elf64::Rela64 const& rela64) : Elf32_Rela{} {
            r_offset = truncate_addr(rela64.r_offset);

            Elf32_Word const r_sym = ELF64_R_SYM(rela64.r_info);
            Elf32_Word const r_type = [&r_info=rela64.r_info](){
                Elf32_Xword const r64_type = ELF64_R_TYPE(r_info);
                switch (r64_type) {
                    case R_X86_64_32:
                    case R_X86_64_32S:
                        return R_386_32;
                    case R_X86_64_PC32:
                    case R_X86_64_PLT32:
                        return R_386_PC32;
                    default:
                        throw UnsupportedFileContent{"Unsupported relocation type: " + std::to_string(r64_type)};
                }
            }();
//            printf("\nConverted relocation type=%u, sym=%u into type=%lu, sym=%u\n", r_type, r_sym, ELF64_R_TYPE(rela64.r_info), r_sym);
            r_info = ELF32_R_INFO(r_sym, r_type);
            r_addend = static_cast<decltype(r_addend)>(rela64.r_addend);

        }

        /*void Rela32::write_out(std::ofstream& elf_file, size_t& offset) const {
            static_assert(sizeof(*this) == sizeof(Elf32_Rela));
            write_from_field(elf_file, *this);
        }*/

        Rel32::Rel32(Rela32 const& rela32, Section32Rela const& section32_rela, sections32_t& sections) : Elf32_Rel{} {
            r_offset = rela32.r_offset;
            r_info = rela32.r_info;
            try {
                auto const& symtab = dynamic_cast<Section32Symtab const&>(*sections[section32_rela.header.sh_link]);
                auto const& symbol = symtab.symbols[ELF32_R_SYM(r_info)];

                if (ELF32_ST_TYPE(symbol.st_info) != STT_NOTYPE) {
                    try {
                        auto& rel_section = dynamic_cast<Section32WithFixedSizeData&>(*sections[section32_rela.header.sh_info]);
                        using addend_t = std::remove_const_t<decltype(rela32.r_addend)>;

//                        std::cout << "r_offset=" << r_offset << ", section_size=" << rel_section.header.sh_size << "\n";
                        auto& addr = reinterpret_cast<addend_t&>(rel_section.data.get()[r_offset]);

//                        std::cout << "Before addr=" << addr << "; addend=" << rela32.r_addend << "; ";
                        addr += rela32.r_addend;
//                        std::cout << "after addr=" << addr << '\n';

                    } catch (std::bad_cast const&) {
                        throw UnsupportedFileContent{"Rela section " + std::to_string(section32_rela.header.sh_info) + " is bound to section without data."};
                    }
                }
            } catch (std::bad_cast const&) {
                throw UnsupportedFileContent{"Section referenced in Rela section is not a Symtab section."};
            }
        }

        void Rel32::write_out(std::ofstream& elf_file, size_t& offset) const {
            static_assert(sizeof(*this) == sizeof(Elf32_Rel));
            write_from_field(elf_file, *this);
        }

        Rel32::Rel32(Elf32_Addr const offset, Elf32_Word const type, Elf32_Word const symbol_idx) : Elf32_Rel{} {
            r_offset = offset;
            r_info = ELF32_R_INFO(symbol_idx, type);
        }

        Rel32 Rel32::self_ref(Elf32_Addr const offset, Elf32_Word const self_symbol_idx) {
            return Rel32{offset, R_386_32, self_symbol_idx};
        }

        Rel32 Rel32::local_symbol_ref(Elf32_Addr offset, Elf32_Word local_symbol_idx) {
            return Rel32{offset, R_386_PC32, local_symbol_idx};
        }

        Symbol32::Symbol32(elf64::Symbol64 const& symbol64) : Elf32_Sym{} {
            st_name = symbol64.st_name;
            st_value = symbol64.st_value;
            st_size = symbol64.st_size; // FIXME: surely?
            st_info = symbol64.st_info;  // TODO: to be modified elsewhere
            st_other = symbol64.st_other; // TODO: this as well
            st_shndx = symbol64.st_shndx;
        }

        void Symbol32::write_out(std::ofstream& elf_file, size_t& offset) const {
            static_assert(sizeof(*this) == sizeof(Elf32_Sym));
            write_from_field(elf_file, *this);
        }

        Symbol32::Symbol32(Symbol32 const& symbol, bool const global, Elf32_Word const thunk_section_idx) : Elf32_Sym{} {
            st_name = symbol.st_name;
            st_value = symbol.st_value;
            st_size = 0; // for now; TODO: remember to set to finally -> done
            st_shndx = thunk_section_idx;
            st_other = st_other;
            Elf32_Word const type = STT_FUNC;
            Elf32_Word const binding = global
                    ? STB_GLOBAL // global stub for local 64-bit function
                    : STB_LOCAL;  // local stub for external 32-bit function
            st_info = ELF32_ST_INFO(binding, type);
        }

        Symbol32 Symbol32::global_stub(Symbol32 const& local_symbol, Elf32_Word thunkin_section_idx) {
            return Symbol32{local_symbol, true, thunkin_section_idx};
        }

        Symbol32 Symbol32::local_stub(Symbol32 const& global_symbol, Elf32_Word thunkout_section_idx) {
            return Symbol32{global_symbol, false, thunkout_section_idx};
        }

        Symbol32::Symbol32(Section32 const& section, Elf32_Word const section_idx, Elf32_Word const section_name_idx)
                : Elf32_Sym{} {
            st_name = section_name_idx;
            st_value = 0;
            st_size = 0;
            st_shndx = section_idx;
            st_other = st_other;
            st_info = ELF32_ST_INFO(STB_LOCAL, STT_SECTION);
        }

        Symbol32 Symbol32::for_section(Section32 const& section, Elf32_Word const section_idx) {
            return Symbol32{section, section_idx, 0};
        }

        Thunkin::Thunkin(func_spec::Function const& func_spec, size_t const thunk_symbol_idx, size_t const local_symbol_idx) {
            for (uint8_t const byte: stubs::thunkin_code) {
                stub.push_back(byte);
            }
            for (auto const pre_rel32 : stubs::relocations) {
                Rel32 rel = pre_rel32.local_symbol
                            ? Rel32::local_symbol_ref(pre_rel32.offset, local_symbol_idx)
                            : Rel32::self_ref(pre_rel32.offset, thunk_symbol_idx);
                *reinterpret_cast<Elf32_Word*>(stub.data() + rel.r_offset) = pre_rel32.addend;
                relocations.push_back(rel);
            }
        }

        void Thunkin::lay_to_sections(Section32Thunkin& thunkin_section, Section32Rel& rel_thunkin_section) {
            auto thunk_pos = thunkin_section.add_thunkin(std::move(stub));
            for (auto& rel: relocations) {
                rel.r_offset += thunk_pos;
                rel_thunkin_section.relocations.push_back(rel);
            }
        }

        Section32::Section32(elf64::Section64 const &section64) {
            header.sh_name = section64.header.sh_name;
            header.sh_type = section64.header.sh_type; //  == SHT_RELA ? SHT_REL : section64.header.sh_type;
            header.sh_flags = section64.header.sh_flags;
            header.sh_addr = section64.header.sh_addr;
            header.sh_offset = 0; // static_cast<unsigned int>(-1); // will be set later
            header.sh_size = section64.header.sh_size;
            header.sh_link = section64.header.sh_link;
            header.sh_info = section64.header.sh_info;
            header.sh_addralign = section64.header.sh_addralign; // FIXME: for sure?
            header.sh_entsize = section64.header.sh_entsize;

            // TODO
        }

        Section32::Section32(Elf32_Shdr const& header) {
            this->header = header;
        }

        char const* Section32::type() const {
            switch (header.sh_type) {
                case SHT_NULL:
                    return "NULL";
                case SHT_PROGBITS:
                    return "SHT_PROGBITS";
                case SHT_NOBITS:
                    return "SHT_NOBITS";
                case SHT_SYMTAB:
                    return "SHT_SYMTAB";
                case SHT_STRTAB:
                    return "SHT_STRTAB";
                case SHT_DYNAMIC:
                    return "SHT_DYNAMIC";
                case SHT_RELA:
                    return "SHT_RELA";
                case SHT_REL:
                    return "SHT_REL";
                default:
                    return "other";
            }
        }

        void Section32::align_offset(size_t& offset) const {
            align_offset_to(offset, alignment());
        }

        void Section32::align_offset(size_t& offset, std::ofstream& elf_file) const {
            align_offset_to(offset, alignment(), elf_file);
        }

        void Section32::write_out_data(std::ofstream& elf_file, size_t& offset) {
//            printf("(before alignment = %lx) ", offset);
            align_offset(offset, elf_file);
//            printf("writing at offset %lx\n", offset);
        }

        void Section32::write_out_header(std::ofstream& elf_file, size_t& offset) const {
            // section headers alignment
            align_offset_to(offset, 8, elf_file);
//            printf("Writing out header at offset %lx\n", offset);
            write_from_field(elf_file, header);
            offset += sizeof(header);
        }

        Section32WithoutData::Section32WithoutData(elf64::Section64WithoutData const& section64)
            : Section32(section64) {
            // pass
        }

        size_t Section32WithoutData::size() {
            return 0;
        }

        Section32WithFixedSizeData::Section32WithFixedSizeData(elf64::Section64WithGenericData const& section64)
            : Section32(section64), data{std::unique_ptr<char[]>([size=section64.header.sh_size, data=section64.data.get()](){
                char* ptr = new char[size];
                std::copy(data, data + size, ptr);
                return ptr;
            }())} {}

        void Section32WithFixedSizeData::write_out_data(std::ofstream& elf_file, size_t& offset) {
            Section32::write_out_data(elf_file, offset);
            elf_file.write(data.get(), static_cast<ssize_t>(size()));
        }

        size_t Section32WithFixedSizeData::size() {
            return header.sh_size;
        }

        Section32WithGrowableData::Section32WithGrowableData(elf64::Section64WithGenericData const& section64)
            : Section32{section64} {
            data.resize(section64.header.sh_size);
            std::copy(section64.data.get(), section64.data.get() + section64.header.sh_size, data.data());
        }

        Section32WithGrowableData::Section32WithGrowableData(Elf32_Shdr const& header) : Section32{header} {}

        size_t Section32WithGrowableData::size() {
            header.sh_size = data.size();
            return header.sh_size;
        }

        Section32Strtab::Section32Strtab(elf64::Section64Strtab const& strtab64)
                : Section32WithGrowableData{strtab64} {}

        Elf32_Word Section32Strtab::append_name(std::string const& name) {
            for (char c: name) {
                data.emplace_back(c);
            }
            data.emplace_back('\0');

            Elf32_Word pos = header.sh_size;
            header.sh_size += name.size() + 1;
            return pos;
        }

        Section32Symtab::Section32Symtab(elf64::Section64Symtab const& symtab64) : Section32{symtab64} {
            for (auto const& symbol64: symtab64.symbols) {
                symbols.emplace_back(symbol64);
            }
            header.sh_entsize = sizeof(Elf32_Sym);
            header.sh_size = sizeof(Elf32_Sym) * symbols.size();
        }

        void Section32Symtab::write_out_data(std::ofstream& elf_file, size_t& offset) {
            Section32::write_out_data(elf_file, offset);
            for (auto const& symbol: symbols) {
                symbol.write_out(elf_file, offset);
            }
        }

        size_t Section32Symtab::size() {
            header.sh_size = sizeof(Elf32_Sym) * symbols.size();
            return header.sh_size;
        }

        Elf32_Word Section32Symtab::add_symbol(Symbol32 const symbol) {
            auto pos = symbols.size();
            symbols.push_back(symbol);
            return pos;
        }

        Elf32_Word Section32Symtab::register_section(Section32 const& section, Elf32_Word section_idx) {
            // TODO: add name to shstrtab -> done
            return add_symbol(Symbol32::for_section(section, section_idx));
        }

        Section32Rela::Section32Rela(elf64::Section64Rela const& rela64) : Section32{rela64} {
            for (auto const& relocation: rela64.relocations) {
                relocations.emplace_back(relocation);
            }
            header.sh_entsize = sizeof(Elf32_Rela);
            header.sh_size = sizeof(Elf32_Rela) * relocations.size();
        }

        size_t Section32Rela::size() {
            header.sh_size = sizeof(Elf32_Rela) * relocations.size();
            return header.sh_size;
        }

        /*void Section32Rela::write_out_data(std::ofstream& elf_file, size_t& offset) const {
            Section32::write_out_data(elf_file, offset);
            for (auto const& relocation: relocations) {
                relocation.write_out(elf_file, offset);
            }
        }*/

        Section32Rel::Section32Rel(Section32Rela const& rela32, sections32_t& sections) : Section32{rela32.header} {
            for (auto const& relocation: rela32.relocations) {
                relocations.emplace_back(relocation, rela32, sections);
            }
            header.sh_type = SHT_REL;
            header.sh_entsize = sizeof(Elf32_Rel);
            header.sh_size = sizeof(Elf32_Rel) * relocations.size();
        }

        void Section32Rel::write_out_data(std::ofstream& elf_file, size_t& offset) {
            Section32::write_out_data(elf_file, offset);
            for (auto const& relocation: relocations) {
                relocation.write_out(elf_file, offset);
            }
        }

        size_t Section32Rel::size() {
            header.sh_size = sizeof(Elf32_Rel) * relocations.size();
            return header.sh_size;
        }

        Section32Rel Section32Rel::make_for_thunk(const Section32Thunk& thunk_section, Elf32_Word const thunk_section_idx,
                                                  Section32Strtab& strtab, Elf32_Word const symtab_idx) {
            std::string rel_section_name{".rel"};
            rel_section_name += strtab.name_of(thunk_section.header.sh_name);
            Elf32_Word name_idx = strtab.append_name(rel_section_name);

            Elf32_Shdr header{
                    .sh_name = name_idx,
                    .sh_type = SHT_REL,
                    .sh_flags = 0,
                    .sh_addr = 0,
                    .sh_offset = 0, // so far
                    .sh_size = 0, // so far
                    .sh_link = thunk_section_idx,
                    .sh_info = symtab_idx,
                    .sh_addralign = 1,
                    .sh_entsize = 0
            };

            return Section32Rel{header};
        }

        size_t Section32Thunkin::add_thunkin(std::vector<uint8_t> stub) {
            auto const pos = data.size();
            data = std::move(stub);
            return pos;
        }

        std::unique_ptr<Section32> Section32::convert_section(elf64::Section64 const& section64, Header32 const& elf_header) {
            if (dynamic_cast<elf64::Section64WithoutData const*>(&section64) != nullptr) {
                return std::make_unique<Section32WithoutData>(Section32WithoutData{
                        dynamic_cast<elf64::Section64WithoutData const&>(section64)
                });
            } else if (dynamic_cast<elf64::Section64Symtab const*>(&section64) != nullptr) {
                return std::make_unique<Section32Symtab>(Section32Symtab{
                        dynamic_cast<elf64::Section64Symtab const&>(section64)
                });
            } else if (dynamic_cast<elf64::Section64Rela const*>(&section64) != nullptr) {
                return std::make_unique<Section32Rela>(Section32Rela{
                        dynamic_cast<elf64::Section64Rela const&>(section64)
                });
            } else if (dynamic_cast<elf64::Section64Strtab const*>(&section64) != nullptr) {
                return std::make_unique<Section32Strtab>(Section32Strtab{
                        dynamic_cast<elf64::Section64Strtab const&>(section64)
                });
            } else if (dynamic_cast<elf64::Section64WithGenericData const*>(&section64) != nullptr) {
                return std::make_unique<Section32WithFixedSizeData>(Section32WithFixedSizeData{
                        dynamic_cast<elf64::Section64WithGenericData const&>(section64)
                });
            } else {
                assert(false);
            }
        }

        Elf32::Elf32(elf64::Elf64 const& elf64, func_spec::Functions const& functions)
            : header{elf64.header},
              sections{[&header=this->header, &elf64_sections=elf64.sections](){
                  sections32_t _sections;
                  for (auto const& section64: elf64_sections) {
                      _sections.push_back(Section32::convert_section(*section64, header));
                  }
                  return _sections;
              }()},
              shstrtab{[](Section32* section){
                  std::cout << section->type() << '\n';
                  auto _strtab = dynamic_cast<Section32Strtab*>(section);
                  if (_strtab == nullptr) {
                      throw UnsupportedFileContent{"Strtab given in the ELF header is not valid."};
                  }
                  return _strtab;
              }(sections[header.e_shstrndx].get())} {

            /*for (auto const& section: sections) {
                std::cout << section->type() << "\t: ";
                std::cout << std::flush;
                std::cout << section->to_string() << '\n';
            }*/

            std::cout << "###############################\nBegin relocation conversion\n";

            // RELA into REL conversion:
            convert_relocations();

            // Symbols conversions:
            convert_symbols(functions);

            std::cout << "\nCorrecting offsets.\n";
            correct_offsets();
        }

        void Elf32::convert_relocations() {
            for (auto& section: sections) {
                std::cout << section->type() << "\t: ";
                std::cout << std::flush;
                std::cout << section->to_string() << '\n';
                auto*const cast = dynamic_cast<Section32Rela*>(section.get());
                if (cast != nullptr) {
                    std::cout << "Creating new Section32Rel\n";
                    std::unique_ptr<Section32> temp_unique = std::make_unique<Section32Rel>(Section32Rel{*cast, sections});
                    assert(dynamic_cast<Section32Rel*>(temp_unique.get()) != nullptr);

                    section.swap(temp_unique);
                }
            }
        }

        void Elf32::convert_symbols(func_spec::Functions const& functions) {
            std::vector<std::optional<std::pair<size_t, size_t>>> thunkin_section_idcs{sections.size()};
            std::vector<std::optional<std::pair<size_t, size_t>>> thunkout_section_idcs{sections.size()};

            try {
                Elf32_Word symtab_idx = 0;
                for (std::unique_ptr<Section32> const& section: sections) { // looking for symtabs
                    auto* symtab = dynamic_cast<Section32Symtab*>(section.get());
                    if (symtab != nullptr) { // found SYMTAB
                        for (auto& symbol: symtab->symbols) {

                            auto bind = ELF32_ST_BIND(symbol.st_info);
                            auto type = ELF32_ST_TYPE(symbol.st_info);
                            auto& symstrtab = dynamic_cast<Section32Strtab&>(*sections[symtab->strtab()]);
                            auto name = symstrtab.name_of(symbol.st_name);

                            if (bind == STB_GLOBAL && type == STT_FUNC) {
                                // Case 1.
                                // - change original symbols from GLOBAL to LOCAL.
                                symbol.st_info = ELF32_ST_INFO(STB_LOCAL, STT_FUNC);

                                if (functions.find(name) == functions.end()) {
                                    throw UnsupportedFileContent{std::string{"Local function "} + name + " not present in function file."};
                                }
                                auto const& func_spec = *functions.find(name);

                                size_t thunkin_section_idx;
                                // - create thunkin section if not exist, as well as corresponding rel.thunkin
                                if (!thunkin_section_idcs[symbol.related_section_idx()].has_value()) {
                                    thunkin_section_idx = sections.size();
                                    Elf32_Word rel_thunkin_section_idx = thunkin_section_idx + 1;

                                    thunkin_section_idcs[symbol.related_section_idx()] = std::make_optional<>(
                                            std::make_pair(thunkin_section_idx, rel_thunkin_section_idx));

                                    auto thunkin_section = std::make_unique<Section32Thunkin>(*section, symtab_idx, *shstrtab);

                                    // TODO: register new section symbols! -> done
                                    auto thunkin_section_name_idx = symstrtab.append_name(name + std::string{".thunkin"});
                                    auto section_symbol_idx = symtab->register_section(*thunkin_section, thunkin_section_idx);
                                    thunkin_section->associated_symbol = section_symbol_idx;

                                    sections.push_back(std::move(thunkin_section));

                                    auto rel_thunkin_section = std::make_unique<Section32Rel>(Section32Rel::make_for_thunk(
                                            dynamic_cast<Section32Thunk&>(*sections[thunkin_section_idx]),
                                            thunkin_section_idx, *shstrtab, symtab_idx)
                                    );

                                    sections.push_back(std::move(rel_thunkin_section));
                                }

                                /* - add new global symbols: trampolines that change mode from 32-bit to 64-bit,
                                 *   call original function and change mode back to 32-bit. */

                                // add global symbol
                                auto local_symbol_idx = symtab->add_symbol(Symbol32::global_stub(symbol, thunkin_section_idx));

                                // just get references to thunk & thunk rel sections
                                auto& thunkin_section = dynamic_cast<Section32Thunkin&>(
                                        *sections[thunkin_section_idcs[symbol.related_section_idx()]->first]);
                                auto& rel_thunkin_section = dynamic_cast<Section32Rel&>(
                                        *sections[thunkin_section_idcs[symbol.related_section_idx()]->second]);

                                // build thunkin
                                Thunkin thunkin{func_spec, thunkin_section.associated_symbol.value(), local_symbol_idx};

                                // - add new relocations that point from stubs to original symbols (e.g. thunk -> f)
                                // lay thunk to sections
                                thunkin.lay_to_sections(thunkin_section, rel_thunkin_section);

                                /* Case 1: DONE? */

                            } else if (bind == STB_GLOBAL && type == STT_NOTYPE && functions.find(name) != functions.end()) {
                                // Case 2.
                                auto const& func_spec = *functions.find(name);
                                if (functions.find(name) != functions.end()) {
                                    // the symbol is an external function, so we shall:
                                    // - add new local symbols: stubs that change mode to 32-bit,
                                    //   call global symbols and come back to 64-bit:


                                    // - change relocations in the way that now they point to new symbols (stubs)
                                    //   instead of original external functions (e.g. [!-> fputs] => [-> thunk_fputs])
                                }
                            }
/*                        size_t idx = symbol.st_shndx;
                        std::unique_ptr<Section32> const& section = sections[idx];
                        section->name(*secstrtab);
                        std::cout << "Symbol: <" << symstrtab->name_of(symbol.st_name) << ">,\t"
                                  "relevant to section no=" << symbol.st_shndx << " : " <<
                                  (symbol.special_section ? "" : section->name(*secstrtab) )
                                  << '\n';*/
                        }
                    }
                    ++symtab_idx;
                }
                auto correct_symbol_size = [&sections=sections](std::optional<std::pair<size_t, size_t>> const idx_pair){
                    if (idx_pair.has_value()) {
                        auto& thunk_section = dynamic_cast<Section32Thunk&>(*sections[idx_pair->first]);
                        auto &symtab = dynamic_cast<Section32Symtab&>(*sections[thunk_section.associated_symtab]);
                        symtab.symbols[thunk_section.associated_symbol.value()].st_size = thunk_section.size();
                    }
                };
                for (auto idx_pair: thunkin_section_idcs) {
                    correct_symbol_size(idx_pair);
                }
                for (auto idx_pair: thunkout_section_idcs) {
                    correct_symbol_size(idx_pair);
                }

            } catch (std::bad_cast const&) {
                throw UnsupportedFileContent{"Bad symbol name shstrtab index."};
            }

            /* - 1st case: calling our (64-bit) functions from outside (32-bit):
             * - changing original symbols from GLOBAL to LOCAL
             * - adding new global symbols: trampolines that change mode from 32-bit to 64-bit,
             *   call original function and change mode back to 32-bit
             * - adding new relocations that point from stubs to original symbols (e.g. thunk -> f)
             * */


            /* - 2nd case: calling external functions (32-bit O̶R̶ ̶6̶4̶-̶b̶i̶t̶ [crossed out because of 3.3 point of task content])
             *   from our (64-bit) code:
             * - adding new local symbols: stubs that change mode to 32-bit, call global symbols and come back to 64-bit
             * - changing relocations in the way that now they point to new symbols (stubs)
             *   instead of original external functions (e.g. [!-> fputs] => [-> thunk_fputs]) */


            /* - 3rd case: calling our functions from our functions (both 64-bit):
             * - no stubs needed */
            // Case 3:

        }

        void Elf32::correct_offsets() {
/* *
 * 1) ELF header:
 *     - shoff
 * 2) Sections:
 *     - sh_offset
 *     - sh_size -> to chyba lepiej aktualizować na bieżąco w dodawanych sekcjach (?)
 * 3) Relocations:
 *     - r_offset -> to nie powinno ulec zmianie, bo to przesunięcie względem początku sekcji
 * 4) Symbols:
 *     (nothing here)
 * */
            size_t offset = sizeof(Elf32_Ehdr);
            size_t i = 0;
            for (auto const& section: sections) {
                // alignment check
                section->size();
                section->align_offset(offset);
//                printf("Section %lu: aligned offset to %lu, requested %u\n", i++, offset, section->header.sh_addralign);

                // set section data offset
                section->set_offset(offset);

                // increase
//                printf("Section %lu: before %lx, size: %lx, after %lx\n", i++, offset, section->size(), offset + section->size());
                offset += section->size();
//                printf("Increased offset to %lu\n", offset);
            }

            // section headers alignment
                align_offset_to(offset, 8);

            // set section headers offset
            header.e_shoff = offset;
        }

        void Elf32::write_out(std::ofstream& elf_file) const {
            size_t offset = 0;
            header.write_out(elf_file, offset);

            size_t i = 0;
            for (auto const& section: sections) {
//                printf("Section %lu: ", i++);
                section->write_out_data(elf_file, offset);
//                printf("Section %lu: before %lx, size: %lx, after %lx\n", i - 1, offset, section->size(), offset + section->size());
                offset += section->size();
            }

            i = 0;
            std::cout << "\nWriting headers:\n";
            for (auto const& section: sections) {
//                printf("Section %lu: wrote header to %lx\n", i++, offset);
                section->write_out_header(elf_file, offset);
            }
        }
    }
#undef write_from_field
}

int main4() {
    std::ifstream func_stream;
    func_stream.exceptions(/*std::ifstream::eofbit | *//*std::ifstream::failbit | */std::ifstream::badbit);
    func_stream.open(func_file_name, std::ifstream::in);

    converter::func_spec::Functions functions{func_stream};
    functions.print_one("f");
    functions.print();

    func_stream.close();
    return 0;
}

int main(int argc, char const* argv[]) {
    if (argc != 4) {
        std::cerr << "Wrong number of arguments.\n";
        return 1;
    }

    char const* elf64_file_name = argv[1];
    char const* functions_file_name = argv[2];
    char const* elf32_file_name = argv[3];

    std::ifstream func_stream;
    func_stream.exceptions(std::ifstream::badbit);
    func_stream.open(functions_file_name, std::ifstream::in);

    std::ifstream elf_istream;
    elf_istream.exceptions(std::ifstream::badbit);
    elf_istream.open(elf64_file_name, std::ifstream::in | std::ifstream::binary);

    std::ofstream elf_ostream;
    elf_ostream.exceptions(/*std::ifstream::eofbit | *//*std::ifstream::failbit | */std::ifstream::badbit);
    elf_ostream.open(elf32_file_name, std::ifstream::out | std::ifstream::binary);

//    std::ofstream elf_copy_stream;
//    elf_copy_stream.open(elf_copy_name, std::ofstream::out | std::ofstream::binary);

//    std::copy(std::istreambuf_iterator<char>(elf_istream), std::istreambuf_iterator<char>(),
//              std::ostreambuf_iterator<char>(elf_copy_stream));

    try {
        converter::func_spec::Functions functions{func_stream};
        functions.print();
        std::cout << "\n\n#############################\n\n";

        converter::Elf64 elf64{elf_istream};

        converter::Elf32 elf32{elf64, functions};

        std::cout << "\nWriting ELF32 out.\n";
        elf32.write_out(elf_ostream);

    } catch (std::ifstream::failure const&) {
        std::cerr << "Error when processing file: read error or unexpected EOF.\n";
        return 1;
    } catch (converter::UnsupportedFileContent const& e) {
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