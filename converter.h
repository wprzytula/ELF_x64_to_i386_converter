#ifndef ZAD1_ELF_CONVERTER_CONVERTER_H
#define ZAD1_ELF_CONVERTER_CONVERTER_H

#include <elf.h>
#include <fstream>
#include <memory>
#include <utility>
#include <vector>
#include <set>

namespace converter {
    namespace func_spec {

        enum struct ArgType {
            int_t,
            uint_t,
            long_t,
            ulong_t,
            longlong_t,
            ulonglong_t,
            ptr_t,
        };

        struct Arg {
            using enum ArgType;
            ArgType type;

            static ArgType parse_arg_type(char const* argtype);

            Arg(const std::string& argtype) : type{parse_arg_type(argtype.c_str())} {}

            [[nodiscard]] bool is_signed() const {
                return type == int_t || type == long_t || type == longlong_t;
            }

            [[nodiscard]] size_t bits_32() const;

            [[nodiscard]] size_t bits_64() const;
        };

        struct Ret {
            std::optional<ArgType> const ret;

            static std::optional<ArgType> parse_ret_type(char const* argtype);

            explicit Ret(char const* argtype) : ret{parse_ret_type(argtype)} {}
        };

        struct Function {
            std::string const name;
            Ret const ret;
            std::vector<Arg> const args;

            explicit Function(std::string name, Ret ret, std::vector<Arg> args) : name{std::move(name)}, ret{std::move(ret)}, args{std::move(args)} {}
            static Function from_line_decl(std::string& decl);

            struct order {
                using is_transparent = void;
                bool operator()(Function const& x, Function const& y) const {
                    return x.name < y.name;
                }

                bool operator()(std::string const& x, Function const& y) const {
                    return x < y.name;
                }

                bool operator()(Function const& x, std::string const& y) const {
                    return x.name < y;
                }
            };
        };

        struct Functions {
            std::set<Function, Function::order> functions;

            explicit Functions(std::ifstream& func_stream);

            [[nodiscard]] decltype(functions.find("")) find(std::string const& name) const {
                return functions.find(name);
            }

            [[nodiscard]] decltype(functions.end()) end() const {
                return functions.end();
            }

//          debug only
            void print() {
                for (auto const& function : functions) {
                    printf("Function: ret=%d, name=%s, args:",
                           function.ret.ret.has_value() ? static_cast<int>(function.ret.ret.value()) : -1,
                           function.name.c_str()
                    );
                    for (auto const& arg: function.args) {
                        printf(" %d", static_cast<int>(arg.type));
                    }
                    putchar('\n');
                }
            }

            void print_one(std::string const& name) {
                auto const& function = *functions.find(name);
                printf("Function: ret=%d, name=%s, args:",
                       function.ret.ret.has_value() ? static_cast<int>(function.ret.ret.value()) : -1,
                       function.name.c_str()
                );
                for (auto const& arg: function.args) {
                    printf(" %d", static_cast<int>(arg.type));
                }
                putchar('\n');
            }
        };
    }

    namespace elf64 {
        struct Elf64;
        struct Header64;
        struct Rela64;
        struct Symbol64;
        struct Section64;
        struct Section64WithoutData;
        struct Section64WithGenericData;
        struct Section64Strtab;
        struct Section64Symtab;
        struct Section64Rela;
    }

    namespace elf32 {
        struct Section32;
        struct Section32WithoutData;
        struct Section32WithGenericData;
        struct Section32Symtab;
        struct Section32Strtab;
        struct Section32Rel;
        struct Section32Rela;

        using sections32_t = std::vector<std::unique_ptr<Section32>>;

        struct Header32 : Elf32_Ehdr {
            explicit Header32(elf64::Header64 const& header64);

            [[nodiscard]] static constexpr size_t size() {
                return sizeof(Elf32_Ehdr);
            }

            void write_out(std::ofstream& ofstream, size_t& offset) const;
        };

        struct Rela32 : Elf32_Rela {
            explicit Rela32(elf64::Rela64 const& rela64);

//            void write_out(std::ofstream& ofstream, size_t& i) const; // FIXME: remove
        };

        struct Rel32 : Elf32_Rel {
            explicit Rel32(Rela32 const& rela32, Section32Rela const& section32_rela, sections32_t& sections);

            void write_out(std::ofstream& elf_file, size_t& i) const;
        };

        struct Symbol32 : Elf32_Sym {
            explicit Symbol32(elf64::Symbol64 const& symbol64);

            void write_out(std::ofstream& elf_file, size_t& i) const;
        };

        struct Section32 {
            Elf32_Shdr header{};

            explicit Section32(elf64::Section64 const &section64);
            explicit Section32(Elf32_Shdr const& header);

            Section32(Section32&& section) = default;
            virtual ~Section32() = default;

            [[nodiscard]] virtual std::string to_string() const {
                return "Section32 generic";
            }

            [[nodiscard]] char const* type() const;

            static std::unique_ptr<Section32> parse_section(elf64::Section64 const&, Header32 const& elf_header);

            [[nodiscard]] size_t size() const {
                return header.sh_size;
            }

            [[nodiscard]] size_t alignment() const {
                return header.sh_addralign == 0 ? 1 : header.sh_addralign;
            }

            void set_offset(Elf32_Addr const offset) {
                header.sh_offset = offset;
            }

            virtual void write_out_data(std::ofstream& elf_file, size_t& offset) const;

            void write_out_header(std::ofstream& elf_file, size_t& offset) const;

            void align_offset(size_t& offset) const;

            void align_offset(size_t& offset, std::ofstream& elf_file) const;
        };

        struct Section32WithoutData : public Section32 {
            Section32WithoutData(Section32WithoutData&& section) = default;
            ~Section32WithoutData() override = default;

            explicit Section32WithoutData(elf64::Section64WithoutData const& section64);

            [[nodiscard]] std::string to_string() const override {
                return "Section32WithoutData";
            }
        };

        struct Section32WithGenericData : public Section32 {
            std::unique_ptr<char[]> data;

            ~Section32WithGenericData() override = default;
            Section32WithGenericData(Section32WithGenericData&& section) = default;

            explicit Section32WithGenericData(elf64::Section64WithGenericData const& section64);

            void write_out_data(std::ofstream& elf_file, size_t& offset) const override;

            [[nodiscard]] std::string to_string() const override {
                return "Section32WithGenericData";
            }
        };

        struct Section32Strtab final : public Section32WithGenericData {
            ~Section32Strtab() override = default;
            Section32Strtab(Section32Strtab&& section) = default;

            [[nodiscard]] char const* name_of(Elf32_Word i) const {
                return &data.get()[i];
            }

            [[nodiscard]] std::string to_string() const override {
                return "Section32Strtab";
            }
        };

        struct Section32Symtab final : public Section32 {
            std::vector<Symbol32> symbols;

            ~Section32Symtab() override = default;
            Section32Symtab(Section32Symtab&& section) = default;

            explicit Section32Symtab(elf64::Section64Symtab const& symtab);

            [[nodiscard]] std::string to_string() const override {
                return "Section32Symtab";
            }

            void write_out_data(std::ofstream& elf_file, size_t& offset) const override;
        };

        struct Section32Rela final : public Section32 {
            std::vector<Rela32> relocations;

            ~Section32Rela() override = default;
            Section32Rela(Section32Rela&& section) = default;

            explicit Section32Rela(elf64::Section64Rela const& rela64);

            [[nodiscard]] std::string to_string() const override {
                return "Section32Rela";
            }

//            void write_out_data(std::ofstream& elf_file, size_t& offset) const override; // FIXME: remove
        };

        struct Section32Rel final : public Section32 {
            std::vector<Rel32> relocations;

            ~Section32Rel() override = default;
            Section32Rel(Section32Rel&& section) = default;

            [[nodiscard]] std::string to_string() const override {
                return "Section32Rel";
            }

            explicit Section32Rel(Section32Rela const& rela32, sections32_t& sections);

            void write_out_data(std::ofstream& elf_file, size_t& offset) const override;
        };

        struct Elf32 {
            Header32 header;
            sections32_t sections;

            explicit Elf32(elf64::Elf64 const& elf64, func_spec::Functions const& functions);

            void convert_relocations();

            void convert_symbols(func_spec::Functions const& functions);

            void correct_offsets();

            void write_out(std::ofstream& elf_file) const;
        };
    }

    namespace elf64 {
        struct Header64 : Elf64_Ehdr {
            explicit Header64(std::ifstream &elf_stream);
        };

        struct Symbol64 : Elf64_Sym {
            bool special_section;
            explicit Symbol64(std::ifstream &elf_stream);
        };

        struct Rela64 : Elf64_Rela {
            explicit Rela64(std::ifstream &elf_stream);
        };

        struct Section64 {
            Elf64_Shdr header{};

            explicit Section64(std::ifstream &elf_stream);

            Section64(Section64&& section) = default;
            virtual ~Section64() = default;

            [[nodiscard]] char const* name(Section64Strtab const &str_table) const;
            static std::unique_ptr<Section64> parse_section(std::ifstream& elf_stream, Elf64_Ehdr const& elf_header);
        };

        struct Section64WithoutData : public Section64 {
            explicit Section64WithoutData(Section64 section64) : Section64(std::move(section64)) {}
            ~Section64WithoutData() override = default;
            Section64WithoutData(Section64WithoutData&&) = default;
        };

        struct Section64WithGenericData : public Section64 {
            std::unique_ptr<char[]> data;

            explicit Section64WithGenericData(Section64 section64, std::ifstream& elf_stream);

            ~Section64WithGenericData() override = default;
            Section64WithGenericData(Section64WithGenericData&&) = default;

        };

        struct Section64Strtab final : public Section64WithGenericData {
            explicit Section64Strtab(Section64WithGenericData section64_with_data) : Section64WithGenericData(std::move(section64_with_data)) {}
            ~Section64Strtab() final = default;
            Section64Strtab(Section64Strtab&&) = default;

            [[nodiscard]] char const* name_of(Elf64_Word i) const {
                return &data.get()[i];
            }
        };

        struct Section64Rela final : public Section64 {
            std::vector<Rela64> relocations;

            explicit Section64Rela(Section64 section64, std::ifstream& elf_stream);
            ~Section64Rela() final = default;
            Section64Rela(Section64Rela&&) = default;
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

    using elf64::Elf64;
    using elf32::Elf32;
}

#endif //ZAD1_ELF_CONVERTER_CONVERTER_H
