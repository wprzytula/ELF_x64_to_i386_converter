#ifndef ZAD1_ELF_CONVERTER_CONVERTER_H
#define ZAD1_ELF_CONVERTER_CONVERTER_H

#include <elf.h>
#include <fstream>
#include <memory>
#include <utility>
#include <vector>
#include <set>
#include <deque>
#include <optional>

#define read_to_field(ifstream, field) ifstream.read(reinterpret_cast<char*>(&(field)), sizeof(field))
#define write_from_field(elf_stream, field) elf_stream.write(reinterpret_cast<char const*>(&(field)), sizeof(field))

namespace converter {
    struct UnsupportedFileContent : public std::invalid_argument {
        explicit UnsupportedFileContent(std::string const& what) : std::invalid_argument(what) {}
    };

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

            Arg(const std::string& argtype) : type{parse_arg_type(argtype.c_str())} {} // NOLINT(google-explicit-constructor)

            [[nodiscard]] bool is_signed() const {
                return type == int_t || type == long_t || type == longlong_t;
            }

            [[nodiscard]] size_t bytes_32() const;

            [[nodiscard]] size_t bytes_64() const;

            [[nodiscard]] bool size_differs() const;
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

    namespace stubs {
        struct ThunkPreRel32 {
            bool local_symbol;
            Elf32_Addr offset;
            Elf32_Sword addend;

            explicit ThunkPreRel32(Elf64_Rela const& rela64);
        };

        struct Stub {
            std::vector<uint8_t> text_code;
            std::vector<uint8_t> rodata_code;
            std::vector<ThunkPreRel32> text_relocations;
            std::vector<ThunkPreRel32> rodata_relocations;

            Stub(Stub const&) = delete;
            Stub(Stub&&) = default;
        private:
            explicit Stub(std::ifstream& stub_elf);
            static Stub from_assembly(std::string const& assembly);
        public:
            static std::string asmin(func_spec::Function const& func_spec);
            static std::string asmout(func_spec::Function const& func_spec);
            static Stub stubin(func_spec::Function const& func_spec);
            static Stub stubout(func_spec::Function const& func_spec);
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
        struct Section32WithFixedSizeData;
        struct Section32Symtab;
        struct Section32Strtab;
        struct Section32Rel;
        struct Section32Rela;
        struct Section32Thunk;
        struct Section32Thunkin;
        struct Section32Thunkout;

        // deque prevents iterator invalidation after pushing to the back
        using sections32_t = std::deque<std::unique_ptr<Section32>>;

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
        private:
            explicit Rel32(Elf32_Addr offset, Elf32_Word type, Elf32_Word symbol_idx);
        public:
            explicit Rel32(Rela32 const& rela32, Section32Rela const& section32_rela, sections32_t& sections);

            static Rel32 thunk_self_ref(Elf32_Addr offset, Elf32_Word self_symbol_idx);

            static Rel32 func_ref(Elf32_Addr offset, Elf32_Word func_symbol_idx);

            void write_out(std::ofstream& elf_file, size_t& i) const;
        };

        struct Symbol32 : Elf32_Sym {
        private:
            explicit Symbol32(Symbol32 const& symbol, Elf32_Word type, Elf32_Word binding,
                              Elf32_Word thunk_section_idx);
            explicit Symbol32(Section32 const& section, Elf32_Word section_idx,
                              Elf32_Word section_name_idx);
        public:
            explicit Symbol32(elf64::Symbol64 const& symbol64);

            [[nodiscard]] decltype(st_shndx) related_section_idx() const {
                return st_shndx;
            }

            static Symbol32 global_stub(Symbol32 const& local_symbol, Elf32_Word thunkin_section_idx);

            static Symbol32 global_ref(Symbol32 const& global_symbol);

            static Symbol32 for_section(Section32 const& section, Elf32_Word section_idx, Elf32_Word section_name_idx);

            void write_out(std::ofstream& elf_file, size_t& i) const;
        };

        struct Thunk {
            std::vector<uint8_t> code;
            std::vector<Rel32> relocations;

            explicit Thunk(stubs::Stub stub, size_t thunk_symbol_idx, size_t func_symbol_idx);

            void lay_to_sections(Section32Thunk& thunk_section, Section32Rel& rel_thunk_section, Symbol32& thunk_symbol);
        };

        struct Thunkin final : public Thunk {
            explicit Thunkin(func_spec::Function const& func_spec, size_t thunk_symbol_idx, size_t local_symbol_idx);
        };

        struct Thunkout final : public Thunk {
            explicit Thunkout(func_spec::Function const& func_spec, size_t thunk_symbol_idx, size_t global_symbol_idx);
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

            static std::unique_ptr<Section32> convert_section(elf64::Section64 const& section64, Header32 const& elf_header);

            [[nodiscard]] virtual size_t size() = 0;

            [[nodiscard]] size_t alignment() const {
                return header.sh_addralign == 0 ? 1 : header.sh_addralign;
            }

            void set_offset(Elf32_Addr const offset) {
                header.sh_offset = offset;
            }

            virtual void write_out_data(std::ofstream& elf_file, size_t& offset);

            void write_out_header(std::ofstream& elf_file, size_t& offset) const;

            void align_offset(size_t& offset) const;

            void align_offset(size_t& offset, std::ofstream& elf_file) const;
        };

        struct Section32WithoutData : public Section32 {
            Section32WithoutData(Section32WithoutData&& section) = default;
            ~Section32WithoutData() override = default;

            explicit Section32WithoutData(elf64::Section64WithoutData const& section64);

            size_t size() override;

            [[nodiscard]] std::string to_string() const override {
                return "Section32WithoutData";
            }
        };

        struct Section32WithFixedSizeData : public Section32 {
            std::unique_ptr<char[]> data;

            ~Section32WithFixedSizeData() override = default;
            Section32WithFixedSizeData(Section32WithFixedSizeData&& section) = default;

            explicit Section32WithFixedSizeData(elf64::Section64WithGenericData const& section64);

            size_t size() override;

            void write_out_data(std::ofstream& elf_file, size_t& offset) override;

            [[nodiscard]] std::string to_string() const override {
                return "Section32WithFixedSizeData";
            }
        };

        struct Section32WithGrowableData : public Section32 {
            std::vector<uint8_t> data;

            ~Section32WithGrowableData() override = default;
            Section32WithGrowableData(Section32WithGrowableData&& section) = default;

            explicit Section32WithGrowableData(Elf32_Shdr const& header);

            explicit Section32WithGrowableData(elf64::Section64WithGenericData const& section64);

            [[nodiscard]] size_t size() override;

            void write_out_data(std::ofstream& elf_file, size_t& offset) override;
        };

        struct Section32Strtab final : public Section32WithGrowableData {
            ~Section32Strtab() override = default;
            Section32Strtab(Section32Strtab&& section) = default;

            explicit Section32Strtab(elf64::Section64Strtab const& strtab64);

            [[nodiscard]] char const* name_of(Elf32_Word i) const {
                return reinterpret_cast<char const*>(data.data() + i);
            }

            [[nodiscard]] Elf32_Word append_name(std::string const& name);

            [[nodiscard]] std::string to_string() const override {
                return "Section32Strtab";
            }
        };

        struct Section32Symtab final : public Section32 {
            std::deque<Symbol32> symbols;

            ~Section32Symtab() override = default;
            Section32Symtab(Section32Symtab&& section) = default;

            explicit Section32Symtab(elf64::Section64Symtab const& symtab);

            [[nodiscard]] decltype(header.sh_link) strtab() const {
                return header.sh_link;
            }

            Elf32_Word add_symbol(Symbol32 symbol);

            Elf32_Word register_section(Section32 const& section, Elf32_Word section_idx, Elf32_Word section_name_idx);

            [[nodiscard]] std::string to_string() const override {
                return "Section32Symtab";
            }

            void write_out_data(std::ofstream& elf_file, size_t& offset) override;

            size_t size() override;
        };

        struct Section32Rela final : public Section32 {
            std::vector<Rela32> relocations;

            ~Section32Rela() override = default;
            Section32Rela(Section32Rela&& section) = default;

            explicit Section32Rela(elf64::Section64Rela const& rela64);

            [[nodiscard]] std::string to_string() const override {
                return "Section32Rela";
            }

            size_t size() override;

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
        private:
            explicit Section32Rel(Elf32_Shdr const& header) : Section32{header} {}
        public:

            static Section32Rel make_for_thunk(const Section32Thunk& thunk_section, Elf32_Word thunk_section_idx,
                                               Section32Strtab& strtab, Elf32_Word symtab_idx);

            void write_out_data(std::ofstream& elf_file, size_t& offset) override;

            size_t size() override;
        };

        /*
         * SectionWithGrowableData -> Strtab, Thunkin, Thunkout
         * */

        struct Section32Thunk : public Section32WithGrowableData {
            ~Section32Thunk() override = default;
            Section32Thunk(Section32Thunk&& section) = default;
        private:
            explicit Section32Thunk(Elf32_Shdr const& header)
                : Section32WithGrowableData{header} {}
        public:

            static Section32Thunk make_thunk(Section32 const& thunked_section, size_t symtab_idx,
                                             Section32Strtab& strtab, std::string const& name);

            [[nodiscard]] size_t add_thunk(std::vector<uint8_t> stub);
        };

        struct Section32Thunkin final : public Section32Thunk {
            ~Section32Thunkin() override = default;
            Section32Thunkin(Section32Thunkin&& section) = default;
            explicit Section32Thunkin(Section32 const& thunked_section, size_t const symtab_idx, Section32Strtab& strtab)
                : Section32Thunk{make_thunk(thunked_section, symtab_idx, strtab, ".thunkin")} {}
        };

        struct Section32Thunkout final : public Section32Thunk {
            ~Section32Thunkout() override = default;
            Section32Thunkout(Section32Thunkout&& section) = default;
            explicit Section32Thunkout(Section32 const& thunked_section, size_t const symtab_idx, Section32Strtab& strtab)
            : Section32Thunk{make_thunk(thunked_section, symtab_idx, strtab, ".thunkout")} {}
        };

        struct Elf32 {
            Header32 header;
            sections32_t sections;
            Section32Strtab*const shstrtab;

            explicit Elf32(elf64::Elf64 const& elf64, func_spec::Functions const& functions);

            void add_new_section(std::unique_ptr<Section32> section);

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
