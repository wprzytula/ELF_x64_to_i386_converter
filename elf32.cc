#include "converter.h"
#include "cassert"

#include <iostream>
#include <optional>
#include <map>

namespace converter::elf32 {
    namespace {
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
    }

    Header32::Header32(elf64::Header64 const& header64) : Elf32_Ehdr{} {
        std::copy(std::begin(header64.e_ident), std::end(header64.e_ident), std::begin(e_ident));
        e_ident[EI_CLASS] = ELFCLASS32;
        e_type = header64.e_type; // ET_REL
        e_machine = EM_386;
        e_version = EV_CURRENT;
        e_entry = header64.e_entry;
        e_phoff = 0;
        e_shoff = header64.e_shoff;
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
        write_from_field(elf_stream, *this);
        offset += size();
    }

    Rela32::Rela32(elf64::Rela64 const& rela64) : Elf32_Rela{} {
        r_offset = rela64.r_offset;

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

    Rel32 Rel32::thunk_self_ref(Elf32_Addr const offset, Elf32_Word const self_symbol_idx) {
        printf("Constructing Rel32: offset=%u, type=self, symbol_idx=%u\n", offset, self_symbol_idx);
        return Rel32{offset, R_386_32, self_symbol_idx};
    }

    Rel32 Rel32::func_ref(Elf32_Addr const offset, Elf32_Word const func_symbol_idx) {
        printf("Constructing Rel32: offset=%u, type=func, symbol_idx=%u\n", offset, func_symbol_idx);
        return Rel32{offset, R_386_PC32, func_symbol_idx};
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

    Symbol32::Symbol32(Symbol32 const& symbol, Elf32_Word const type, Elf32_Word const binding,
                       Elf32_Word const thunk_section_idx) : Elf32_Sym{} {
        st_name = symbol.st_name;
        st_value = symbol.st_value;
        st_size = 0; // for now;
        st_shndx = thunk_section_idx;
        st_other = st_other;
        st_info = ELF32_ST_INFO(binding, type);
    }

    Symbol32 Symbol32::global_stub(Symbol32 const& local_symbol, Elf32_Word thunkin_section_idx) {
        return Symbol32{local_symbol, STT_FUNC, STB_GLOBAL, thunkin_section_idx};
    }

    Symbol32 Symbol32::global_ref(Symbol32 const& global_symbol) {
        return Symbol32{global_symbol, STT_NOTYPE, STB_GLOBAL, 0 /* UNDEFINED section index */};
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

    Symbol32 Symbol32::for_section(Section32 const& section, Elf32_Word const section_idx, Elf32_Word const section_name_idx) {
        return Symbol32{section, section_idx, section_name_idx};
    }

    Thunk::Thunk(stubs::Stub stub, size_t const thunk_symbol_idx, size_t const func_symbol_idx)
        : code{std::move(stub.code)} {
        for (auto const pre_rel32 : stub.relocations) {
            Rel32 rel = pre_rel32.local_symbol
                        ? Rel32::func_ref(pre_rel32.offset, func_symbol_idx)
                        : Rel32::thunk_self_ref(pre_rel32.offset, thunk_symbol_idx);
            *reinterpret_cast<Elf32_Word*>(code.data() + rel.r_offset) = pre_rel32.addend;
            relocations.push_back(rel);
        }
    }

    void Thunk::lay_to_sections(Section32Thunk& thunk_section, Section32Rel& rel_thunk_section) {
        auto thunk_pos = thunk_section.add_thunk(std::move(code));
        for (auto& rel: relocations) {
            rel.r_offset += thunk_pos;
            rel_thunk_section.relocations.push_back(rel);
        }
    }

    Thunkin::Thunkin(func_spec::Function const& func_spec, size_t const thunk_symbol_idx, size_t const local_symbol_idx)
        : Thunk{stubs::Stub::stubin(func_spec), thunk_symbol_idx, local_symbol_idx} {}

    Thunkout::Thunkout(func_spec::Function const& func_spec, size_t const thunk_symbol_idx, size_t const global_symbol_idx)
        : Thunk{stubs::Stub::stubout(func_spec), thunk_symbol_idx, global_symbol_idx} {}

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

    void Section32WithGrowableData::write_out_data(std::ofstream& elf_file, size_t& offset) {
        Section32::write_out_data(elf_file, offset);
        elf_file.write(reinterpret_cast<char const*>(data.data()), static_cast<ssize_t>(size()));
    }

    Section32Strtab::Section32Strtab(elf64::Section64Strtab const& strtab64)
            : Section32WithGrowableData{strtab64} {}

    Elf32_Word Section32Strtab::append_name(std::string const& name) {
        printf("Appending name %s to strtab.\n", name.c_str());
        for (char c: name) {
            data.push_back(c);
        }
        data.push_back('\0');

        Elf32_Word const pos = header.sh_size;
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
        if (ELF32_ST_BIND(symbol.st_info) == STB_LOCAL) {
            header.sh_info = pos + 1;
        }
        return pos;
    }

    Elf32_Word Section32Symtab::register_section(Section32 const& section, Elf32_Word const section_idx,
                                                 Elf32_Word const section_name_idx) {
        // TODO: add name to shstrtab -> done elsewhere
        return add_symbol(Symbol32::for_section(section, section_idx, section_name_idx));
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
        printf("Making Section32Rel for thunk: %s\n", rel_section_name.c_str());
        Elf32_Word name_idx = strtab.append_name(rel_section_name);

        Elf32_Shdr header{
                .sh_name = name_idx,
                .sh_type = SHT_REL,
                .sh_flags = 0,
                .sh_addr = 0,
                .sh_offset = 0, // so far
                .sh_size = 0, // so far
                .sh_link = symtab_idx,
                .sh_info = thunk_section_idx,
                .sh_addralign = 1,
                .sh_entsize = sizeof(Elf32_Rel),
        };

        return Section32Rel{header};
    }

    size_t Section32Thunk::add_thunk(std::vector<uint8_t> stub) {
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

        std::cout << "\nConverting symbols.\n";

        // Symbols conversions:
        convert_symbols(functions);

        std::cout << "\nCorrecting offsets.\n";
        correct_offsets();
    }

    void Elf32::add_new_section(std::unique_ptr<Section32> section) {
        sections.push_back(std::move(section));
        ++header.e_shnum;
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
        struct Indices {
            Elf32_Word thunk;
            Elf32_Word rel_thunk;
            Elf32_Word symbol;
        };

        Elf32_Word text_section_idx = 0;
        for (Elf32_Word i = 0; i < sections.size(); ++i) {
            if (sections[i]->header.sh_type == SHT_PROGBITS && sections[i]->header.sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
                text_section_idx = i;
            }
        }
        if (text_section_idx == 0) throw UnsupportedFileContent{"No .text section!"};

        try {
            std::vector<std::optional<Indices>> thunkin_section_idcs{sections.size()};
            std::vector<std::optional<Indices>> thunkout_section_idcs{sections.size()};
            std::map<size_t, std::vector<size_t>> symbols_to_be_sized;

            for (Elf32_Word symtab_idx = 0; symtab_idx < sections.size(); ++symtab_idx) { // looking for symtabs
                std::unique_ptr<Section32> const& section = sections[symtab_idx];
                auto* symtab = dynamic_cast<Section32Symtab*>(section.get());

                if (symtab != nullptr) { // found SYMTAB
                    symbols_to_be_sized[symtab_idx] = {};
                    auto symbols_size_before_conversion = symtab->symbols.size();

                    for (Elf32_Word symbol_idx = 0; symbol_idx < symbols_size_before_conversion; ++symbol_idx) {
                        Symbol32& symbol = symtab->symbols[symbol_idx];
                        auto bind = ELF32_ST_BIND(symbol.st_info);
                        auto type = ELF32_ST_TYPE(symbol.st_info);
                        auto& symstrtab = dynamic_cast<Section32Strtab&>(*sections[symtab->strtab()]);
                        auto name = symstrtab.name_of(symbol.st_name);

                        if (bind == STB_GLOBAL && type == STT_FUNC) {
                            // Case 1.
                            std::cout << "Detected global binding function:\n\tname: " << name << "\n";

                            Section32& thunked_section = *sections[symbol.st_shndx];
                            auto const& thunked_section_name = shstrtab->name_of(sections[symbol.st_shndx]->header.sh_name);

                            // - change original symbols from GLOBAL to LOCAL.
                            symbol.st_info = ELF32_ST_INFO(STB_LOCAL, STT_FUNC);

                            if (functions.find(name) == functions.end()) {
                                throw UnsupportedFileContent{std::string{"Local function "} + name + " not present in function file."};
                            }
                            auto const& func_spec = *functions.find(name);

                            // - create thunkin section if not exist, as well as corresponding rel.thunkin
                            Elf32_Word thunkin_section_idx;
                            Elf32_Word thunkin_section_symbol_idx;
                            if (!thunkin_section_idcs[symbol.related_section_idx()].has_value()) {

                                thunkin_section_idx = sections.size();
                                Elf32_Word const rel_thunkin_section_idx = thunkin_section_idx + 1;

                                auto thunkin_section = std::make_unique<Section32Thunkin>(thunked_section, symtab_idx, *shstrtab);
                                auto thunkin_section_name_idx = symstrtab.append_name(thunked_section_name + std::string{".thunkin"});
                                thunkin_section_symbol_idx = symtab->register_section(*thunkin_section, thunkin_section_idx,
                                                                                   thunkin_section_name_idx);

                                thunkin_section_idcs[symbol.related_section_idx()] = std::make_optional<>(
                                        Indices{.thunk=thunkin_section_idx, .rel_thunk=rel_thunkin_section_idx, .symbol=thunkin_section_symbol_idx});

                                add_new_section(std::move(thunkin_section));

                                auto rel_thunkin_section = std::make_unique<Section32Rel>(Section32Rel::make_for_thunk(
                                        dynamic_cast<Section32Thunk&>(*sections[thunkin_section_idx]),
                                        thunkin_section_idx, *shstrtab, symtab_idx)
                                );

                                add_new_section(std::move(rel_thunkin_section));
                            } else {
                                auto indices = thunkin_section_idcs[symbol.related_section_idx()].value();
                                thunkin_section_idx = indices.thunk;
                                thunkin_section_symbol_idx = indices.symbol;
                            }

                            /* - add new global symbols: trampolines that change mode from 32-bit to 64-bit,
                             *   call original function and change mode back to 32-bit. */

                            // add global symbol
                            auto global_symbol_idx = symtab->add_symbol(Symbol32::global_stub(symbol, thunkin_section_idx));
                            symbols_to_be_sized[symtab_idx].push_back(global_symbol_idx);

                            // just get references to thunk & thunk rel sections
                            auto& thunkin_section = dynamic_cast<Section32Thunkin&>(
                                    *sections[thunkin_section_idcs[symbol.related_section_idx()]->thunk]);
                            auto& rel_thunkin_section = dynamic_cast<Section32Rel&>(
                                    *sections[thunkin_section_idcs[symbol.related_section_idx()]->rel_thunk]);

                            // build thunkin
                            Thunkin thunkin{func_spec, thunkin_section_symbol_idx, symbol_idx};

                            // - add new relocations that point from stubs to original symbols (e.g. thunk -> f)
                            // lay thunk to sections
                            thunkin.lay_to_sections(thunkin_section, rel_thunkin_section);

                            /* Case 1: DONE? */

                        } else if (bind == STB_GLOBAL && type == STT_NOTYPE && functions.find(name) != functions.end()) {
                            // Case 2.
                            std::cout << "Detected undefined binding to function:\n\tname: " << name << "\n";

                            auto const& func_spec = *functions.find(name);
                            if (functions.find(name) != functions.end()) {
                                // the symbol is an external function, so we shall:
                                // - change undefined global symbols into local symbols, pointing at stubs
                                //   that change mode to 32-bit, call global symbols and come back to 64-bit.

                                Section32& thunked_section = *sections[text_section_idx];
                                auto const& thunked_section_name = shstrtab->name_of(sections[text_section_idx]->header.sh_name);

                                // - create thunkout section if not exist, as well as corresponding rel.thunkout
                                Elf32_Word thunkout_section_idx;
                                Elf32_Word thunkout_section_symbol_idx;
                                if (!thunkout_section_idcs[text_section_idx].has_value()) {

                                    thunkout_section_idx = sections.size();
                                    Elf32_Word const rel_thunkout_section_idx = thunkout_section_idx + 1;

                                    auto thunkout_section = std::make_unique<Section32Thunkout>(thunked_section, symtab_idx, *shstrtab);

                                    auto thunkout_section_name_idx = symstrtab.append_name(thunked_section_name + std::string{".thunkout"});
                                    thunkout_section_symbol_idx = symtab->register_section(*thunkout_section, thunkout_section_idx,
                                                                                       thunkout_section_name_idx);

                                    thunkout_section_idcs[text_section_idx] = std::make_optional<>(
                                            Indices{.thunk=thunkout_section_idx, .rel_thunk=rel_thunkout_section_idx, .symbol=thunkout_section_symbol_idx});

                                    add_new_section(std::move(thunkout_section));

                                    auto rel_thunkout_section = std::make_unique<Section32Rel>(Section32Rel::make_for_thunk(
                                            dynamic_cast<Section32Thunk&>(*sections[thunkout_section_idx]),
                                            thunkout_section_idx, *shstrtab, symtab_idx)
                                    );

                                    add_new_section(std::move(rel_thunkout_section));
                                } else {
                                    auto indices = thunkout_section_idcs[text_section_idx].value();
                                    thunkout_section_idx = indices.thunk;
                                    thunkout_section_symbol_idx = indices.symbol;
                                }

                                // add new undefined global symbol, mimicking the altered one.
                                auto global_symbol_idx = symtab->add_symbol(Symbol32::global_ref(symbol));

                                // alter the former symbol: make it local and pointing to .thunkout section.
                                symbol.st_info = ELF32_ST_INFO(STB_LOCAL, type);
                                symbol.st_shndx = thunkout_section_idx;
                                symbols_to_be_sized[symtab_idx].push_back(symbol_idx);

                                // just get references to thunk & thunk rel sections
                                auto& thunkout_section = dynamic_cast<Section32Thunkout&>(
                                        *sections[thunkout_section_idcs[text_section_idx]->thunk]);
                                auto& rel_thunkout_section = dynamic_cast<Section32Rel&>(
                                        *sections[thunkout_section_idcs[text_section_idx]->rel_thunk]);

                                // construct and insert a stub.
                                Thunkout thunkout{func_spec, thunkout_section_symbol_idx, global_symbol_idx};
                                thunkout.lay_to_sections(thunkout_section, rel_thunkout_section);
                            }
                        }
                        size_t idx = symbol.st_shndx;
                        /*std::cout << "Symbol: <" << symstrtab.name_of(symbol.st_name) << ">,\t"
                                  "relevant to section no=" << symbol.st_shndx <<*//* " : " <<
                                  (symbol.special_section ? "" : section->name(*secstrtab) )
                                  <<*//* '\n';*/
                    }
                }
            }

            /* New symbols size correction */
            for (auto& [symtab_idx, symbols]: symbols_to_be_sized) {
                auto& symtab = dynamic_cast<Section32Symtab&>(*sections[symtab_idx]);
                for (auto const symbol_idx: symbols) {
                    auto& symbol = symtab.symbols[symbol_idx];
                    auto& sized_section = *sections[symbol.st_shndx];
                    symbol.st_size = sized_section.size();
                }
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
//                printf("Section %lu: before %lx, size: %lx, after %lx\n", i++, offset, section->size(), offset + section->size());
            offset += section->size();
            assert(offset == elf_file.tellp());
        }

        i = 0;
//            std::cout << "\nWriting headers:\n";
        for (auto const& section: sections) {
//                printf("Section %lu: wrote header to %lx\n", i++, offset);
            section->write_out_header(elf_file, offset);
            assert(offset == elf_file.tellp());
        }
    }
}