#include <elf.h>
#include <iostream>
#include <fstream>
#include <iterator>
#include <optional>
#include <cstring>
#include <vector>
#include <memory>

constexpr char const* elf_file_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/no_x64.o";
constexpr char const* elf_copy_name = "/home/xps15/Studia/Sem6/ZSO/Laby/Zad1_ELF_converter/tests/copy";

class NonsupportedFileContent : public std::exception {};

#define read_to_field(elf_stream, field) elf_stream.read(reinterpret_cast<char*>(&field), sizeof(field))

std::optional<Elf64_Ehdr> parse_header(std::ifstream& elf_stream) {
    Elf64_Ehdr header;

    read_to_field(elf_stream, header.e_ident);
    if (strncmp(reinterpret_cast<char const *>(header.e_ident), ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_OSABI] != ELFOSABI_SYSV) {
        std::cerr << "Can only convert x64 object files conforming to System V ABI.\n";
        return {};
    }

    read_to_field(elf_stream, header.e_type);
    if (header.e_type != ET_REL) {
        std::cerr << "Can only convert ET_REL executable files.\n";
        return {};
    }

    read_to_field(elf_stream, header.e_machine);
    if (header.e_machine != EM_X86_64) {
        std::cerr << "Can only convert x86-64 arch executable files.\n";
        return {};
    }

    read_to_field(elf_stream, header.e_version);
    read_to_field(elf_stream, header.e_entry);
    read_to_field(elf_stream, header.e_phoff);
    read_to_field(elf_stream, header.e_shoff);
    read_to_field(elf_stream, header.e_flags);
    read_to_field(elf_stream, header.e_ehsize);
    read_to_field(elf_stream, header.e_phentsize);
    read_to_field(elf_stream, header.e_phnum);
    read_to_field(elf_stream, header.e_shentsize);
    read_to_field(elf_stream, header.e_shnum);
    read_to_field(elf_stream, header.e_shstrndx);

    return std::make_optional<>(header);
}

struct Section64 {
    Elf64_Shdr header{};
    std::optional<std::unique_ptr<char[]>> data;

    explicit Section64(std::ifstream& elf_stream, Elf64_Ehdr const& elf_header) {
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

        if (header.sh_size) {
            std::cout << "Data found in section, at " << header.sh_offset << '\n';
            data = std::make_optional(std::make_unique<char[]>(header.sh_size));
            elf_stream.seekg(static_cast<ssize_t>(header.sh_offset));
            elf_stream.read(data.value().get(), static_cast<ssize_t>(header.sh_size));
        }
    }

    [[nodiscard]] char const* name(Section64 const& str_table) const {
        return &str_table.data.value().get()[header.sh_name];
    }
};

struct Elf64 {
    Elf64_Ehdr header{};
    std::vector<Section64> sections;
    explicit Elf64(std::ifstream& elf_stream) {
        std::optional<Elf64_Ehdr> const elf_header_opt = parse_header(elf_stream);
        if (!elf_header_opt.has_value()) {
            throw NonsupportedFileContent();
        }

        header = *elf_header_opt;

        for (size_t i = 0; i < header.e_shnum; ++i) {
            elf_stream.seekg(static_cast<ssize_t>(header.e_shoff + i * header.e_shentsize));
            sections.emplace_back(elf_stream, header);
        }

        for (Section64 const& section: sections) {
            std::cout << section.name(sections[header.e_shstrndx]) << '\n';
        }
    }
};


int main() {
    std::ifstream elf_stream;
    elf_stream.exceptions(/*std::ifstream::eofbit | *//*std::ifstream::failbit | */std::ifstream::badbit);
    elf_stream.open(elf_file_name, std::ifstream::in | std::ifstream::binary);

    std::ofstream elf_copy_stream;
    elf_copy_stream.open(elf_copy_name, std::ofstream::out | std::ofstream::binary);

//    std::copy(std::istreambuf_iterator<char>(elf_stream), std::istreambuf_iterator<char>(),
//              std::ostreambuf_iterator<char>(elf_copy_stream));

    try {
        Elf64{elf_stream};
    } catch (std::ifstream::failure&) {
        std::cerr << "Error when processing file: read error or unexpected EOF.\n";
        return 1;
    } catch (NonsupportedFileContent&) {
        std::cerr << "Nonsupported file content was found in the ELF.\n";
    }

    elf_stream.close();
    elf_copy_stream.close();

    return 0;
}
