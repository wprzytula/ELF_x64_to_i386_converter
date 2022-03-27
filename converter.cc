#include <iostream>
#include <fstream>

#include "converter.h"
#include "assemblage.h"

int main(int argc, char const* argv[]) {
    if (argc != 4) {
        std::cerr << "Wrong number of arguments.\n";
        return 1;
    }

    char const* elf64_file_name = argv[1];
    char const* functions_file_name = argv[2];
    char const* output_file_name = argv[3];

    std::ifstream func_stream;
    func_stream.exceptions(std::ifstream::badbit);
    func_stream.open(functions_file_name, std::ifstream::in);

    try {
        converter::func_spec::Functions functions{func_stream};
        functions.print();
        std::cout << "\n\n#############################\n\n";

        converter::assembly::rid_gnu_property(elf64_file_name, output_file_name);

        std::ifstream elf_istream;
        elf_istream.exceptions(std::ifstream::badbit);
        elf_istream.open(output_file_name, std::ifstream::in | std::ifstream::binary);

        converter::Elf64 elf64{elf_istream};
        elf_istream.close();

        converter::Elf32 elf32{elf64, functions};

        std::ofstream elf_ostream;
        elf_ostream.exceptions(std::ifstream::badbit);
        elf_ostream.open(output_file_name, std::ifstream::out | std::ifstream::binary);

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
