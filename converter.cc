#include <iostream>
#include <fstream>
#include <utility>
#include <sstream>
#include <optional>
#include <cstring>

#include "converter.h"
#include "assemblage.h"

namespace converter {
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
}

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
