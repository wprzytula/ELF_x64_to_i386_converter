#include <utility>
#include <sstream>
#include <optional>
#include <cstring>
#include "converter.h"

namespace converter::func_spec {
    ArgType Arg::parse_arg_type(char const* argtype) {
        if (strcmp(argtype, "int") == 0) return int_t;
        if (strcmp(argtype, "uint") == 0) return uint_t;
        if (strcmp(argtype, "long") == 0) return long_t;
        if (strcmp(argtype, "ulong") == 0) return ulong_t;
        if (strcmp(argtype, "longlong") == 0) return longlong_t;
        if (strcmp(argtype, "ulonglong") == 0) return ulonglong_t;
        if (strcmp(argtype, "ptr") == 0) return ptr_t;
        throw std::invalid_argument{std::string{"invalid argument specified for function: "} + argtype + "."};
    }

    size_t Arg::bytes_32() const {
        switch (type) {
            case longlong_t:
            case ulonglong_t:
                return 8;
            default:
                return 4;
        }
    }

    size_t Arg::bytes_64() const {
        switch (type) {
            case int_t:
            case uint_t:
                return 4;
            default:
                return 8;
        }
    }

    bool Arg::size_differs() const {
        return bytes_32() != bytes_64();
    }

    std::optional<ArgType> Ret::parse_ret_type(char const* argtype) {
        if (strcmp(argtype, "void") == 0) return {};
        return std::make_optional<>(Arg::parse_arg_type(argtype));
    }

    Function Function::from_line_decl(std::string const& decl) {
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

        if (args.size() > 6) {
            throw UnsupportedFileContent{"More than 6 args specified for a function <" + name + ">."};
        }

        return Function(std::move(name), std::move(ret), std::move(args));
    }

    Functions::Functions(std::ifstream& func_stream) {
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
