#ifndef ZAD1_ELF_CONVERTER_ASSEMBLAGE_H
#define ZAD1_ELF_CONVERTER_ASSEMBLAGE_H

namespace converter::assembly {
    static char const* LOCK_PREFIX = "lock_";

    class Tempfile {
        std::string lock_name{LOCK_PREFIX};
        size_t _file_num;
    public:
        explicit Tempfile();
        Tempfile(Tempfile const&) = delete;
        Tempfile(Tempfile&&) = default;
        Tempfile& operator=(Tempfile const&) = delete;
        Tempfile& operator=(Tempfile&&) = default;
        ~Tempfile();

        [[nodiscard]] size_t file_num() const {
            return _file_num;
        }

    };

    void rid_gnu_property(std::string const& codefile, std::string const& outfile);

    std::pair<Tempfile, std::string> assemble_to_file(std::string const& asm_code, bool binary_text_only=false);

    std::string assemble(std::string const& asm_code, bool binary_text_only=false);
}

#endif //ZAD1_ELF_CONVERTER_ASSEMBLAGE_H
