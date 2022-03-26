#ifndef ZAD1_ELF_CONVERTER_ASSEMBLAGE_H
#define ZAD1_ELF_CONVERTER_ASSEMBLAGE_H

namespace converter::assembly {
    void rid_gnu_property(std::string const& codefile, std::string const& outfile);

    std::string assemble(std::string const& asm_code);
}

#endif //ZAD1_ELF_CONVERTER_ASSEMBLAGE_H
