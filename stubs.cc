#include <optional>
#include "converter.h"
#include "assemblage.h"
#include <memory>
#include <string>
#include <stdexcept>
#include <sstream>

namespace converter::stubs {
    namespace {
        std::string const thunkin_template = R"(
.code32
fun_stub:
;# zapis rejestrów
    pushl   %%edi
    pushl   %%esi
;# wyrównanie stosu
    subl    $4, %%esp
;# zmiana trybu
    ljmpl   *fun_addr_32to64

;# część 64-bitowa
.code64
fun_stub_64:
;# bierzemy argumenty ze stosu
%s
;# wołamy właściwą funkcję
    call    fun
;# konwersja wartości zwracanej
    movq    %%rax, %%rdx
    shrq    $32, %%rdx
;# powrót
    ljmpl   *fun_addr_64to32

.code32
fun_stub_32:
;# cofnięcie wyrównania stosu
    addl    $4, %%esp
;# zdjęcie rejestrów
    popl   %%esi
    popl   %%edi
    retl

fun_addr_64to32:
    .long fun_stub_32
    .long 0x23

fun_addr_32to64:
    .long fun_stub_64
    .long 0x33
)";

        std::string const thunkout_template = R"(
.code64
fun_stub:
;# zapis rejestrów
    pushq   %%rbx
    pushq   %%rbp
    pushq   %%r12
    pushq   %%r13
    pushq   %%r14
    pushq   %%r15
;# zapisujemy argumenty na stosie
    subq    $0x%u,  %%rsp
%s
;# zmiana trybu
    ljmpl   *fun_addr_64to32

;# część 32-bitowa
.code32
fun_stub_32:
;# segmenty
    pushl   $0x2b
    popl    %%ds
    pushl   $0x2b
    popl    %%es
;# wywołanie właściwej funkcji
    call    fun
;# powrót
    ljmpl   *fun_addr_32to64

;# znowu część 64-bitowa
.code64
fun_stub_64:
;# konwertujemy wartość zwracaną
    mov     %%eax,  %%eax
    shlq    $32,    %%rdx
    orq     %%rdx,  %%rax
;# zrzucamy rzeczy ze stosu i wracamy
    addq    $0x%u,  %%rsp
    popq    %%r15
    popq    %%r14
    popq    %%r13
    popq    %%r12
    popq    %%rbp
    popq    %%rbx
    retq

fun_addr_64to32:
.long      fun_stub_32
.long      0x23

fun_addr_32to64:
.long      fun_stub_64
.long      0x33
)";

        template<typename ...Args>
        std::string string_format(std::string const& format, Args... args) {
            int size_s = std::snprintf(nullptr, 0, format.c_str(), args...) + 1; // Extra space for '\0'
            if (size_s <= 0) {
                throw std::runtime_error("Error during formatting.");
            }
            auto size = static_cast<size_t>(size_s);
            std::unique_ptr<char[]> buf(new char[size]);
            std::snprintf(buf.get(), size, format.c_str(), args...);
            return {buf.get(), buf.get() + size - 1}; // We don't want the '\0' inside
        }

        std::string generate_thunkin(std::string const& takes) {
            return string_format(thunkin_template, takes.c_str());
        }

        std::string generate_thunkout(uint32_t const args_size, std::string const& movs) {
            return string_format(thunkout_template, args_size, movs.c_str(), args_size);
        }

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
                /* 50 */   0x00, 0x00};
    }

    ThunkPreRel32::ThunkPreRel32(Elf64_Rela const& rela64) {
        auto type = ELF64_R_TYPE(rela64.r_info);
        local_symbol = type == R_X86_64_PLT32 || type == R_X86_64_PC32;
        addend = static_cast<decltype(addend)>(rela64.r_addend);
        offset = static_cast<decltype(offset)>(rela64.r_offset);
    }

    Stub::Stub(std::ifstream& stub_elf) {
        Elf64_Ehdr header;
        read_to_field(stub_elf, header);

        std::optional<elf64::Section64WithGenericData> text;
        std::optional<elf64::Section64Rela> rela;

        for (size_t i = 0; i < header.e_shnum; ++i) {
            stub_elf.seekg(static_cast<ssize_t>(header.e_shoff + i * header.e_shentsize));

            elf64::Section64 section64{stub_elf};
            if (section64.header.sh_type == SHT_PROGBITS && section64.header.sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
                // found .text
                text.emplace(std::move(section64), stub_elf);

                code.resize(text->header.sh_size);
                std::copy(text->data.get(), text->data.get() + text->header.sh_size, code.data());

            } else if (section64.header.sh_type == SHT_RELA) {
                // found .rela.text
                rela.emplace(std::move(section64), stub_elf);

                for (elf64::Rela64 const& rela64: rela->relocations) {
                    relocations.emplace_back(rela64);
                }
            }

            if (text.has_value() && rela.has_value()) {
                return;
            }
        }
        std::string error_msg{"Section"};
        if (!text.has_value()) error_msg.append(" <.text>");
        if (!rela.has_value()) error_msg.append(" <.rela.text>");
        throw UnsupportedFileContent{error_msg + " not found in created code file."};
    }

    Stub Stub::from_assembly(std::string const& assembly_code) {
        auto [stubelf_lock_guard, stubelf_name] = assembly::assemble_to_file(assembly_code);
        std::ifstream stubelf_stream{stubelf_name};
        stubelf_stream.exceptions(std::ifstream::badbit);

        return Stub{stubelf_stream};
    }

    static char const* registers64[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    static char const* registers32[] = {"edi", "esi", "edx", "ecx", "r8d", "r9d"};

    std::string Stub::asmin(func_spec::Function const& func_spec) {
        std::string takes;
        auto gen_take = [](char const* instr, size_t offset, char const* reg){
            std::stringstream take;
            take << '\t' << instr << " 0x" << std::hex << offset << "(%rsp), %" << reg << '\n';
            return take.str();
        };

        size_t offset = 0x10;

        for (uint32_t i = 0; i < func_spec.args.size(); ++i) {
            auto const& arg = func_spec.args[i];

            char const*const reg = (arg.bytes_64() == 4 || (arg.size_differs() && !arg.is_signed())
                                    ? registers32
                                    : registers64
            )[i];
            char const* instr;
            if (arg.size_differs()) {
                instr = arg.is_signed()
                        ? "movslq"
                        : "movl";
            } else {
                instr = arg.bytes_32() == 4
                        ? "movl"
                        : "movq";
            }

            takes += gen_take(instr, offset, reg);
            offset += arg.bytes_32();
        }

        return generate_thunkin(takes);
    }

    std::string Stub::asmout(func_spec::Function const& func_spec) {
        uint32_t offset = 0;
        std::stringstream movs;
        for (uint32_t i = 0; i < func_spec.args.size(); ++i) {
            auto const& arg = func_spec.args[i];

            char const mov_letter = arg.bytes_32() == 4 ? 'l' : 'q';
            char const* reg = arg.bytes_32() == 4 ? registers32[i] : registers64[i];

            movs << "\tmov" << mov_letter << "\t%" << reg << ", 0x" << std::hex << offset << "(%rsp)\n";

            offset += arg.bytes_32();
        }

        static const uint32_t divisor = 16;
        static const uint32_t remainder = 8;
        offset += remainder - offset % divisor;
        if (offset < 0)
            offset += divisor;

        return generate_thunkout(offset, movs.str());
    }

    Stub Stub::stubin(func_spec::Function const& func_spec) {
        return from_assembly(asmin(func_spec));
    }

    Stub Stub::stubout(func_spec::Function const& func_spec) {
        return from_assembly(asmout(func_spec));
    }
}
