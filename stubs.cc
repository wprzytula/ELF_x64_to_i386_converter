#include <optional>
#include "converter.h"
#include "assemblage.h"
#include <memory>
#include <string>
#include <stdexcept>

namespace converter::stubs {
    std::string const thunkin = R"(
;# long long fun(void *ptr, int x, long long y)

.code32
fun_stub:
;# zapis rejestrów
    pushl   %edi
    pushl   %esi
;# wyrównanie stosu
    subl    $4, %esp
;# zmiana trybu
    ljmpl   *fun_addr_32to64

;# część 64-bitowa
.code64
fun_stub_64:
;# bierzemy argumenty ze stosu
    movslq  0x10(%rsp), %rdi ;# TODO: movs or movz according to signedness
    movslq  0x14(%rsp), %rsi
    movslq  0x18(%rsp), %rdx
    movslq  0x1c(%rsp), %rcx
    movslq  0x20(%rsp), %r8
    movslq  0x24(%rsp), %r9
;# wołamy właściwą funkcję
    call    fun
;# konwersja wartości zwracanej
    movq    %rax, %rdx
    shrq    $32, %rdx
;# powrót
    ljmpl   *fun_addr_64to32

.code32
fun_stub_32:
    addl    $4, %esp
    popl    %esi
    popl    %edi
    retl

fun_addr_64to32:
    .long fun_stub_32
    .long 0x23

fun_addr_32to64:
    .long fun_stub_64
    .long 0x33
)";
    std::string const thunkin_template = R"(
.code32
fun_stub:
;# zapis rejestrów
    {}
;# wyrównanie stosu
    subl    $4, %esp
;# zmiana trybu
    ljmpl   *fun_addr_32to64

;# część 64-bitowa
.code64
fun_stub_64:
;# bierzemy argumenty ze stosu
    {}
;# wołamy właściwą funkcję
    call    fun
;# konwersja wartości zwracanej
    movq    %rax, %rdx
    shrq    $32, %rdx
;# powrót
    ljmpl   *fun_addr_64to32

.code32
fun_stub_32:
;# cofnięcie wyrównania stosu
    addl    $4, %esp
;# zdjęcie rejestrów
    {}
    retl

fun_addr_64to32:
    .long fun_stub_32
    .long 0x23

fun_addr_32to64:
    .long fun_stub_64
    .long 0x33
)";

    std::string const thunkout_template = R"(
;# long long fun(void *ptr, int x, long long y)
.code64
fun_stub:
;# zapis rejestrów
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
;# zapisujemy argumenty na stosie
    {}
;# zmiana trybu
    ljmpl   *fun_addr_64to32

;# część 32-bitowa
.code32
fun_stub_32:
;# segmenty
    pushl   $0x2b
    popl    %ds
    pushl   $0x2b
    popl    %es
;# wywołanie właściwej funkcji
    call    fun
;# powrót
    ljmpl   *fun_addr_32to64

;# znowu część 64-bitowa
.code64
fun_stub_64:
;# konwertujemy wartość zwracaną
    mov     %eax, %eax
    shlq    $32, %rdx
    orq     %rdx, %rax
;# zrzucamy rzeczy ze stosu i wracamy
    {}                                      ;addq    $0x18, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbp
    popq    %rbx
    retq

fun_addr_64to32:
.long      fun_stub_32
.long      0x23

fun_addr_32to64:
.long      fun_stub_64
.long      0x33
)";

    template<typename ...Args>
    std::string string_format(std::string const& format, Args... args)
    {
        int size_s = std::snprintf(nullptr, 0, format.c_str(), args...) + 1; // Extra space for '\0'
        if (size_s <= 0) {
            throw std::runtime_error("Error during formatting.");
        }
        auto size = static_cast<size_t>(size_s);
        std::unique_ptr<char[]> buf(new char[size]);
        std::snprintf(buf.get(), size, format.c_str(), args...);
        return {buf.get(), buf.get() + size - 1}; // We don't want the '\0' inside
    }

    std::string generate_thunkin(std::string const& pushes, std::string const& takes, std::string const& pops) {
        return string_format(thunkin_template, pushes.c_str(), takes.c_str(), pops.c_str());
    }

    std::string generate_thunkout(std::string const& pushes, std::string const& pops) {
        return string_format(thunkin_template, pushes.c_str(), pops.c_str());
    }

    /* *
     * 00000000  57 56 83 ec 04 ff 2d 00  00 00 00 48 63 7c 24 10
     * 00000010  48 63 74 24 14 48 63 54  24 18 48 63 4c 24 1c 4c
     * 00000020  63 44 24 20 4c 63 4c 24  24 e8 00 00 00 00 48 89
     * 00000030  c2 48 c1 ea 20 ff 2c 25  00 00 00 00 83 c4 04 5e
     * 00000040  5f c3 00 00 00 00 23 00  00 00 00 00 00 00 33 00
     * 00000050  00 00
     * */
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
            /* 50 */   0x00, 0x00 };

    ThunkPreRel32::ThunkPreRel32(Elf64_Rela const& rela64) {
        auto type = ELF64_R_TYPE(rela64.r_info);
        local_symbol = type == R_X86_64_PLT32 || type == R_X86_64_PC32;
        addend = static_cast<decltype(addend)>(rela64.r_addend);
        offset = static_cast<decltype(offset)>(rela64.r_offset);
    }

    /*std::vector<ThunkPreRel32> relocations {
            {.local_symbol=false, .offset=0x7,   .addend=0x4a},
            {.local_symbol=true,  .offset=0x2a,  .addend=-0x4},
            {.local_symbol=false, .offset=0x38,  .addend=0x42},
            {.local_symbol=false, .offset=0x42,  .addend=0x3c},
            {.local_symbol=false, .offset=0x4a,  .addend=0xb },
    };*/

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
//                    printf("\n\n############## \t\t placing relocation: %lu", rela64.r_offset);
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

    Stub Stub::stubin(func_spec::Function const& func_spec) {
        auto& assembly_code = thunkin; // FIXME
        return from_assembly(assembly_code);
    }

    Stub Stub::stubout(func_spec::Function const& func_spec) {
        auto& assembly_code = thunkin; // FIXME
        return from_assembly(assembly_code);
    }
}
