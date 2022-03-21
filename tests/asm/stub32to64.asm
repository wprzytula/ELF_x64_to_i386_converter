; long long fun(void *ptr, int x, long long y)

.code32
fun_stub:
;# zapis rejestrów
pushl %edi
pushl %esi
;# wyrównanie stosu
subl $4, %esp
;# zmiana trybu
ljmpl *fun_addr_32to64

;# część 64-bitowa
.code64
fun_stub_64:
;# bierzemy argumenty ze stosu
    movl 0x10(%rsp), %edi
    movslq 0x14(%rsp), %rsi
    movq 0x18(%rsp), $rdx
;# wołamy właściwą funkcję
    call fun
;# konwersja wartości zwracanej
    movq %rax, %rdx
    shrq $32, %rdx
;# powrót
    ljmpl *fun_addr_64to32

.code32
fun_stub_32:
    addl $4, %esp
    popl %esi
    popl %edi
    retl

fun_addr_64to32:
    .long fun_stub_32
    .long 0x23

fun_addr_32to64:
    .long fun_stub_64
    .long 0x33