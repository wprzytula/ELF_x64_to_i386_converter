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
    subq    $0x18, %rsp
    movq    %rdx, 8(%rsp)
    movl    %esi, 4(%rsp)
    movl    %edi, (%rsp)
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
    addq    $0x18, %rsp
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