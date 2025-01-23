.intel_syntax noprefix
.global trampoline
.section .text

trampoline:
    # Preserve
    push rbp
    mov rbp, rsp
    push r14
    push r13
    mov r13, rcx # Preserve syscall number
    mov r14, rdx # Preserve syscall stub instruction address
    # Forward arguments of the caller
    mov rcx, r8
    mov rdx, r9
    mov r8, [rbp+48]
    mov r9, [rbp+56]
    
    mov r10, rcx
    mov rax, r13
    call r14
    pop r13
    pop r14
    pop rbp
    ret
