.code

trampoline proc
    ; Preserve
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    mov r13, rcx                    ; Preserve syscall number
    mov r14, rdx                    ; Preserve syscall stub instruction address
    mov r15, r8                     ; Preserve amount of arguments that will be pushed onto the stack

    ; Forward arguments of the caller
    mov rcx, r9
    mov rdx, [rsp + 40 + 48]        ; 32 - shadow store, 8 - return address, add 48 to account for registers pushed onto the stack
    mov r8,  [rsp + 48 + 48]
    mov r9,  [rsp + 56 + 48]

    ; copy
    push rdx                        ; Preserve rdx
    mov rax, 8                      
    mul r15                         ; Multiply by 8 to get bytes to reserve stack space
    pop rdx
    mov r12, rax                    ; Preserve the size of the arguments that need to be copied onto the stack
    sub rsp, rax                    ; Increase the stack by the amount needed by the arguments on the stack that need to be copied
    lea rsi, [rsp + rax + 64 + 48]
    mov rdi, rsp                    ; Copy to the current top of the stack
    push rcx                        ; Preserve rcx
    mov rcx, r15
    rep movsq                       ; Copy the arguments that are supposed to be allocated on the stack
    pop rcx
    
    mov r10, rcx                    ; Preserve rcx
    mov rax, r13
    sub rsp, 32                     ; Shadow space
    call r14                        ; Jump to syscall stub
    add r12, 32
    add rsp, r12

    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
trampoline endp

END
