.code
main PROC

    ;INJECTION POINT
    push rax                    ;SAVING REGISTER VALUE
    mov rax, 0FF000000000000FFh ;ADDRESS - fixed size
    jmp rax
    pop rax                     ;RESTORE RAX AFTER JMP BACK

    ;REDIRECTED CODE
    pop rax                      ;RESTORE REGISTER AFTER JMP
    nop                          ;CODE
    nop                          ;RESTORE PARTS OF ORIGINAL IF NEEDED
    push rax                     ;SAVING REGISTER VALUE
    mov rax, 0FF000000000000FFh  ;ADDRESS = INJECTION ADDRESS + 13 BYTES
    jmp rax


    ;"NEW CODE"
    mov rax, 01h
    inc rax
main ENDP
END