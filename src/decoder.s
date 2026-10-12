BITS 32

GLOBAL start
GLOBAL loop
section .text

start:
    push esi
    push eax
    push ebx

    ;get in ebx the addr where encoded data ends
    mov ebx, esp
    sub ebx, 0xfffffd35

    ; 0xfffffd35 = -(30+685)
    ; 30 - size of decoder, 685 - size of encoded data
    
    ;get addr of encoded data
    mov esi, esp
    sub esi, 0xfffffff4 ; get addr of decoder = esp + 12
    sub esi, 0xffffffe2 ; 0xffffffe2 = -30, 30 - size of decoder

loop: 
    xor byte [esi], 0x03
    inc esi
    cmp esi, ebx
    jnz loop

    pop ebx
    pop eax
    pop esi



