global _start

section .data
        message db "1337",0x0A
        chiffre db "42",0x0A

section .bss
        buf : resb 3
        len EQU $-buf ; longueur de input
section .text

_start:
        mov eax, 4
        mov ebx, 1
        mov ecx, message
        mov edx, 5
        int 0x80

        ;read stdin
        mov eax, 3
        mov ebx, 0
        mov ecx, buf
        mov edx, len ; taile du msg
        int 0X80 ;(syscall ou interuption)

        mov esi, buf
        mov edi, chiffre
        cld ; clair DF pour la direction croissan>
        repe cmpsb ; répète jusqu'à ce que les ch>

        ;pas identique
        jne return_1

        ;identique
        jmp return_0

return_1:
        ;otherwise, return 1
        mov eax, 1
        mov ebx, 1
        int 0x80
return_0:
        mov eax, 1
        mov ebx, 0
        int 0x80



