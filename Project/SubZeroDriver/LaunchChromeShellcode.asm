BITS 64
SECTION .text
global main
main:

    mov rax, rsp                ; RAX = RSP
    and rsp, 0xffffffffffffff00 ; Align the stack to a multiple of 16 bytes
    add rsp, 8                  ; Add 8 to align with RAX push
    push rax                    ; Save RSP value for the end
    call get_rip                ; Get current address using call opcode
get_rip:
    pop r15                     ; R15 = Current address

; Parse PEB and find kernel32
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
    mov r9d, 0xaeb52e19        ; djb2(CreateProcessA)
    
Get_Function:

; Loop through exported functions and find CreateProcessA
    
    inc rcx                    ; Increment the ordinal
    xor rax, rax               ; RAX = 0
    mov eax, [rsi + rcx * 4]   ; Get name offset
    add rax, rbx               ; Get function name
    push rcx                   ; Push ordinal
    mov rcx, rax               ; RCX = Function name pointer
    mov rdx, 1                 ; RDX = Char size (ASCII)
    call djb2                  ; Hash name
    pop rcx                    ; Pop ordinal back
    cmp eax, r9d               ; CreateProcessA?
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
    add rdx, rbx               ; RDX = CreateProcessA
    mov rdi, rdx               ; Save CreateProcessA in RDI

; Call CreateProcessA

    xor rdx, rdx                       ; RDX = 0 (lpCommandLine)

    xor rcx, rcx                       ; RCX = Loop counter
ZeroStartupInfoStruct:
    inc rcx                            ; RCX++
    push rdx                           ; Push 0
    cmp rcx, 0xD                       ; StartupInfo size \ register size (0x68 \ 0x8 = 0xD)
    jnz ZeroStartupInfoStruct          
    mov r10, rsp                       ; R10 = StartupInfo offset

    xor rcx, rcx                       ; RCX = Loop counter
ZeroProcessInformationStruct:
    inc rcx                            ; RCX++
    push rdx                           ; Push 0
    cmp rcx, 0x3                       ; ProcessInformation size \ register size (0x18 \ 0x8 = 0x3)
    jnz ZeroProcessInformationStruct
    mov r11, rsp                       ; R11 = ProcessInformation offset

; Push the rest of CreateProcessA's parameters and call it
    push r11                           ; lpProcessInformation
    push r10                           ; lpStartupInfo
    push rdx                           ; bInheritHandles
    push rdx                           ; dwCreationFlags
    push rdx                           ; lpEnvironment
    push rdx                           ; lpCurrentDirectory
    xor r9, r9                         ; lpThreadAttributes
    xor r8, r8                         ; lpProcessAttributes
    lea rcx, [r15 + cmdline - get_rip] ; lpApplicationName
    sub rsp, 0x20                      ; Allocate stack space
    call rdi                           ; CreateProcessA();
    add rsp, 0xD0                      ; Free stack space: 0x20 (shadow space) + 0x30 (paramateres pushed) + 0x80 (structures)
    jmp end

; djb2 Hash Function
; RCX = The address of the string (must be null-terminated)
; RDX + The char size (1 for ascii, 2 for widechar) 
djb2:
    push rbx
    push rdi
    mov eax, 5381

.hash_loop:
    cmp byte [rcx], 0
    je return_from_func
    mov ebx, eax
    shl eax, 5
    add eax, ebx
    movzx rdi, byte [rcx]
    add eax, edi
    add rcx, rdx
    jmp .hash_loop
return_from_func:
    pop rdi
    pop rbx
    ret

cmdline:
    db "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 0
    
end:
    pop rsp
    ret