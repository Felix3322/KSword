;++
;
; Module Name:
;
;     page_fault_stub.asm
;
; Abstract:
;
;     x64 vector-14 entry preserving the hardware error-code frame and Windows
;     x64 ABI.  User-origin faults SWAPGS only around the C dispatcher and then
;     restore user GS before chaining to the original Windows handler.
;
;--

OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN KswRxpfPageFaultDispatch:PROC
PUBLIC KswRxpfPageFaultStub
PUBLIC KswRxpfInvokeTestPage

KSW_FRAME_R15         EQU 000h
KSW_FRAME_R14         EQU 008h
KSW_FRAME_R13         EQU 010h
KSW_FRAME_R12         EQU 018h
KSW_FRAME_R11         EQU 020h
KSW_FRAME_R10         EQU 028h
KSW_FRAME_R9          EQU 030h
KSW_FRAME_R8          EQU 038h
KSW_FRAME_RDI         EQU 040h
KSW_FRAME_RSI         EQU 048h
KSW_FRAME_RBP         EQU 050h
KSW_FRAME_RBX         EQU 058h
KSW_FRAME_RDX         EQU 060h
KSW_FRAME_RCX         EQU 068h
KSW_FRAME_RAX         EQU 070h
KSW_FRAME_ERROR       EQU 078h
KSW_FRAME_RIP         EQU 080h
KSW_FRAME_CS          EQU 088h
KSW_FRAME_RFLAGS      EQU 090h
KSW_FRAME_HARDWARE_RSP EQU 098h

KSW_LOCAL_TRANSFER    EQU -020h
KSW_LOCAL_RESUME_RSP  EQU -018h
KSW_LOCAL_SWAPPED     EQU -010h
KSW_LOCAL_RESUME_FRAME EQU -130h
KSW_CHAIN_FROM_ERROR  EQU -098h

.code

KswRxpfPageFaultStub PROC
    ; Save every general register that the C dispatcher may modify.
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; R12 points at the fixed C-visible trap frame for the complete entry.
    mov r12, rsp
    sub rsp, 130h

    ; Preserve volatile SIMD registers across the asynchronous exception.
    movdqu xmmword ptr [r12-080h], xmm0
    movdqu xmmword ptr [r12-070h], xmm1
    movdqu xmmword ptr [r12-060h], xmm2
    movdqu xmmword ptr [r12-050h], xmm3
    movdqu xmmword ptr [r12-040h], xmm4
    movdqu xmmword ptr [r12-030h], xmm5

    ; User-origin exceptions still carry user GS until this conditional swap.
    mov qword ptr [r12+KSW_LOCAL_SWAPPED], 0
    test byte ptr [r12+KSW_FRAME_CS], 3
    jz KswRxpfGsReady
    swapgs
    mov qword ptr [r12+KSW_LOCAL_SWAPPED], 1

KswRxpfGsReady:
    ; The Windows x64 ABI requires DF clear, 16-byte alignment and shadow space.
    cld
    and rsp, -16
    sub rsp, 040h
    mov qword ptr [rsp+020h], 0
    mov qword ptr [rsp+028h], 0
    mov rcx, r12
    lea rdx, [rsp+020h]
    lea r8, [rsp+028h]
    lea r9, [r12+KSW_LOCAL_RESUME_FRAME]
    call KswRxpfPageFaultDispatch

    ; Save dispatcher outputs in the reserved non-red-zone scratch area.
    mov r10, qword ptr [rsp+020h]
    mov qword ptr [r12+KSW_LOCAL_TRANSFER], r10
    mov r10, qword ptr [rsp+028h]
    mov qword ptr [r12+KSW_LOCAL_RESUME_RSP], r10
    mov r13, rax

    ; Restore volatile SIMD state before either transfer path.
    movdqu xmm0, xmmword ptr [r12-080h]
    movdqu xmm1, xmmword ptr [r12-070h]
    movdqu xmm2, xmmword ptr [r12-060h]
    movdqu xmm3, xmmword ptr [r12-050h]
    movdqu xmm4, xmmword ptr [r12-040h]
    movdqu xmm5, xmmword ptr [r12-030h]

    ; Return GS to the exact state expected by the original handler or IRET.
    cmp qword ptr [r12+KSW_LOCAL_SWAPPED], 0
    je KswRxpfGsRestored
    swapgs

KswRxpfGsRestored:
    cmp r13, 1
    je KswRxpfHandled

    ; C execution cleared DF; restore its interrupted value before chaining.
    test qword ptr [r12+KSW_FRAME_RFLAGS], 0400h
    jz KswRxpfChainDirectionReady
    std

KswRxpfChainDirectionReady:
    ; Restore all registers and expose the untouched CPU error-code frame.
    mov rsp, r12
    mov r15, qword ptr [rsp+KSW_FRAME_R15]
    mov r14, qword ptr [rsp+KSW_FRAME_R14]
    mov r13, qword ptr [rsp+KSW_FRAME_R13]
    mov r12, qword ptr [rsp+KSW_FRAME_R12]
    mov r11, qword ptr [rsp+KSW_FRAME_R11]
    mov r10, qword ptr [rsp+KSW_FRAME_R10]
    mov r9, qword ptr [rsp+KSW_FRAME_R9]
    mov r8, qword ptr [rsp+KSW_FRAME_R8]
    mov rdi, qword ptr [rsp+KSW_FRAME_RDI]
    mov rsi, qword ptr [rsp+KSW_FRAME_RSI]
    mov rbp, qword ptr [rsp+KSW_FRAME_RBP]
    mov rbx, qword ptr [rsp+KSW_FRAME_RBX]
    mov rdx, qword ptr [rsp+KSW_FRAME_RDX]
    mov rcx, qword ptr [rsp+KSW_FRAME_RCX]
    mov rax, qword ptr [rsp+KSW_FRAME_RAX]
    lea rsp, [rsp+KSW_FRAME_ERROR]
    jmp qword ptr [rsp+KSW_CHAIN_FROM_ERROR]

KswRxpfHandled:
    ; The assembly-owned resume copy cannot overlap PUSH/CALL stack effects.
    lea r11, [r12+KSW_LOCAL_RESUME_FRAME]
    mov r10, qword ptr [r12+KSW_LOCAL_RESUME_RSP]
    sub r10, 018h
    mov rax, qword ptr [r11+KSW_FRAME_RIP]
    mov qword ptr [r10+000h], rax
    mov rax, qword ptr [r11+KSW_FRAME_CS]
    mov qword ptr [r10+008h], rax
    mov rax, qword ptr [r11+KSW_FRAME_RFLAGS]
    mov qword ptr [r10+010h], rax
    mov qword ptr [r11+KSW_FRAME_HARDWARE_RSP], r10

    ; Restore emulated GPRs, retaining R10/R11 until the final stack switch.
    mov r15, qword ptr [r11+KSW_FRAME_R15]
    mov r14, qword ptr [r11+KSW_FRAME_R14]
    mov r13, qword ptr [r11+KSW_FRAME_R13]
    mov r12, qword ptr [r11+KSW_FRAME_R12]
    mov r9, qword ptr [r11+KSW_FRAME_R9]
    mov r8, qword ptr [r11+KSW_FRAME_R8]
    mov rdi, qword ptr [r11+KSW_FRAME_RDI]
    mov rsi, qword ptr [r11+KSW_FRAME_RSI]
    mov rbp, qword ptr [r11+KSW_FRAME_RBP]
    mov rbx, qword ptr [r11+KSW_FRAME_RBX]
    mov rdx, qword ptr [r11+KSW_FRAME_RDX]
    mov rcx, qword ptr [r11+KSW_FRAME_RCX]
    mov rax, qword ptr [r11+KSW_FRAME_RAX]
    mov rsp, qword ptr [r11+KSW_FRAME_HARDWARE_RSP]
    mov r10, qword ptr [r11+KSW_FRAME_R10]
    mov r11, qword ptr [r11+KSW_FRAME_R11]
    iretq
KswRxpfPageFaultStub ENDP

; Call a page through a normal unwind-described kernel x64 call frame.
KswRxpfInvokeTestPage PROC FRAME
    sub rsp, 028h
    .allocstack 028h
    .endprolog
    call rcx
    add rsp, 028h
    ret
KswRxpfInvokeTestPage ENDP

END
