;------------------------------------------------------------------------------
;
; Module Name:
;
;     hvm_entry.asm
;
; Abstract:
;
;     Captures selector state, supplies the one-shot VMCALL guest entry, and
;     transfers every VM exit to the non-returning C dispatcher.
;
;------------------------------------------------------------------------------

OPTION CASEMAP:NONE

EXTERN KswordARKHvmVmExitDispatch:PROC

PUBLIC KswordARKHvmCaptureSegments
PUBLIC KswordARKHvmControlledGuestEntry
PUBLIC KswordARKHvmAsmLaunch
PUBLIC KswordARKHvmVmExitEntry

.CODE

KswordARKHvmCaptureSegments PROC
    ; Store the packed ten-byte GDTR at snapshot offset zero.
    sgdt FWORD PTR [rcx]
    ; Store the packed ten-byte IDTR at snapshot offset ten.
    sidt FWORD PTR [rcx + 10]
    ; Capture ES into its packed snapshot slot.
    mov ax, es
    ; Publish the captured ES selector.
    mov WORD PTR [rcx + 20], ax
    ; Capture CS into its packed snapshot slot.
    mov ax, cs
    ; Publish the captured CS selector.
    mov WORD PTR [rcx + 22], ax
    ; Capture SS into its packed snapshot slot.
    mov ax, ss
    ; Publish the captured SS selector.
    mov WORD PTR [rcx + 24], ax
    ; Capture DS into its packed snapshot slot.
    mov ax, ds
    ; Publish the captured DS selector.
    mov WORD PTR [rcx + 26], ax
    ; Capture FS into its packed snapshot slot.
    mov ax, fs
    ; Publish the captured FS selector.
    mov WORD PTR [rcx + 28], ax
    ; Capture GS into its packed snapshot slot.
    mov ax, gs
    ; Publish the captured GS selector.
    mov WORD PTR [rcx + 30], ax
    ; Capture the current local-descriptor-table selector.
    sldt ax
    ; Publish the captured LDTR selector.
    mov WORD PTR [rcx + 32], ax
    ; Capture the current task-register selector.
    str ax
    ; Publish the captured task-register selector.
    mov WORD PTR [rcx + 34], ax
    ; Return to the VMCS builder.
    ret
KswordARKHvmCaptureSegments ENDP

KswordARKHvmControlledGuestEntry PROC
    ; Produce the single expected, deterministic VM-exit reason.
    vmcall
    ; Force a second intercept if a future dispatcher accidentally resumes.
    hlt
    ; Prevent fall-through into adjacent executable bytes.
    jmp KswordARKHvmControlledGuestEntry
KswordARKHvmControlledGuestEntry ENDP

KswordARKHvmAsmLaunch PROC
    ; Save the original wrapper stack pointer in context field zero.
    mov QWORD PTR [rcx], rsp
    ; Attempt the first VM entry for the current clear-state VMCS.
    vmlaunch
    ; Default a returning VMLAUNCH to VMfailInvalid.
    mov eax, 2
    ; Preserve result two when the carry flag reports VMfailInvalid.
    jc KswordARKHvmAsmLaunchComplete
    ; Select result one for a VMfailValid zero-flag result.
    mov eax, 1
    ; Preserve result one when the zero flag reports VMfailValid.
    jz KswordARKHvmAsmLaunchComplete
    ; Retain a defensive zero for an architecturally unreachable flag state.
    xor eax, eax
KswordARKHvmAsmLaunchComplete:
    ; Return the VM-entry failure code to the C launch lifecycle.
    ret
KswordARKHvmAsmLaunch ENDP

KswordARKHvmVmExitEntry PROC FRAME
    ; Reserve the Windows x64 caller home area on the dedicated exit stack.
    sub rsp, 20h
    ; Describe the fixed stack allocation to the x64 unwinder.
    .ALLOCSTACK 20h
    ; End the unwindable prologue before the first C call.
    .ENDPROLOG
    ; Transfer the current VMCS to the exit dispatcher.
    call KswordARKHvmVmExitDispatch
    ; Require the dispatcher to return the exact active launch context.
    test rax, rax
    ; Trap if the dispatcher could not recover a launch continuation.
    jz KswordARKHvmVmExitFatal
    ; Restore the wrapper stack that contains the original C return address.
    mov rsp, QWORD PTR [rax]
    ; Report successful VM entry and handled VM exit to the C lifecycle.
    xor eax, eax
    ; Return through the original KswordARKHvmAsmLaunch caller frame.
    ret
KswordARKHvmVmExitFatal:
    ; Trap immediately if the dispatcher violates its context contract.
    int 3
    ; Keep the fallback path bounded even when a debugger continues the trap.
    pause
    ; Never execute bytes outside the fallback loop.
    jmp KswordARKHvmVmExitFatal
KswordARKHvmVmExitEntry ENDP

END
