    .text
    .p2align 2
    .global guest_stack_round_trip_asm
    .type guest_stack_round_trip_asm, %function

guest_stack_round_trip_asm:
    // x0: aligned guest SP, x1: host callback, x2: opaque, x3: observation.
    // Preserve every callee-saved register this bounded gate uses on the host stack.
    sub sp, sp, #64
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x29, x30, [sp, #48]
    mov x29, sp
    mov x19, sp
    mov x20, x1
    mov x21, x2
    mov x22, x3
    str x19, [x22, #8]

    // Enter the guarded synthetic guest stack and touch only one tiny frame.
    mov sp, x0
    sub sp, sp, #16
    stp xzr, xzr, [sp]
    mov x23, sp
    str x23, [x22, #0]

    // Host C/C++ must never run on the guest stack. Restore the captured host
    // frame before calling out; x19/x23 are callee-saved across the callback.
    mov sp, x19
    mov x0, x21
    mov x1, x19
    blr x20
    str x0, [x22, #32]

    // Return to the synthetic guest frame only to leave it explicitly, then
    // restore the exact host frame and return through the normal AAPCS64 path.
    mov sp, x23
    add sp, sp, #16
    mov sp, x19
    str x19, [x22, #24]
    ldp x29, x30, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp, #0]
    add sp, sp, #64
    ret

    .size guest_stack_round_trip_asm, .-guest_stack_round_trip_asm
