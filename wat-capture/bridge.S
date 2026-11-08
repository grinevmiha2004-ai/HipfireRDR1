.text
.macro save
 pushfq
 push %rax
 push %rcx
 push %rdx
 push %r8
 push %r9
 push %r10
 push %r11
 sub $0x80,%rsp
 movdqu %xmm0,0x20(%rsp)
 movdqu %xmm1,0x30(%rsp)
 movdqu %xmm2,0x40(%rsp)
 movdqu %xmm3,0x50(%rsp)
 movdqu %xmm4,0x60(%rsp)
 movdqu %xmm5,0x70(%rsp)
 lea 0xc0(%rsp),%rcx
.endm
.macro restore
 movdqu 0x20(%rsp),%xmm0
 movdqu 0x30(%rsp),%xmm1
 movdqu 0x40(%rsp),%xmm2
 movdqu 0x50(%rsp),%xmm3
 movdqu 0x60(%rsp),%xmm4
 movdqu 0x70(%rsp),%xmm5
 add $0x80,%rsp
 pop %r11
 pop %r10
 pop %r9
 pop %r8
 pop %rdx
 pop %rcx
 pop %rax
 popfq
.endm

.global capture_bridge
.type capture_bridge,@function
capture_bridge:
 save
 call capture_tick
 restore
 jmp original_tick
.size capture_bridge,.-capture_bridge
.section .note.GNU-stack,"",@progbits

