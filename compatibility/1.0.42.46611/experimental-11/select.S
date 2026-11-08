.text
.global select_resolved
.type select_resolved,@function
select_resolved:
 # Recreate the native CDF A20 frame, then enter its validated continuation
 # after path lookup with the real owner/node in the exact expected registers.
 # The original game code performs creation, scheduling and reference counting.
 push %rdi
 sub $0x170,%rsp
 mov %rcx,%rdi
 mov %rdx,%rax
 mov game_image(%rip),%r11
 add $0xcdfe5a,%r11
 jmp *%r11
.size select_resolved,.-select_resolved
.section .note.GNU-stack,"",@progbits
