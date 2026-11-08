SECTIONS { . = 0x68000; .text : { *(.text*) *(.rodata*) } . = ALIGN(0x1000); .data : { *(.data*) *(.bss*) BYTE(0) } /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) } }
original_select = 0xd730;
original_playing = 0xd7f0;
original_weapon = 0xd870;
original_rapid = 0xda70;
actor_from = 0x1ac0;
read_pointer = 0x19a0;
read_byte = 0x18a0;
game_image = 0xf8f0;
iat_rpm = 0x362d8;
log_event = 0x1c90;
