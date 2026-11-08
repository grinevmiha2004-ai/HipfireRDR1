SECTIONS { . = 0x68000; .text : { *(.text*) *(.rodata*) } . = 0x6a000; .data : { *(.data*) *(.bss*) BYTE(0) } /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) } }
game_image = 0xf8f0;
iat_rpm = 0x362d8;
iat_time = 0x362a8;
iat_key = 0x36418;
rh_init = 0x24030;
rh_push = 0x24028;
rh_call = 0x24020;
log_event = 0x1c90;
original_tick = 0x655ae;
