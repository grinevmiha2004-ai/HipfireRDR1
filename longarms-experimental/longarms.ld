SECTIONS { . = 0x68000; .text : { *(.text*) *(.rodata*) } . = 0x6b000; .data : { *(.data*) *(.bss*) BYTE(0) } /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) } }
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

original_pose = 0x1490;
original_cover = 0xd8f0;
original_cancel = 0x1f80;
owned_actor = 0xf7cc;
owned_kind = 0x24080;
owned_expanded = 0x2407e;

original_aim = 0x15c0;
owned_goal = 0x2407d;
input_enabled = 0xf960;
mod_enabled = 0xf7c8;
release_at = 0x24060;
original_tick = 0x655ae;

reload_pending = 0x63000;
