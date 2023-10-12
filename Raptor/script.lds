ENTRY(_start)

SECTIONS
{

   .text : { *(.text) }
   .rodata : { *(.rodata) }
   .eh_frame : { *(.eh_frame) }
   .data : { *(.data) *(.metadata) }
   .bss : { *(.bss) }

   .dynamic : { *(.data_layer) }

}
