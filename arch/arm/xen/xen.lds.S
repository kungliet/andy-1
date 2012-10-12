/*
 * xen.lds.S
 *
 * Copyright (C) 2008 Samsung Electronics
 *          ChanJu Park  <bestworld@samsung.com>
 *
 * Secure Xen on ARM architecture designed by Sang-bum Suh consists of
 * Xen on ARM and the associated access control.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public version 2 of License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/autoconf.h>

OUTPUT_ARCH(arm)
ENTRY(start)
ENTRY(text)
PHDRS
{
	text PT_LOAD ;
}
SECTIONS
{
#ifdef CONFIG_PLATFORM_GOLDFISH
	. = 0xFF010000;
#else
	. = 0xFF008000;
#endif
	_stext = .;			/* Text and read-only data */
	.text : {
		*(.text)
		*(.fixup)
		*(.gnu.warning)
	} :text =0x9090

	.text.lock : {
		*(.text.lock) 
	} : text	/* out-of-line lock text */

	_etext = .;			/* End of text section */

	.rodata : {
		*(.rodata)
		*(.rodata.*) 
	} :text

	.data : {			/* Data */
		*(.data)
	} :text

	. = ALIGN(4096);		/* Init code and data */

	__init_begin = .;
	.text.init : {
		*(.text.init) 
	} :text
	.data.init : { 
		*(.data.init)
	} :text

	. = ALIGN(32);

	__setup_start = .;
	.setup.init : { 
		*(.setup.init) 
	} :text

	__setup_end = .;
	__initcall_start = .;
	.initcall.init : { *(.initcall.init) } :text
	__initcall_end = .;
	. = ALIGN(4096);
	__init_end = .;

	. = ALIGN(16*1024);	/* stack must be aligned with 16KB, now */ 

	__bss_start = .;		/* BSS */
	.bss : {
		*(.bss.stack_aligned)
		*(.bss.page_aligned)
		*(.bss)
	} :text
	_end = . ;


	/* Sections to be discarded */

  	/DISCARD/ : {
  		*(.text.exit)
		*(.data.exit)
		*(.exitcall.exit)
	}
	/* Stabs debugging sections.  */
	.stab 0 : { *(.stab) }
	.stabstr 0 : { *(.stabstr) }
	.stab.excl 0 : { *(.stab.excl) }
	.stab.exclstr 0 : { *(.stab.exclstr) }
	.stab.index 0 : { *(.stab.index) }
	.stab.indexstr 0 : { *(.stab.indexstr) }
	.comment 0 : { *(.comment) }
	
}

