	.file	"var.s"
	.text
	.comm	shadow,8932,32
	.globl	take_snapshot
	.type	take_snapshot, @function
take_snapshot:
.LFB0:
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	shadow(%rip), %rax
	movq	_bfd_error_program_name_ptr_bfddc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	abbrev_lists_ptr_dsdwarfdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	bfd_error_ptr_bfddc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	bfd_id_counter_ptr_opnclsdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	bfd_last_cache_ptr_cachedc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	compare_section_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	cu_abbrev_map_ptr_dsdwarfdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	cu_count_ptr_dsdwarfdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	cu_sets_ptr_dsdwarfdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	cu_tu_indexes_read_ptr_dsdwarfdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	dynsymcount_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	dynsyms_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	exit_status_ptr_dsobjdumpdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	first_break_ptr_dsxmallocdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	first_dwo_info_ptr_dsdwarfdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	push	%rax
	movl	$256, %edx
	movq	level_type_signed_ptr_dsdwarfdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$256, %rax
	push	%rax
	movl	$1920, %edx
	movq	long_options_ptr_dsobjdumpdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$1920, %rax
	movq	max_open_files_ptr_cachedc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	name_ptr_dsxmallocdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	next_free_abbrev_map_entry_ptr_dsdwarfdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	open_files_ptr_cachedc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	prev_discriminator_ptr_dsobjdumpdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	prev_functionname_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	prev_line_ptr_dsobjdumpdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	print_files_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	sanitize_string.buffer_len_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	sanitize_string.buffer_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	shndx_pool_ptr_dsdwarfdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	shndx_pool_size_ptr_dsdwarfdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	shndx_pool_used_ptr_dsdwarfdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	sorted_symcount_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	push	%rax
	movl	$256, %edx
	movq	sum_block_ptr_tekhexdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$256, %rax
	movq	symcount_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	syms_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	synthcount_ptr_dsobjdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	tu_count_ptr_dsdwarfdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	tu_sets_ptr_dsdwarfdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	mov	_bfd_section_id(%rip), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	push	%rax
	movl	$1184, %edx
	leaq	_bfd_std_section(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$1184, %rax
	movups	bfd_default_vector(%rip), %xmm8
	movups	%xmm8, (%rax)
	add	$16, %rax
	movq	byte_get(%rip), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	push	%rax
	movl	$5040, %edx
	leaq	debug_displays(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$5040, %rax
	mov	do_follow_links(%rip), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	first_separate_info(%rip), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	mov	optind(%rip), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	program_name(%rip), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	popq	%rbp
	ret
.LFE0:
	.size   take_snapshot, .-take_snapshot
	.globl	restore_snapshot
	.type	restore_snapshot, @function
restore_snapshot:
.LFB1:
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	shadow(%rip), %rax
	movq	_bfd_error_program_name_ptr_bfddc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	abbrev_lists_ptr_dsdwarfdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	bfd_error_ptr_bfddc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	bfd_id_counter_ptr_opnclsdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	bfd_last_cache_ptr_cachedc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	compare_section_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	cu_abbrev_map_ptr_dsdwarfdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	cu_count_ptr_dsdwarfdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	cu_sets_ptr_dsdwarfdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	cu_tu_indexes_read_ptr_dsdwarfdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	dynsymcount_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	dynsyms_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	exit_status_ptr_dsobjdumpdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	first_break_ptr_dsxmallocdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	first_dwo_info_ptr_dsdwarfdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	push	%rax
	movl	$256, %edx
	movq	level_type_signed_ptr_dsdwarfdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$256, %rax
	push	%rax
	movl	$1920, %edx
	movq	long_options_ptr_dsobjdumpdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$1920, %rax
	movq	max_open_files_ptr_cachedc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	name_ptr_dsxmallocdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	next_free_abbrev_map_entry_ptr_dsdwarfdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	open_files_ptr_cachedc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	prev_discriminator_ptr_dsobjdumpdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	prev_functionname_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	prev_line_ptr_dsobjdumpdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	print_files_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	sanitize_string.buffer_len_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	sanitize_string.buffer_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	shndx_pool_ptr_dsdwarfdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	shndx_pool_size_ptr_dsdwarfdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	shndx_pool_used_ptr_dsdwarfdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	sorted_symcount_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	push	%rax
	movl	$256, %edx
	movq	sum_block_ptr_tekhexdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$256, %rax
	movq	symcount_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	syms_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	synthcount_ptr_dsobjdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	tu_count_ptr_dsdwarfdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	tu_sets_ptr_dsdwarfdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	mov	(%rax), %r11d
	mov	 %r11d, _bfd_section_id(%rip)
	add	$4, %rax
	push	%rax
	movl	$1184, %edx
	movq	%rax, %rsi
	leaq	_bfd_std_section(%rip), %rdi
	call	memcpy@PLT
	pop	%rax
	add	$1184, %rax
	movups	(%rax), %xmm8
	movups	 %xmm8, bfd_default_vector(%rip)
	add	$16, %rax
	movq	(%rax), %r11
	movq	 %r11, byte_get(%rip)
	add	$8, %rax
	push	%rax
	movl	$5040, %edx
	movq	%rax, %rsi
	leaq	debug_displays(%rip), %rdi
	call	memcpy@PLT
	pop	%rax
	add	$5040, %rax
	mov	(%rax), %r11d
	mov	 %r11d, do_follow_links(%rip)
	add	$4, %rax
	movq	(%rax), %r11
	movq	 %r11, first_separate_info(%rip)
	add	$8, %rax
	mov	(%rax), %r11d
	mov	 %r11d, optind(%rip)
	add	$4, %rax
	movq	(%rax), %r11
	movq	 %r11, program_name(%rip)
	add	$8, %rax
	popq	%rbp
	ret
.LFE1:
	.size   restore_snapshot, .-restore_snapshot
