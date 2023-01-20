	.file	"/tmp/var.s"
	.text
	.comm	shadow,500,32
	.globl	take_snapshot
	.type	take_snapshot, @function
take_snapshot:
.LFB0:
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	shadow(%rip), %rax
	push	%rax
	movl	$160, %edx
	movq	image_ptr_optimdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$160, %rax
	movq	operation_ptr_optipngdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	opng_optimize_impl.bakfile_name_ptr_optimdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	opng_optimize_impl.infile_name_local_ptr_optimdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	opng_optimize_impl.infile_ptr_optimdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	opng_optimize_impl.new_outfile_ptr_optimdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	opng_optimize_impl.outfile_name_ptr_optimdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	push	%rax
	movl	$120, %edx
	movq	options_ptr_optipngdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$120, %rax
	push	%rax
	movl	$112, %edx
	movq	process_ptr_optimdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$112, %rax
	movq	read_info_ptr_ptr_optimdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	read_ptr_ptr_optimdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	start_of_line_ptr_optipngdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	summary_ptr_optimdc(%rip), %r11
	movups	(%r11), %xmm8
	movups	%xmm8, (%rax)
	add	$16, %rax
	push	%rax
	movl	$24, %edx
	movq	the_exception_context_ptr_optimdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$24, %rax
	movq	usr_panic_ptr_optimdc(%rip), %r11
	movq	(%r11), %r11
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
	push	%rax
	movl	$160, %edx
	movq	image_ptr_optimdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$160, %rax
	movq	operation_ptr_optipngdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	opng_optimize_impl.bakfile_name_ptr_optimdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	opng_optimize_impl.infile_name_local_ptr_optimdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	opng_optimize_impl.infile_ptr_optimdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	opng_optimize_impl.new_outfile_ptr_optimdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	opng_optimize_impl.outfile_name_ptr_optimdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	push	%rax
	movl	$120, %edx
	movq	options_ptr_optipngdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$120, %rax
	push	%rax
	movl	$112, %edx
	movq	process_ptr_optimdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$112, %rax
	movq	read_info_ptr_ptr_optimdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	read_ptr_ptr_optimdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	start_of_line_ptr_optipngdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	summary_ptr_optimdc(%rip), %r11
	movups	(%rax), %xmm8
	movups	%xmm8, (%r11)
	add	$16, %rax
	push	%rax
	movl	$24, %edx
	movq	the_exception_context_ptr_optimdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$24, %rax
	movq	usr_panic_ptr_optimdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	popq	%rbp
	ret
.LFE1:
	.size   restore_snapshot, .-restore_snapshot
