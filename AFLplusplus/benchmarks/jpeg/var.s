	.file	"var.s"
	.text
	.comm	shadow,28,32
	.globl	take_snapshot
	.type	take_snapshot, @function
take_snapshot:
.LFB0:
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	shadow(%rip), %rax
	movq	main._B_ptr_ddsdjpegdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	outfilename_ptr_ddsdjpegdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	progname_ptr_ddsdjpegdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	requested_fmt_ptr_ddsdjpegdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
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
	movq	main._B_ptr_ddsdjpegdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	outfilename_ptr_ddsdjpegdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	progname_ptr_ddsdjpegdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	requested_fmt_ptr_ddsdjpegdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	popq	%rbp
	ret
.LFE1:
	.size   restore_snapshot, .-restore_snapshot
