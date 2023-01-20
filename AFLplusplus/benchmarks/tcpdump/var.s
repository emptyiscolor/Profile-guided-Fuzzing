	.file	"./var.s"
	.text
	.comm	shadow,852544,32
	.globl	take_snapshot
	.type	take_snapshot, @function
take_snapshot:
.LFB0:
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	shadow(%rip), %rax
	push	%rax
	movl	$1025, %edx
	movq	bittok2str_internal.buf_ptr_dsutilmprintdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$1028, %rax
	push	%rax
	movl	$163840, %edx
	movq	bytestringtable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$163840, %rax
	movq	ddpskt_string.buf_ptr_dsprintmatalkdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	push	%rax
	movl	$131072, %edx
	movq	enametable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$131072, %rax
	push	%rax
	movl	$131072, %edx
	movq	h6nametable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$131072, %rax
	push	%rax
	movl	$98304, %edx
	movq	hnametable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$98304, %rax
	push	%rax
	movl	$98304, %edx
	movq	hnametable_ptr_dsprintmatalkdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$98304, %rax
	movq	infodelay_ptr_dstcpdumpdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	push	%rax
	movl	$17, %edx
	movq	intoa.buf_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$20, %rax
	push	%rax
	movl	$256, %edx
	movq	ipxaddr_string.line_ptr_dsprintmipxdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$256, %rax
	movq	lastconn_ptr_dsprintmsldc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	push	%rax
	movl	$2048, %edx
	movq	lastlen_ptr_dsprintmsldc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$2048, %rax
	movq	newh6namemem.num_ptr_dsaddrtonamedc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	newh6namemem.ptr_ptr_dsaddrtonamedc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	newhnamemem.num_ptr_dsaddrtonamedc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	newhnamemem.ptr_ptr_dsaddrtonamedc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	packets_captured_ptr_dstcpdumpdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	pd_ptr_dstcpdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	program_name_ptr_dstcpdumpdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	push	%rax
	movl	$29408, %edx
	movq	tcp_seq_hash4_ptr_dsprintmtcpdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$29408, %rax
	movq	timeout_ptr_dstcpdumpdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	push	%rax
	movl	$512, %edx
	movq	tok2str.buf_ptr_dsutilmprintdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$512, %rax
	movq	tok2str.idx_ptr_dsutilmprintdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	push	%rax
	movl	$98304, %edx
	movq	tporttable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$98304, %rax
	push	%rax
	movl	$98304, %edx
	movq	uporttable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$98304, %rax
	mov	optind(%rip), %r11d
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
	push	%rax
	movl	$1025, %edx
	movq	bittok2str_internal.buf_ptr_dsutilmprintdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$1028, %rax
	push	%rax
	movl	$163840, %edx
	movq	bytestringtable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$163840, %rax
	movq	ddpskt_string.buf_ptr_dsprintmatalkdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	push	%rax
	movl	$131072, %edx
	movq	enametable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$131072, %rax
	push	%rax
	movl	$131072, %edx
	movq	h6nametable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$131072, %rax
	push	%rax
	movl	$98304, %edx
	movq	hnametable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$98304, %rax
	push	%rax
	movl	$98304, %edx
	movq	hnametable_ptr_dsprintmatalkdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$98304, %rax
	movq	infodelay_ptr_dstcpdumpdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	push	%rax
	movl	$17, %edx
	movq	intoa.buf_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$20, %rax
	push	%rax
	movl	$256, %edx
	movq	ipxaddr_string.line_ptr_dsprintmipxdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$256, %rax
	movq	lastconn_ptr_dsprintmsldc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	push	%rax
	movl	$2048, %edx
	movq	lastlen_ptr_dsprintmsldc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$2048, %rax
	movq	newh6namemem.num_ptr_dsaddrtonamedc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	newh6namemem.ptr_ptr_dsaddrtonamedc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	newhnamemem.num_ptr_dsaddrtonamedc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	newhnamemem.ptr_ptr_dsaddrtonamedc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	packets_captured_ptr_dstcpdumpdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	pd_ptr_dstcpdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	program_name_ptr_dstcpdumpdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	push	%rax
	movl	$29408, %edx
	movq	tcp_seq_hash4_ptr_dsprintmtcpdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$29408, %rax
	movq	timeout_ptr_dstcpdumpdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	push	%rax
	movl	$512, %edx
	movq	tok2str.buf_ptr_dsutilmprintdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$512, %rax
	movq	tok2str.idx_ptr_dsutilmprintdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	push	%rax
	movl	$98304, %edx
	movq	tporttable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$98304, %rax
	push	%rax
	movl	$98304, %edx
	movq	uporttable_ptr_dsaddrtonamedc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$98304, %rax
	mov	(%rax), %r11d
	mov	 %r11d, optind(%rip)
	add	$4, %rax
	popq	%rbp
	ret
.LFE1:
	.size   restore_snapshot, .-restore_snapshot
