	.file	"/tmp/var.s"
	.text
	.comm	shadow,1104,32
	.globl	take_snapshot
	.type	take_snapshot, @function
take_snapshot:
.LFB0:
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	shadow(%rip), %rax
	movq	defaultEntityLoader_ptr_xmllintdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	handlers_ptr_encodingdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	libxml_is_threaded_ptr_threadsdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	mainthread_ptr_threadsdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	nbCharEncodingHandler_ptr_encodingdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	nbregister_ptr_xmllintdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	once_control_ptr_threadsdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	progresult_ptr_xmllintdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	movq	xmlCurrentExternalEntityLoader_ptr_xmlIOdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	xmlDictInitialized_ptr_dictdc(%rip), %r11
	movb	(%r11), %r11b
	movb	%r11b, (%rax)
	add	$4, %rax
	movq	xmlDictMutex_ptr_dictdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	xmlInputCallbackInitialized_ptr_xmlIOdc(%rip), %r11
	movb	(%r11), %r11b
	movb	%r11b, (%rax)
	add	$4, %rax
	movq	xmlInputCallbackNr_ptr_xmlIOdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	push	%rax
	movl	$480, %edx
	movq	xmlInputCallbackTable_ptr_xmlIOdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$480, %rax
	movq	xmlMemInitialized_ptr_xmlmemorydc(%rip), %r11
	movb	(%r11), %r11b
	movb	%r11b, (%rax)
	add	$4, %rax
	movq	xmlMemMutex_ptr_xmlmemorydc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	xmlOutputCallbackInitialized_ptr_xmlIOdc(%rip), %r11
	movb	(%r11), %r11b
	movb	%r11b, (%rax)
	add	$4, %rax
	movq	xmlOutputCallbackNr_ptr_xmlIOdc(%rip), %r11
	mov	(%r11), %r11d
	mov	%r11d, (%rax)
	add	$4, %rax
	push	%rax
	movl	$480, %edx
	movq	xmlOutputCallbackTable_ptr_xmlIOdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$480, %rax
	movq	xmlParserInitialized_ptr_parserdc(%rip), %r11
	movb	(%r11), %r11b
	movb	%r11b, (%rax)
	add	$4, %rax
	movq	xmlThrDefMutex_ptr_globalsdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	xmlUTF16BEHandler_ptr_encodingdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	xmlUTF16LEHandler_ptr_encodingdc(%rip), %r11
	movq	(%r11), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	xmlXPathNAN(%rip), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	xmlXPathNINF(%rip), %r11
	movq	%r11, (%rax)
	add	$8, %rax
	movq	xmlXPathPINF(%rip), %r11
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
	movq	defaultEntityLoader_ptr_xmllintdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	handlers_ptr_encodingdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	libxml_is_threaded_ptr_threadsdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	mainthread_ptr_threadsdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	nbCharEncodingHandler_ptr_encodingdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	nbregister_ptr_xmllintdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	once_control_ptr_threadsdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	progresult_ptr_xmllintdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	movq	xmlCurrentExternalEntityLoader_ptr_xmlIOdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	xmlDictInitialized_ptr_dictdc(%rip), %r11
	movb	(%rax), %r10b
	movb	%r10b, (%r11)
	add	$4, %rax
	movq	xmlDictMutex_ptr_dictdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	xmlInputCallbackInitialized_ptr_xmlIOdc(%rip), %r11
	movb	(%rax), %r10b
	movb	%r10b, (%r11)
	add	$4, %rax
	movq	xmlInputCallbackNr_ptr_xmlIOdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	push	%rax
	movl	$480, %edx
	movq	xmlInputCallbackTable_ptr_xmlIOdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$480, %rax
	movq	xmlMemInitialized_ptr_xmlmemorydc(%rip), %r11
	movb	(%rax), %r10b
	movb	%r10b, (%r11)
	add	$4, %rax
	movq	xmlMemMutex_ptr_xmlmemorydc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	xmlOutputCallbackInitialized_ptr_xmlIOdc(%rip), %r11
	movb	(%rax), %r10b
	movb	%r10b, (%r11)
	add	$4, %rax
	movq	xmlOutputCallbackNr_ptr_xmlIOdc(%rip), %r11
	mov	(%rax), %r10d
	mov	%r10d, (%r11)
	add	$4, %rax
	push	%rax
	movl	$480, %edx
	movq	xmlOutputCallbackTable_ptr_xmlIOdc(%rip), %rsi
	movq	%rax, %rdi
	call	memcpy@PLT
	pop	%rax
	add	$480, %rax
	movq	xmlParserInitialized_ptr_parserdc(%rip), %r11
	movb	(%rax), %r10b
	movb	%r10b, (%r11)
	add	$4, %rax
	movq	xmlThrDefMutex_ptr_globalsdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	xmlUTF16BEHandler_ptr_encodingdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	xmlUTF16LEHandler_ptr_encodingdc(%rip), %r11
	movq	(%rax), %r10
	movq	%r10, (%r11)
	add	$8, %rax
	movq	(%rax), %r11
	movq	 %r11, xmlXPathNAN(%rip)
	add	$8, %rax
	movq	(%rax), %r11
	movq	 %r11, xmlXPathNINF(%rip)
	add	$8, %rax
	movq	(%rax), %r11
	movq	 %r11, xmlXPathPINF(%rip)
	add	$8, %rax
	popq	%rbp
	ret
.LFE1:
	.size   restore_snapshot, .-restore_snapshot
