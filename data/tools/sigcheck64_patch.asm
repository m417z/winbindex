; Patched with the following changes
; with Multiline Ultimate Assembler:
; Allows to retrieve signing date of
; a PE file even if signature is invalid.
; Print raw timestamp.
; Force Unicode output.
; Tweaked -i option regarding invalid signatures.
; Verify MZ file PE offset to be valid.

; In addition, manually cleared the exceptions
; directory to stop swallowing exceptions.

; Patch out signature error check
; before printing date
<$.1DAE4>
	nop
	nop

; New sprintf argument: the FILETIME value
<$.1C831>
	mov r8, qword ptr [rdx]
	jmp $.1C8B1
	nop
	nop
	nop

; New sprintf format
<$.0D09A0>
	L"%llu\0"

; Force Unicode
<$.3945>
	jmp short $$3974
	nop
	nop
	nop
	nop

; -i option: print signing date even in case
; of a validation error
<$.1C39F>
	nop
	nop

; -i option: print all signatures even in case
; of a validation error
<$.1DC4D>
	jmp @cave1
	nop
	nop
	nop
@back1:

; init signing date with 0
<$.0AA77>
	jmp @cave2
	nop
	nop
@back2:

; verify mz file pe offset
<$.1B302>
	jmp @cave3
	nop
	nop
	nop
@back3:

; replace signing date with 0 if it's just the current date
<$.0A06C>
	jmp @cave4
	nop
@back4:

<$.0A088>
	nop
	nop
	nop
	nop

<$.0C090..$.0C500>
	int3

@cave1:
	cmp eax, 0x800B0100 ; TRUST_E_NOSIGNATURE
	je $$1DEAA
	cmp qword ptr ss:[rbp-0x68], 0
	je $$1DEAA
	cmp ebx, 10
	ja $$1DEAA ; give up after 10 errors
	jmp @back1
	
@cave2:
	mov rax, qword ptr ss:[rbp+0xE8]
	mov qword ptr [rax], 0
	jmp @back2
	
@cave3:
	push rdx ; save
	push 0 ; for temp storage
	
	mov rcx, rdi
	lea rdx, qword ptr [rsp]
	call qword ptr ds:[$$0C3390] ;; GetFileSizeEx
	
	pop rcx ; size
	pop rdx ; restore
	
	movsxd rax, dword ptr ds:[rdx+0x3C]
	lea r8, qword ptr [rax+0x0C]
	cmp r8, rcx
	ja $$1B36C ; offset too large
	
	lea rcx, ds:[rax+rdx*1]
	jmp @back3

comment ~
    if ((pTimeSgnr =
            WTHelperGetProvSignerFromChain(ProviderData(), 0, TRUE, 0)) &&
        (pTimeSgnr->dwSignerType & SGNR_TYPE_TIMESTAMP) &&
        (pSgnr = WTHelperGetProvSignerFromChain(ProviderData(), 0, FALSE, 0)))
~
@cave4:
	push r12 ; save rcx
	push r13 ; is date valid
	mov r12, rcx
	xor r13d, r13d

	mov r8d, 1
	call qword ptr ds:[$$10BD10]

	test rax, rax
	jz short @f

	test dword [rax+0x18], 0x10 ; pTimeSgnr->dwSignerType & SGNR_TYPE_TIMESTAMP
	jz short @f

	mov r13d, 1 ; timestamp is valid
@@:

	xor r9d, r9d
	xor r8d, r8d
	xor edx, edx
	mov rcx, r12
	call qword ptr ds:[$$10BD10]

	xor ecx, ecx ; timestamp

	test rax, rax
	jz short @f

	test r13d, r13d
	jz short @f
	mov rcx, qword ptr ds:[rax+0x4]
@@:

	pop r13
	pop r12
	jmp @back4

	!pad 0xcc
