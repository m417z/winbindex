; Patched with the following changes
; with Multiline Ultimate Assembler:
; Allows to retrieve signing date of
; a PE file even if signature is invalid.
; Print raw timestamp.
; Force Unicode output.
; Tweaked -i option regarding invalid signatures.

; Patch out signature error check
; before printing date
<$sigcheck64.1DAE4>
	nop
	nop

; New sprintf argument: the FILETIME value
<$sigcheck64.1C831>
	mov r8, qword ptr [rdx]
	jmp $sigcheck64.1C8B1
	nop
	nop
	nop

; New sprintf format
<$sigcheck64.0D09A0>
	L"%llu\0"

; Force Unicode
<$sigcheck64.3945>
	jmp short $$3974
	nop
	nop
	nop
	nop

; -i option: print signing date even in case
; of a validation error
<$sigcheck64.1C39F>
	nop
	nop

; -i option: print all signatures even in case
; of a validation error
<$sigcheck64.1DC4D>
	jmp @cave1
	nop
	nop
	nop
@back1:

; init signing date with 0
<$sigcheck64.0AA77>
	jmp @cave2
	nop
	nop
@back2:

<$sigcheck64.0C2180>
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
