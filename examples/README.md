# Examples

Shellcode examples.

## nop

x64:

```asm
nop
nop
nop
nop
```

## ret0x12345678

x64:

```asm
mov eax, 0x12345678
ret
```

## memcpy

x64 Linux:

```asm
xor rax, rax
mov bl, byte ptr [rsi+rax]
mov byte ptr [rdi+rax], bl
inc rax
cmp rax, rdx
jne -12
mov rax, rdi
ret
```

x64 Windows:

```asm
xor rax, rax
mov bl, byte ptr [rdx+rax]
mov byte ptr [rcx+rax], bl
inc rax
cmp rax, r8
jne -12
mov rax, rcx
ret
```
