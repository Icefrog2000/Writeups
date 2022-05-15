from pwn import *

r = remote('103.245.250.31', 32131)
context.clear(os='linux', arch='x86_64', log_level='debug')

r.sendlineafter(b'file name!\n', b'printme/printme')
r.recvuntil(b'printme/printme \n')
recv = r.recvall()

with open('./printme', 'wb') as f:
    f.write(recv)