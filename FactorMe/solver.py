from pwn import *
from decimal import Decimal, getcontext
import math
import mpmath

getcontext().prec = 2000
mpmath.mp.dps = 2000

# context.log_level = 'debug'

def kiem_tra_thuong(i, j, N, phi):
    decN = Decimal(N)
    decPhi = Decimal(phi)
    thuong = decPhi/decN
    min = Decimal(2**(i - 1))
    max = Decimal((2**i) - 1)
    thuong_min = (1 - (1/min))**j
    thuong_max = (1 - (1/max))**j
    if thuong_min < thuong and thuong < thuong_max:
        return True
    return False

def getN(N, phi):
    for i in range(96, 256):
        for j in range(5, 20):
            min = 2**(i - 1)
            max = (2**i) - 1
            N_min = min**j
            N_max = max**j
            phi_min = (min - 1)**j
            phi_max = (max - 1)**j
            if N_min < N and N < N_max:
                if phi_min < phi and N < phi_max:
                    if kiem_tra_thuong(i, j, N, phi):
                        return j

while True:
    try:
        r = remote('103.245.250.31', 30521)
        for i in range(60):
            log.info('Count: %d' % i)
            r.recvuntil(b'This is public key: ')
            N = int(r.recvline()[:-1])
            r.recvuntil(b'Here is a little hint phi(N): ')
            phi = int(r.recvline()[:-1])
            result = getN(N, phi)
            r.sendlineafter(b'How many primes factors does N have: ', str(result).encode())
            if i == 59:
                print(r.recv())
                print(r.recv())
                print(r.recv())
                exit()
    except:
        r.close()
