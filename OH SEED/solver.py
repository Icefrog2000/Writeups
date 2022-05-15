import random
import time
from pwn import *
from randcrack import RandCrack

n = 2**32-2
max = 2**64

time1 = time.time()
r = remote('103.245.250.31', 30620)
rc = RandCrack()

r.recvuntil(b'random numbers.\n')
recv = r.recvuntil(b'Now')[:-4].split(b' ')
recv = [int(i) for i in recv]

for i in range(624):
    rc.submit(recv[i])

for i in range(624, 665):
    rc.predict_randrange(0, n)

r.sendlineafter(b'last random number:\n', str(rc.predict_randrange(0, n)).encode())
print(r.recv())
print(r.recv())
print(r.recv())