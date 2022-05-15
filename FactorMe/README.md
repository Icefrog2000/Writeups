## Write-Up FactorMe (HCMUS CTF 2022 - Crypto)

Đây là code của server
```python
import signal
from Crypto.Util.number import getPrime
from random import randint
from math import prod

FLAG = open('../flag.txt').read()
ROUNDS = 60

class Challenge:
    def __init__(self):
        self.banner = 'Hello, could you factor this with a hint ???'
        print(self.banner)
        
    def generateN(self, n_bits, n_primes):
        primes = set()
        while len(primes) < n_primes:
            p = getPrime(n_bits)
            primes.add(p)
        return list(primes), prod(primes)

    def getParam(self):
        n_bits = randint(96, 256)
        n_primes = randint(5, 20)
        return n_bits, n_primes
    
    def main(self):
        # N and phi generation tooks approximately 20 - 22s 
        try:
            signal.alarm(45)
            for i in range(ROUNDS):
                n_bits, n_primes = self.getParam()
                primes, N = self.generateN(n_bits, n_primes)
                phi = prod([p - 1 for p in primes])

                print(f'This is public key: {N}')
                print(f'Here is a little hint phi(N): {phi}')

                try:
                    primes_cnt = int(input('How many primes factors does N have'))
                    if primes_cnt == len(primes):
                        if i == ROUNDS - 1:
                            print("Great job. Here is your flag:", FLAG)
                        else:
                            print("Very good. How about this one.")
                    else:
                        print("Wrong numbers of prime factors. Lucky next time")
                        exit(0)
                except:
                    print("What did you sent to me hecker ??? ")
                    exit(0)
        except:
            print("Too slow")

chal = Challenge()
chal.main()
```

Nó chọn ngẫu nhiên `n_primes` số nguyên tố, mỗi số nguyên tố nằm trong khoảng 96-255 bit.
Server trả về tích của các số nguyên tố (N), giá trị hàm phi N (phiN) và yêu cầu bạn đoán xem nó đã dùng bao nhiều số nguyên tố. Đoán đúng 60 lần thì có flag

Gọi min là giá trị bé nhất của 1 số nguyên tố với n_bits, tương tự bới max
Suy ra min = 2^(n_bits - 1)
       max = 2n_bits - 1
        
Ý tưởng đầu tiên là tìm số `n_bits` và `n_primes` sao cho:
+ min^n_primes < N < max^n_primes
+ Tương tư với phiN: (min - 1)^n_primes < phiN < (max - 1)^n_primes

Khi đặt điều kiện thế này thì mình thu được khoảng 8 cặp n_bits và n_primes, nên mình vẫn cần một điều kiện ngặt hơn để loại trừ các cặp n_bits và n_primes sai. Ý tưởng sẽ là ràng buộc N và phiN

Ràng buộc thì chỉ có thể bằng phép hiệu N - phiN hoặc N / phiN. Cơ mà phép chia dễ thực hiện hơn

Ta được điều kiện mới: (1 - 1/min)^n_primes < N/phiN < (1 - 1/max)^n_primes
Cơ mà nếu code bằng python như bình thường thì sai hết tại vị các phép chia python sẽ làm tròn ở mức độ nào đó. Đây là lời giải của mình

```python
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
```

Cơ mà vẫn có trường hợp có tận nhiều cặp `n_bits` và `n_primes` thỏa mãn 3 điều kiện trên, dẫn đến v mình trả lời đúng đến lần thứ 54 rồi mà vẫn bị chết, nên để lấy flag thì tùy vào nhân phẩm của các bạn
