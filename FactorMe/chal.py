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