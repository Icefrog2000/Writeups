## Write-Up OH SEED (HCMUS CTF 2022 - Crypto)

Đây là server của chương trình

```python
import time
import random
import threading
import socketserver

n = 2**32-2  # 32 bits
FLAG_FILE = "flag.txt"
class Service(socketserver.BaseRequestHandler):
    def handle(self):
        self.flag = self.get_flag()
        l = self.gen_random()
        self.send("WELCOME TO RANDOM MACHINE!\n")
        self.send("Here is the first 665 random numbers.\n")
        self.send(" ".join(map(str, l[:-1])) + "\n")
        
        user_input = int(self.receive("Now it's your turn to guess the last random number:\n"))
        #print(user_input, l[-1])
        if (user_input == l[-1]):
            self.send("I hope you're not guessing.\n")
            self.send("Here is your flag.\n")
            self.send(self.flag + "\n")
        else:
            self.send(f"Sorry {l[-1]} != {user_input}\n")
            
    def get_flag(self):
        with open(FLAG_FILE) as f:
            return f.readline()
        
    def gen_random(self):
        random.seed(time.time() + random.randint(0, 999999) + 1312 + hash(self.flag))
        results = [random.randrange(0, n) for i in range(666)]
        return results
    
    def send(self, string: str):
        self.request.sendall(string.encode("utf-8"))

    def receive(self, prompt):
        self.send(prompt)
        return self.request.recv(1000).strip().decode("utf-8")
    
class ThreadedService(socketserver.ThreadingMixIn,
                      socketserver.TCPServer,
                      socketserver.DatagramRequestHandler,):
    pass

def main():
    port = 20202
    host = "192.168.1.8"

    service = Service
    server = ThreadedService((host, port), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    print("Server started on " + str(server.server_address) + "!")
    # Now let the main thread just wait...
    while True:
        time.sleep(10)
        
if __name__ == "__main__":
    main()
```

Vâng, bài này trông bất khả thi vch :)). Mình mất buổi trưa để tìm cách brute force seed. Tự nhiên đến chiều thì nản quá, nghĩ chắc phải có cách gì đó dự đoán được các random tiếp theo khi biết các giá trị random phía trước. Thế nên mình đi hỏi chị google

Bingo, mình đã kiếm được con hàng này
https://github.com/tna0y/Python-random-module-cracker

Sơ qua thì cách dùng như sau, mớm cho nó 624 giá trị random từ trước rồi nó sẽ dự đoán giá trị random thứ 625 cho bạn. Lấy flag thôi
```python
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
```
