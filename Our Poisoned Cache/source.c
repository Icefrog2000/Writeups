
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
        /* WARNING: Subroutine does not return */
        exit(0);
    }
    /* WARNING: Subroutine does not return */
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
