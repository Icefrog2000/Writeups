
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

undefined8 main(void) {
    __uid_t __suid;
    __uid_t __euid;
    __uid_t __ruid;
    size_t sVar1;
    char *local_a0;
    undefined8 local_98;
    undefined8 local_90;
    undefined8 local_88;
    undefined8 local_80;
    undefined8 local_78;
    undefined8 local_70;
    undefined8 local_68;
    undefined8 local_60;
    undefined8 local_58;
    undefined8 local_50;
    undefined8 local_48;
    undefined8 local_40;
    undefined8 local_38;
    undefined4 local_30;
    undefined2 local_2c;
    undefined local_2a;
    undefined4 local_1c;

    local_98 = 0;
    local_90 = 0;
    local_88 = 0;
    local_80 = 0;
    local_78 = 0;
    local_70 = 0;
    local_68 = 0;
    local_60 = 0;
    local_58 = 0;
    local_50 = 0;
    local_48 = 0;
    local_40 = 0;
    local_38 = 0;
    local_30 = 0;
    local_2c = 0;
    local_2a = 0;
    __suid = geteuid();
    __euid = geteuid();
    __ruid = geteuid();
    setresuid(__ruid, __euid, __suid);
    setvbuf(stdout, (char *)0x0, 2, 0);
    puts("Please enter the file name!");
    local_a0 = (char *)0x0;
    local_1c = 0;
    local_a0 = (char *)malloc(100);
    gets(local_a0);
    sVar1 = strlen(local_a0);
    if (100 < sVar1) {
        puts("Filename too long !. Maximum is 100 characters! ");
        exit(1);
    }
    secure(&local_a0);
    printf("Your sanitized filename %s \n", local_a0);
    sprintf((char *)&local_98, "%s%s", "/bin/cat ", local_a0);
    system((char *)&local_98);
    free(local_a0);
    return 0;
}
