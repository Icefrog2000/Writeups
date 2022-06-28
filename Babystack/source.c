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
