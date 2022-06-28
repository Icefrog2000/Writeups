
void FUN_004015e4(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  return;
}


void FUN_004012a8(char *param_1)

{
  char cVar1;
  size_t sVar2;
  int local_10;
  
  sVar2 = strlen(param_1);
  for (local_10 = 0; local_10 < (int)sVar2; local_10 = local_10 + 1) {
    cVar1 = (char)local_10;
    if ((param_1[local_10] < 'a') || ('z' < param_1[local_10])) {
      if ((param_1[local_10] < '0') || ('9' < param_1[local_10])) {
        if ((param_1[local_10] < 'A') || ('Z' < param_1[local_10])) {
          if ((param_1[local_10] == '%') && (param_1[local_10] == '$')) {
            param_1[local_10] = param_1[local_10] + cVar1 + (char)(local_10 / 7) * -7;
          }
        }
        else {
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


void FUN_00401216(void)

{
  char *pcVar1;
  long in_FS_OFFSET;
  char local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Tell me some funny things!");
  fgets(local_78,0x78,stdin);
  pcVar1 = strstr(local_78,"funny");
  if (pcVar1 != (char *)0x0) {
    FUN_004012a8(local_78);
    printf(local_78);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}


undefined8 FUN_00401649(void)

{
  FUN_004015e4();
  FUN_00401216();
  return 0;
}

