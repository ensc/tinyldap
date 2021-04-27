#define _XOPEN_SOURCE
#define _DEFAULT_SOURCE
#include <sys/types.h>
#ifdef __dietlibc__
#include <md5.h>
#else
#include <openssl/md5.h>
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#endif
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <ctype.h>
#include "ldap.h"
#include "auth.h"
#include <libowfat/str.h>
#include <libowfat/textcode.h>
#include <libowfat/byte.h>

int check_password(const char* fromdb,struct string* plaintext) {
  if (str_start(fromdb,"{MD5}")) {
    unsigned char digest[17];
    char md5[40];
    MD5_CTX c;
    MD5Init(&c);
    MD5Update(&c,(unsigned char*)plaintext->s,plaintext->l);
    MD5Final(digest,&c);
    digest[16]=0;
    md5[fmt_base64(md5,(char*)digest,16)]=0;
    if (str_equal(md5,fromdb+5))
      return 1;
  }
  if (plaintext->l<100 && ((fromdb[0]=='$' && fromdb[2]=='$' && isdigit(fromdb[1])) || strlen(fromdb)==13)) {
    char* c=alloca(plaintext->l+1);
    byte_copy(c,plaintext->l,plaintext->s);
    c[plaintext->l]=0;
    if (str_equal(crypt(c,fromdb),fromdb)) return 1;
  }
  if (plaintext->l == strlen(fromdb) && byte_equal(plaintext->s,plaintext->l,fromdb))
    return 1;
  return 0;
}
