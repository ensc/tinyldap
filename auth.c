#ifdef __FreeBSD__
#include <sys/types.h>
#endif
#ifdef __dietlibc__
#include <md5.h>
#else
#include <openssl/md5.h>
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#endif
#include "ldap.h"
#include "auth.h"
#include "str.h"
#include "textcode.h"

int check_password(const char* fromdb,struct string* plaintext) {
  if (str_start(fromdb,"{MD5}")) {
    char digest[17];
    char md5[40];
    MD5_CTX c;
    MD5Init(&c);
    MD5Update(&c,plaintext->s,plaintext->l);
    MD5Final(digest,&c);
    digest[16]=0;
    md5[fmt_base64(md5,digest,16)]=0;
    if (str_equal(md5,fromdb+5))
      return 1;
  }
  return 0;
}
