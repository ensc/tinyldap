#include <md5.h>
#include "ldap.h"
#include "auth.h"
#include "str.h"
#include "textcode.h"
#include "byte.h"

int check_password(const char* fromdb,struct string* plaintext) {
  if (str_start(fromdb,"{MD5}")) {
    char digest[17];
    char md5[40];
    MD5_CTX c;
    MD5Init(&c);
    MD5Update(&c,plaintext->s,plaintext->l);
    MD5Final(digest,&c);
    digest[16]=0;
    fmt_hexdump(md5,digest,16);
    if (byte_equal(md5,32,fromdb+5))
      return 1;
  }
  return 0;
}
