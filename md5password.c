#include <md5.h>
#include "buffer.h"
#include "str.h"
#include "textcode.h"

int main(int argc,char* argv[]) {
  char digest[17];
  char md5[40];
  int i;
  for (i=1; i<argc; ++i) {
    MD5_CTX c;
    MD5Init(&c);
    MD5Update(&c,argv[i],strlen(argv[i]));
    MD5Final(digest,&c);
    digest[16]=0;
    md5[fmt_base64(md5,digest,16)]=0;
    buffer_puts(buffer_1,argv[i]);
    buffer_puts(buffer_1," -> {MD5}");
    buffer_puts(buffer_1,md5);
    buffer_putnlflush(buffer_1);
  }
  return 0;
}
