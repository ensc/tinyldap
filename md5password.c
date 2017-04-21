#include <sys/types.h>
#ifdef __dietlibc__
#include <md5.h>
#else
#include <openssl/md5.h>
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#endif
#include <string.h>
#include <libowfat/buffer.h>
#include <libowfat/str.h>
#include <libowfat/textcode.h>

int main(int argc,char* argv[]) {
  unsigned char digest[17];
  char md5[40];
  int i;
  for (i=1; i<argc; ++i) {
    MD5_CTX c;
    MD5Init(&c);
    MD5Update(&c,(unsigned char*)argv[i],str_len(argv[i]));
    MD5Final(digest,&c);
    digest[16]=0;
    md5[fmt_base64(md5,(char*)digest,16)]=0;
    buffer_puts(buffer_1,argv[i]);
    buffer_puts(buffer_1," -> {MD5}");
    buffer_puts(buffer_1,md5);
    buffer_putnlflush(buffer_1);
  }
  return 0;
}
