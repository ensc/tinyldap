#include "asn1.h"

int scan_asn1length(const char* src,const char* max,unsigned long* length) {
  const char* orig=src;
  if (src>max) return 0;
  if (*src&0x80) {
    int chars=*src&0x7f;
    long l=0;
    while (chars>0) {
      if (++src>=max) return 0;
      l=l*256+*src;
      --chars;
    }
    *length=l;
  } else
    *length=*src&0x7f;
  return src-orig+1;
}
