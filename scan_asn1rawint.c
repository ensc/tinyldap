#include "asn1.h"

int scan_asn1rawint(const char* src,const char* max,unsigned int len,long* l) {
  int i;
  *l=0;
  for (i=0; i<len; ++i) {
    *l=*l*256+*src;
    ++src;
    if (src>max) return 0;
  }
  return len;
}
