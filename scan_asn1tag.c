#include "asn1.h"

int scan_asn1tag(const char* src,const char* max,enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag) {
  const char* orig=src;
  *tc=(*src&0xC0);
  *tt=(*src&0x20);
  if (max<src) return 0;
  if ((*src & 0x1f) == 0x1f) {
    for (;;) {
      if (src>max) return 0;
      *tag=*tag*128+(*src&0x7F);
      if (!(*src&0x80)) break;
    }
    return (src-orig+1);
  } else {
    *tag=*src&0x1f;
    return 1;
  }
}
