#include "asn1.h"

size_t scan_asn1tag(const char* src,const char* max,enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag) {
  const char* orig=src;
  *tc=(*src&0xC0);
  *tt=(*src&0x20);
  if (max<src) return 0;
/* The lower 5 bits are the tag, unless it's 0x1f, in which case the
 * next bytes are the tag: always take the lower 7 bits; the last byte
 * in the sequence is marked by a cleared high bit */
  if ((*src & 0x1f) == 0x1f) {
    unsigned long l=0;
    for (;;) {
      ++src;
      if (src>max) return 0;
      if (l>(((unsigned long)-1)>>7)) return 0;	/* catch integer overflow */
      l=l*128+(*src&0x7F);
      if (!(*src&0x80)) break;
    }
    *tag=l;
    return (src-orig+1);
  } else {
    *tag=*src&0x1f;
    return 1;
  }
}
