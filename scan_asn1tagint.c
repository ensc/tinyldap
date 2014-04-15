#include "asn1.h"

size_t scan_asn1tagint(const char* src,const char* max,unsigned long* val) {
  const char* orig=src;
  unsigned long l=0;
  if (src==max || (unsigned char)src[0]==0x80) return 0;	/* catch non-minimal encoding */
  for (;; ++src) {
    if (src>=max) return 0;
    if (l>>(sizeof(l)*8-7)) return 0;	/* catch integer overflow */
    l=l*128+(*src&0x7F);
    if (!(*src&0x80)) break;
  }
  *val=l;
  return src-orig+1;
}
