#include <asn1.h>

unsigned int fmt_asn1intpayload(char* dest,unsigned long l) {
  unsigned int needed=sizeof l;
  unsigned int i;
  unsigned int fixup;
  for (i=1; i<needed; ++i) {
    if (!(l>>(i*8)))
      break;
  }
  fixup=(l>>((i-1)*8))&0x80 ? 1 : 0;
  if (dest) {
    unsigned int j=i;
    if (fixup) *dest++=0;
    while (j) {
      --j;
      *dest=(l>>(j*8))&0xff;
      ++dest;
    }
  }
  return i+fixup;
}
