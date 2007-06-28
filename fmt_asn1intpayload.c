#include <asn1.h>

size_t fmt_asn1intpayload(char* dest,unsigned long l) {
  size_t needed=sizeof l,i,fixup;
  for (i=1; i<needed; ++i) {
    if (!(l>>(i*8)))
      break;
  }
  fixup=(l>>((i-1)*8))&0x80 ? 1 : 0;
  if (dest) {
    size_t j=i;
    if (fixup) *dest++=0;
    while (j) {
      --j;
      *dest=(l>>(j*8))&0xff;
      ++dest;
    }
  }
  return i+fixup;
}
