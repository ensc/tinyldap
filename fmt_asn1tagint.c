#include "asn1.h"

size_t fmt_asn1tagint(char* dest,unsigned long l) {
  size_t needed=((sizeof l)*7)/8,i;
  for (i=1; i<needed; ++i)
    if (!(l>>(i*7)))
      break;
  if (dest) {
    size_t j=i;
    while (j) {
      --j;
      *dest=((l>>(j*7))&0x7f) + (j?0x80:0);
      ++dest;
    }
  }
  return i;
}
