#include <asn1.h>

int fmt_asn1intpayload(char* dest,unsigned long l) {
  int needed=sizeof l;
  int i;
  for (i=1; i<needed; ++i) {
    if (!(l>>(i*8)))
      break;
  }
  if (dest) {
    int j=i;
    while (j) {
      --j;
      *dest=(l>>(j*8))&0xff;
      ++dest;
    }
  }
  return i;
}
