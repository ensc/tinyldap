#include "asn1.h"

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 length */
int fmt_asn1length(char* dest,unsigned long l) {
  /* encoding is either l%128 or (0x80+number of bytes,bytes) */
  int needed=(sizeof l);
  int i;
  if (l<128) {
    if (dest) *dest=l&0x7f;
    return 1;
  }
  for (i=1; i<needed; ++i)
    if (!(l>>(i*8)))
      break;
  if (dest) {
    int j=i;
    *dest=0x80+i; ++dest;
    while (j) {
      --j;
      *dest=((l>>(j*8))&0xff);
      ++dest;
    }
  }
  return i+1;
}
