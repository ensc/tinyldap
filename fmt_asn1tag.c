#include "asn1.h"

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 tags */
int fmt_asn1tag(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,unsigned long l) {
  /* encoding is either l%128 or (0x80+number of bytes,bytes) */
  int needed=(sizeof l)+1;
  int i;
  if (l<0x1f) {
    if (dest) *dest=(int)tc+(int)tt+(l&0x1f);
    return 1;
  }
  for (i=1; i<needed; ++i)
    if (!(l>>(i*7)))
      break;
  if (dest) {
    int j=i;
    *dest=(int)tc+(int)tt+0x1f; ++dest;
    while (j) {
      --j;
      *dest=((l>>(j*7))&0x7f) + (j?0x80:0);
      ++dest;
    }
  }
  return i+1;
}
