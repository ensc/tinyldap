#include "asn1.h"

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 tags */
size_t fmt_asn1tag(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,unsigned long l) {
  /* encoding is either l%128 or (0x1f,...) */
  if (l<0x1f) {
    if (dest) *dest=(int)tc+(int)tt+(l&0x1f);
    return 1;
  }
  if (dest) {
    *dest=(int)tc+(int)tt+0x1f; ++dest;
  }
  return fmt_asn1tagint(dest,l)+1;
}
