#include "asn1.h"

size_t scan_asn1tag(const char* src,const char* max,enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag) {
  if (max<=src) return 0;
  *tc=(*src&0xC0);
  *tt=(*src&0x20);
/* The lower 5 bits are the tag, unless it's 0x1f, in which case the
 * next bytes are the tag: always take the lower 7 bits; the last byte
 * in the sequence is marked by a cleared high bit */
  if ((*src & 0x1f) == 0x1f) {
    size_t res=scan_asn1tagint(src+1,max,tag);
    return res+!!res;	/* add 1 unless it's 0, then leave 0 */
  } else {
    *tag=*src&0x1f;
    return 1;
  }
}
