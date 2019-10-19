#include "asn1.h"

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 tags */
size_t fmt_asn1tag(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,unsigned long l) {
  /* encoding is either l%128 or (0x1f,...) */
  if (l<0x1f) {
    if (dest) *dest=tc + tt + l;
    return 1;
  }
  if (dest) {
    *dest=tc + tt + 0x1f;	// 0x1f signals variable length encoding follows
    ++dest;
  }
  return fmt_asn1tagint(dest,l)+1;
}

#ifdef UNITTEST
#include <assert.h>
#include <string.h>
#undef UNITTEST
#include "fmt_asn1tagint.c"

int main() {
  char buf[100];
  assert(fmt_asn1tag(buf, UNIVERSAL, PRIMITIVE, INTEGER)==1 && buf[0]==2);
  assert(fmt_asn1tag(buf, UNIVERSAL, CONSTRUCTED, SEQUENCE_OF)==1 && buf[0]==0x30);
  assert(fmt_asn1tag(buf, UNIVERSAL, CONSTRUCTED, 0x1f)==2 && !memcmp(buf,"\x3f\x1f",2));
  /* fmt_asn1tagint has its own unit tests */
}
#endif
