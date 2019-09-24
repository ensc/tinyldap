#include "asn1.h"

/* Common integer storing method, used in tags >= 0x1f and OIDs */
/* Store big endian, 7 bits at a time, set high bit in all but last byte */
/* Return number of bytes needed. Only write if dest!=NULL */
size_t fmt_asn1tagint(char* dest,unsigned long l) {
  size_t needed=((sizeof l)*8)/7+1,i;
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

#ifdef UNITTEST
#include <assert.h>
#include <string.h>

int main() {
  char buf[10];
  assert(fmt_asn1tagint(buf,1)==1 && !memcmp(buf,"\x01",1));
  assert(fmt_asn1tagint(buf,0x7f)==1 && !memcmp(buf,"\x7f",1));
  assert(fmt_asn1tagint(buf,0x80)==2 && !memcmp(buf,"\x81\x00",2));
  assert(fmt_asn1tagint(buf,0xffffffff)==5 && !memcmp(buf,"\x8f\xff\xff\xff\x7f",5));
}
#endif
