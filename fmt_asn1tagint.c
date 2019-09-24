#include "asn1.h"

static size_t tagintlen(unsigned long l) {
  size_t i;
  for (i=1; l>0x7f; ++i)
    l >>= 7;
  return i;
}

/* Common integer storing method, used in tags >= 0x1f and OIDs */
/* Store big endian, 7 bits at a time, set high bit in all but last byte */
/* Return number of bytes needed. Only write if dest!=NULL */
size_t fmt_asn1tagint(char* dest,unsigned long l) {
  size_t bytes = tagintlen(l);
  if (dest) {
    size_t i, j=bytes, k=bytes;
    for (i=0; i<k; ++i) {
      --j;
      dest[i]=((l>>(j*7))&0x7f) + (j?0x80:0);
    }
  }
  return bytes;
}

#ifdef UNITTEST
#include <assert.h>
#include <string.h>

int main() {
  char buf[10];
  assert(tagintlen(0)==1);
  assert(tagintlen(127)==1);
  assert(tagintlen(128)==2);
  assert(tagintlen(0xfffffffful)==5);
  assert(fmt_asn1tagint(buf,0xfffffffful)==5 && !memcmp(buf,"\x8f\xff\xff\xff\x7f",5));
  if (sizeof(long)==8) assert(fmt_asn1tagint(buf,0xfffffffffffffffful)==10 && !memcmp(buf,"\x81\xff\xff\xff\xff\xff\xff\xff\xff\x7f",10));
  assert(fmt_asn1tagint(buf,1)==1 && !memcmp(buf,"\x01",1));
  assert(fmt_asn1tagint(buf,0x7f)==1 && !memcmp(buf,"\x7f",1));
  assert(fmt_asn1tagint(buf,0x80)==2 && !memcmp(buf,"\x81\x00",2));
  assert(fmt_asn1tagint(buf,0xffffffff)==5 && !memcmp(buf,"\x8f\xff\xff\xff\x7f",5));
}
#endif
