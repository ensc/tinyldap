#include <asn1.h>

size_t fmt_asn1sintpayload(char* dest,signed long l) {
  size_t needed=sizeof l,i;
  signed long tmp=0x7f;
  if (l>=0) return fmt_asn1intpayload(dest,l);
  for (i=1; i<needed; ++i) {
    /* assumes two's complement */
    if ((l|tmp) == -1)
      break;
    tmp=(tmp<<8)|0xff;
  }
  if (dest) {
    size_t j=i;
    while (j) {
      --j;
      *dest=(l>>(j*8))&0xff;
      ++dest;
    }
  }
  return i;
}
