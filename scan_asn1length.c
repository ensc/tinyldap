#include "asn1.h"

unsigned int scan_asn1length(const char* src,const char* max,unsigned long* length) {
  const char* orig=src;
  if (src>max) return 0;
/* If the highest bit of the first byte is clear, the byte is the length.
 * Otherwise the next n bytes are the length (n being the lower 7 bits) */
  if (*src&0x80) {
    int chars=*src&0x7f;
    unsigned long l=0;
    while (chars>0) {
      if (++src>=max) return 0;
      if (l>(((unsigned long)-1)>>8)) return 0;	/* catch integer overflow */
      l=l*256+(unsigned char)*src;
      --chars;
    }
    *length=l;
  } else
    *length=*src&0x7f;
  src++;
  if (src+*length>max) return 0;	/* catch integer overflow */
  if (src+*length<src) return 0;
  return src-orig;
}
