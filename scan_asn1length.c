#include <inttypes.h>
#include "asn1.h"

size_t scan_asn1length(const char* src,const char* max,size_t* value) {
  size_t len=max-src;
  if (len==0 || len>=-(uintptr_t)src) return 0;
  unsigned int i,c=*src;
  size_t l;
  if ((c&0x80)==0) {
    l=c&0x7f;
    i=1;
  } else {
    /* Highest bit set: lower 7 bits is the length of the length value in bytes. */
    c&=0x7f;
    if (!c) return 0;		/* length 0x80 means indefinite length encoding, not supported here */
    l=(unsigned char)src[1];
    if (l==0) return 0;		/* not minimally encoded: 0x81 0x00 instead of 0x00 */
    if (c>sizeof(l)) return 0;	/* too many bytes, does not fit into target integer type */
    for (i=2; i<=c; ++i)
      l=l*256+(unsigned char)src[i];
    if (l<0x7f) return 0;	/* not minimally encoded: 0x81 0x70 instead of 0x70 */
  }
  if (l>len-i) return 0;	/* if the length would not fit into the buffer, return 0 */
  *value=l;
  return i;
}

