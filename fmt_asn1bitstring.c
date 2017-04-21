#include "asn1.h"
#include <libowfat/byte.h>

/* like fmt_asn1string, but l is in BITS, not BYTES */
size_t fmt_asn1bitstring(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,const char* c,size_t l) {
  size_t len;
  size_t actuallen;
  if (l>(size_t)-100) return (size_t)-1;
  actuallen=1+(l+7)/8;	/* add one octet to specify the unused bits in the last octet, and calculate octets needed */
  len=fmt_asn1transparent(dest,tc,tt,tag,actuallen);
  if (dest) {
    if (l)
      dest[len]=7-((l-1)%8);
    else
      dest[len]=0;
    byte_copy(dest+len+1,actuallen-1,c);
  }
  return len+actuallen;
}
