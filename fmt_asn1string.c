#include "asn1.h"
#include <libowfat/byte.h>

size_t fmt_asn1string(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,const char* c,size_t l) {
  size_t len;
  if (l>(size_t)-100) return (size_t)-1;
  len=fmt_asn1transparent(dest,tc,tt,tag,l);
  if (dest) byte_copy(dest+len,l,c);
  return len+l;
}
