#include "asn1.h"
#include <libowfat/byte.h>

size_t fmt_asn1transparent(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,size_t l) {
  size_t len,tmp;
  /* first the tag */
  len=fmt_asn1tag(dest,tc,tt,tag);
  tmp=fmt_asn1length(dest?dest+len:dest,l);
  return tmp+len;
}
