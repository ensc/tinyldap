#include "asn1.h"
#include "byte.h"

int fmt_asn1string(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,const char* c,unsigned long l) {
  int len;
  len=fmt_asn1transparent(dest,tc,tt,tag,l);
  if (dest) byte_copy(dest+len,l,c);
  return len+l;
}
