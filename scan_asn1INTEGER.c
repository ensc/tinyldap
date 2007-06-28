#include "asn1.h"

size_t scan_asn1INTEGER(const char* src,const char* max,signed long* val) {
  size_t tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,val)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==INTEGER)
      return tmp;
  return 0;
}
