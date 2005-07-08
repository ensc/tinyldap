#include "asn1.h"

unsigned int scan_asn1INTEGER(const char* src,const char* max,signed long* l) {
  unsigned int tmp;
  long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,l)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==INTEGER)
      return tmp;
  return 0;
}
