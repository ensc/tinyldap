#include "asn1.h"

unsigned int scan_asn1BOOLEAN(const char* src,const char* max,unsigned long* l) {
  unsigned int tmp;
  long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,l)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==BOOLEAN)
      return tmp;
  return 0;
}
