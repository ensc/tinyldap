#include "asn1.h"

unsigned int scan_asn1STRING(const char* src,const char* max,const char** s,unsigned long* l) {
  unsigned int tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if ((tmp=scan_asn1string(src,max,&tc,&tt,&tag,s,l)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==OCTET_STRING)
      return tmp;
  return 0;
}
