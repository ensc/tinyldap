#include "asn1.h"

int scan_asn1INTEGER(const char* src,const char* max,unsigned long* l) {
  int tmp;
  long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,l)))
    if (tc==UNIVERSAL || tt==PRIMITIVE || tag==INTEGER)
      return tmp;
  return 0;
}
