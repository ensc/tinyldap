#include "asn1.h"

unsigned int scan_asn1BOOLEAN(const char* src,const char* max,unsigned long* l) {
  unsigned int tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  long ltmp;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,&ltmp)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==BOOLEAN) {
      if (ltmp<0 || src+tmp+ltmp>max) return 0;
      *l=(unsigned long)ltmp;
      return tmp;
    }
  return 0;
}
