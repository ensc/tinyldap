#include "asn1.h"

size_t scan_asn1BOOLEAN(const char* src,const char* max,unsigned long* val) {
  size_t tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  long ltmp;
  if ((tmp=scan_asn1int(src,max,&tc,&tt,&tag,&ltmp)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==BOOLEAN) {
      if (ltmp!=0 && ltmp!=1) return 0;
      *val=(unsigned long)ltmp;
      return tmp;
    }
  return 0;
}
