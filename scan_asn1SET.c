#include "asn1.h"

int scan_asn1SET(const char* src,const char* max,unsigned long* len) {
  int res,tmp;
  long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag))) return 0;
  if (!(tmp=scan_asn1length(src+res,max,len))) return 0;
  res+=tmp;
  if (tc==UNIVERSAL && tt==CONSTRUCTED && tag==SET_OF)
    return res;
  return 0;
}
