#include "asn1.h"

size_t scan_asn1SEQUENCE_nolengthcheck(const char* src,const char* max,size_t* len) {
  size_t res,tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag))) return 0;
  if (!(tmp=scan_asn1length_nolengthcheck(src+res,max,len))) return 0;
  res+=tmp;
  if (tc==UNIVERSAL && tt==CONSTRUCTED && tag==SEQUENCE_OF)
    return res;
  return 0;
}


