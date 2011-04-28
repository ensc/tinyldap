#include "asn1.h"

size_t scan_asn1oid(const char* src,const char* max,unsigned long* array,size_t* arraylen) {
  size_t res,tlen;
  unsigned long tag,tmp;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if (!arraylen) return 0;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag)) ||
      (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=OBJECT_IDENTIFIER) ||
      !(tmp=scan_asn1length(src+res,max,&tlen)) || tlen<1) {
    *arraylen=0;
    return 0;
  }
  res+=tmp;
  if (max>src+res+tlen) max=src+res+tlen;	/* clamp max down */
  src+=res;

  return scan_asn1rawoid(src,max,array,arraylen);
}

