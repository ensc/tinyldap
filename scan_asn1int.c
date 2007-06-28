#include "asn1.h"

size_t scan_asn1int(const char* src,const char* max,enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag,signed long* l) {
  size_t len,tmp,tlen;
  if (!(len=scan_asn1tag(src,max,tc,tt,tag))) return 0;
  if (!(tmp=scan_asn1length(src+len,max,&tlen))) return 0;
  len+=tmp;
  if (!(scan_asn1rawint(src+len,max,tlen,l))) return 0;
  return len+tlen;
}
