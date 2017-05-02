#include "asn1.h"

size_t fmt_asn1OID(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,const size_t* array,size_t len) {
  size_t i,l,l2;
  if (len<2) return 0;
  for (l=1,i=2; i<len; ++i) {
    l+=fmt_asn1tagint(dest,array[i]);
  }
  l2=fmt_asn1transparent(dest,tc,tt,tag,l);
  if (!dest) return l+l2;
  dest[l2]=array[0]*40+array[1];
  dest+=l2+1;
  for (i=2; i<len; ++i)
    dest+=fmt_asn1tagint(dest,array[i]);
  return l+l2;
}
