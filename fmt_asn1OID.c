#include "asn1.h"

size_t fmt_asn1OID(char* dest,const unsigned long* array,unsigned long len) {
  size_t i,l,l2;
  if (len<2) return 0;
  for (l=1,i=2; i<len; ++i) {
    l+=fmt_asn1tagint(dest,array[i]);
  }
  l2=fmt_asn1transparent(dest,UNIVERSAL,PRIMITIVE,OBJECT_IDENTIFIER,l);
  if (!dest) return l+l2;
  dest[l2]=array[0]*40+array[1];
  dest+=l2+1;
  for (i=2; i<len; ++i)
    dest+=fmt_asn1tagint(dest,array[i]);
  return l+l2;
}
