#include "asn1.h"

size_t scan_asn1oid(const char* src,const char* max,unsigned long* array,unsigned long* arraylen) {
  const char* orig=src;
  size_t res,tlen,cur=0,al;
  unsigned long tag,tmp;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if (!arraylen) return 0;
  al=*arraylen; *arraylen=0;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag))) return 0;
  if (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=OBJECT_IDENTIFIER) return 0;
  if (!(tmp=scan_asn1length(src+res,max,&tlen))) return 0;
  if (tlen<1) return 0;		/* there has to be at least one octet */
  res+=tmp;
  if (max>src+res+tlen) max=src+res+tlen;	/* clamp max down */
  src+=res;

  {
    int a,b;
    a=(unsigned char)*src;
    b=a%40;
    a/=40;
    /* a can be 0, 1 or 2.  And b is <=39 if a is 0 or 1.
     * So, if a is bigger than 2, it is really 2 */
    if (a>2) {
      b+=(a-2)*40;
      a=2;
    }
    if (array && cur<al) array[cur]=a; ++cur;
    if (array && cur<al) array[cur]=b; ++cur;
  }

  for (++src; src<max; ) {
    size_t i;
    unsigned long tmp;
    if (!(i=scan_asn1tagint(src,max,&tmp)))
      return 0;
    src+=i;
    if (array && cur<al) array[cur]=tmp; ++cur;
  }

  /* if we got this far, then we have an OID, but it might not have fit */
  *arraylen=cur;
  if (cur>al)		/* did not fit */
    return 0;
  return src-orig;
}

