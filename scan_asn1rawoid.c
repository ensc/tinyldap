#include "asn1.h"

size_t scan_asn1rawoid(const char* src,const char* max,size_t* array,size_t* arraylen) {
  const char* orig=src;
  size_t cur=0,al;
  if (!arraylen) return 0;
  al=*arraylen; *arraylen=0;
  if (max-src<1) return 0;	/* there has to be at least one octet */

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

