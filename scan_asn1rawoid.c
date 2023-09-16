#include "asn1.h"

size_t scan_asn1rawoid(const char* src,const char* max,size_t* array,size_t* arraylen) {
  const char* orig=src;
  size_t cur=0,al;
  if (!arraylen)
    return 0;
  al=*arraylen; *arraylen=0;
  if (max-src<1)
    return 0;		/* there has to be at least one octet */

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
    if (array && cur+1<al) { array[cur]=a; array[cur+1]=b; }
    cur+=2;
  }

  for (++src; src<max; ) {
    size_t i;
    unsigned long tmp;
    if (!(i=scan_asn1tagint(src,max,&tmp)))
      return 0;
    src+=i;
    if (array && cur<al) array[cur]=tmp;
    ++cur;
  }

  /* if we got this far, then we have an OID, but it might not have fit */
  *arraylen=cur;
  if (cur>al)		/* did not fit */
    return 0;
  return src-orig;
}

#ifdef UNITTEST
#include <string.h>
#include <assert.h>

#undef UNITTEST
#include "scan_asn1tagint.c"

int main() {
  char buf[100];
  size_t retval[10];
  size_t retvals=10;
  strcpy(buf,"\x55\x04\x03");	// 2.5.4.3 (commonName)
  assert(scan_asn1rawoid(buf,buf+3,retval,&retvals)==3 && retvals==4 && retval[0]==2 && retval[1]==5 && retval[2]==4 && retval[3]==3);
  retvals=3;
  retval[3]=23;
  assert(scan_asn1rawoid(buf,buf+3,retval,&retvals)==0);	// oid too long for dest array, fail line 40
  assert(retval[3]==23);	// make sure we didn't clobber sentinel
  assert(retvals==4);		// make sure it told us how many elements are needed

  assert(scan_asn1rawoid(buf,buf+3,retval,0)==0);		// *retvals is NULL, fail line 7
  strcpy(buf,"\x55\x04\x03");	// 2.5.4.3 (commonName)
  retvals=10;
  assert(scan_asn1rawoid(buf,buf,retval,&retvals)==0);		// src=max, fail line 10
  strcpy(buf,"\x55\x04\xff");	// 2.5.4.[invalid]
  assert(scan_asn1rawoid(buf,buf+3,retval,&retvals)==0);	// scan_asn1tagint fails, fail line 31
  strcpy(buf,"\xb4\x04\x03");	// 2.100.4.3
  retvals=10;
  assert(scan_asn1rawoid(buf,buf+3,retval,&retvals)==3 && retvals==4 && retval[0]==2 && retval[1]==100 && retval[2]==4 && retval[3]==3);
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
