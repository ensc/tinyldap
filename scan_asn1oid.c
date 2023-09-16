#include "asn1.h"

/* This isn't actually used in LDAP.
 * This is here for X.509 certificate parsing code. */

size_t scan_asn1oid(const char* src,const char* max,size_t* array,size_t* arraylen) {
  size_t res,tlen;
  unsigned long tag,tmp;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if (!arraylen)
    return 0;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag)) ||
      (tc!=UNIVERSAL || tt!=PRIMITIVE || tag!=OBJECT_IDENTIFIER) ||
      !(tmp=scan_asn1length(src+res,max,&tlen)) || tlen<1) {
    *arraylen=0;
    return 0;
  }
  res+=tmp;
  if (max>src+res+tlen)
    max=src+res+tlen;	/* clamp max down */
  src+=res;

  tmp=scan_asn1rawoid(src,max,array,arraylen);
  return tmp ? tmp+res : 0;
}

#ifdef UNITTEST
#include <string.h>
#include <assert.h>

#undef UNITTEST
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1rawoid.c"

int main() {
  char buf[100];
  size_t retval[10];
  size_t retvals=10;
  strcpy(buf,"\x06\x03\x55\x04\x03");	// \x06 = UNIVERSAL PRIMITIVE OBJECT_IDENTIFIER, 0x03 = length, \x55\x04\x03 = 2.5.4.3 (commonName)
  assert(scan_asn1oid(buf,buf+5,retval,&retvals)==5 && retvals==4 && retval[0]==2 && retval[1]==5 && retval[2]==4 && retval[3]==3);
  assert(scan_asn1oid(buf,buf+5,retval,NULL)==0);	// trigger line 12
  assert(scan_asn1oid(buf,buf,retval,&retvals)==0);	// trigger line 13
  buf[0]=0x05;	// wrong tag (NULL instead of OBJECT_IDENTIFIER)
  assert(scan_asn1oid(buf,buf+5,retval,&retvals)==0);	// trigger line 14
  buf[0]=0x06;
  assert(scan_asn1oid(buf,buf+1,retval,&retvals)==0);	// trigger line 15
  buf[1]=0;	// send length 0 (OIDs must have at least 1)
  assert(scan_asn1oid(buf,buf+5,retval,&retvals)==0);	// trigger line 15
  buf[1]=3;
  assert(scan_asn1oid(buf,buf+6,retval,&retvals)==0);	// trigger line 21
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
