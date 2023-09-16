#include "ldap.h"

size_t scan_ldapbindrequest(const char* src,const char* max,
			    unsigned long* version,struct string* name,
			    unsigned long* method) {
  size_t res,tmp;
  if (!(res=scan_asn1INTEGER(src,max,(signed long*)version)))
    return 0;
  if (!(tmp=scan_ldapstring(src+res,max,name)))
    return 0;
  res+=tmp;
  {
    enum asn1_tagclass tc;
    enum asn1_tagtype tt;
    if (!(tmp=scan_asn1tag(src+res,max,&tc,&tt,method)))
      return 0;
    if (tc!=PRIVATE || tt!=PRIMITIVE)
      return 0;
    res+=tmp;
  }
  return res;
}

#ifdef UNITTEST
#undef UNITTEST
#include <assert.h>
#include "scan_asn1STRING.c"
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1string.c"
#include "scan_ldapstring.c"
#include "scan_asn1rawint.c"
#include "scan_asn1int.c"
#include "scan_asn1INTEGER.c"

int main() {
  static char buf[] = "\x02\x01\x03\x04\x00\x80";	// bind request without message header
  unsigned long version=0, method=0;
  struct string name = { 0 };
  assert(scan_ldapbindrequest(buf, buf+6, &version, &name, &method)==6 && version==3 && name.l==0 && method==0);
  assert(scan_ldapbindrequest(buf, buf+5, &version, &name, &method)==0); // too short
  buf[5]=0; assert(scan_ldapbindrequest(buf, buf+6, &version, &name, &method)==0); // tc!=PRIVATE
  buf[5]=0xa0; assert(scan_ldapbindrequest(buf, buf+6, &version, &name, &method)==0); // tt!=PRIMITIVE
  buf[5]=0x1f; assert(scan_ldapbindrequest(buf, buf+6, &version, &name, &method)==0); // fail scan_asn1tag
  buf[4]=5; assert(scan_ldapbindrequest(buf, buf+6, &version, &name, &method)==0); // fail scan_ldapstring
  buf[0]=0; assert(scan_ldapbindrequest(buf, buf+6, &version, &name, &method)==0); // fail scan_asn1INTEGER
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
