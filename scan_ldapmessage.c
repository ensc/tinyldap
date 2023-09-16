#include "ldap.h"

size_t scan_ldapmessage(const char* src,const char* max,
			unsigned long* messageid,unsigned long* op,size_t* len) {
  size_t res,tmp;
  if (!(res=scan_asn1SEQUENCE(src,max,len)))
    goto error;
  if (!(tmp=scan_asn1INTEGER(src+res,max,(long*)messageid)))
    goto error;
  res+=tmp;
  {
    enum asn1_tagclass tc;
    enum asn1_tagtype tt;
    if (!(tmp=scan_asn1tag(src+res,max,&tc,&tt,op)))
      goto error;
    if (tc!=APPLICATION)
      goto error;
    res+=tmp;
    if (!(tmp=scan_asn1length(src+res,max,len)))
      goto error;
    res+=tmp;
  }
  return res;
error:
  return 0;
}

#ifdef UNITTEST
#undef UNITTEST
#include <assert.h>
#include <string.h>
#include "scan_asn1SEQUENCE.c"
#include "scan_asn1INTEGER.c"
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1int.c"
#include "scan_asn1rawint.c"

int main() {
  static char buf[] = "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00";	// an LDAP bind request

  unsigned long msgid=0, op=0;
  size_t len=0;
  assert(scan_ldapmessage(buf,buf+14,&msgid,&op,&len)==7 && msgid==1 && op==BindRequest && len == 7);
  // trigger scan_asn1SEQUENCE error (too short)
  assert(scan_ldapmessage(buf,buf+13,&msgid,&op,&len)==0);
  buf[6]=8; assert(scan_ldapmessage(buf,buf+14,&msgid,&op,&len)==0); // fail scan_asn1length
  buf[5]=0; assert(scan_ldapmessage(buf,buf+14,&msgid,&op,&len)==0); // fail tc==APPLICATION
  buf[5]=0x80; assert(scan_ldapmessage(buf,buf+14,&msgid,&op,&len)==0); // fail scan_asn1tag
  buf[2]=0; assert(scan_ldapmessage(buf,buf+14,&msgid,&op,&len)==0); // fail scan_asn1INTEGER
  buf[0]=0; assert(scan_ldapmessage(buf,buf+14,&msgid,&op,&len)==0); // fail scan_asn1SEQUENCE
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}

#endif
