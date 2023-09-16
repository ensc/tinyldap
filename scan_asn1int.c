#include "asn1.h"

size_t scan_asn1int(const char* src,const char* max,enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag,signed long* l) {
  size_t len,tmp,tlen;
  if (!(len=scan_asn1tag(src,max,tc,tt,tag)))
    return 0;
  if (!(tmp=scan_asn1length(src+len,max,&tlen)))
    return 0;
  len+=tmp;
  if (!(scan_asn1rawint(src+len,max,tlen,l)))
    return 0;
  return len+tlen;
}

#ifdef UNITTEST
#include <string.h>
#include <assert.h>

#undef UNITTEST
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1rawint.c"

int main() {
  char buf[100];
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  unsigned long tag;
  signed long l;
  strcpy(buf,"\x02\x01\x01");
  assert(scan_asn1int(buf,buf+3,&tc,&tt,&tag,&l)==3 && tc==UNIVERSAL && tt==PRIMITIVE && tag==INTEGER && l==1);
  assert(scan_asn1int(buf,buf,&tc,&tt,&tag,&l)==0);	// not enough input, first return 0
  assert(scan_asn1int(buf,buf+2,&tc,&tt,&tag,&l)==0);	// not enough input, second return 0
  strcpy(buf,"\x02\x02\x00\x01");
  assert(scan_asn1int(buf,buf+3,&tc,&tt,&tag,&l)==0);	// not enough input, second return 0
  assert(scan_asn1int(buf,buf+4,&tc,&tt,&tag,&l)==0);	// non-minimally encoded raw int, third return
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
