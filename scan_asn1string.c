#include "asn1.h"

size_t scan_asn1string(const char* src,const char* max,
		       enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag,
		       const char** s,size_t* l) {
  size_t len,tmp;
  if (!(len=scan_asn1tag(src,max,tc,tt,tag)))
    return 0;
  if (!(tmp=scan_asn1length(src+len,max,l)))
    return 0;
  len+=tmp;
  *s=src+len;
  return len+*l;
}

#ifdef UNITTEST
#include <string.h>
#include <assert.h>

#undef UNITTEST
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"

int main() {
  char buf[100];
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  unsigned long tag;
  const char* s;
  size_t l;
  strcpy(buf,"\x16\x05""fnord");
  assert(scan_asn1string(buf,buf+7,&tc,&tt,&tag,&s,&l)==7 && tc==UNIVERSAL && tt==PRIMITIVE && tag==IA5String && s==buf+2 && l==5);
  assert(scan_asn1string(buf,buf,&tc,&tt,&tag,&s,&l)==0);	// not enough input, first return 0
  assert(scan_asn1string(buf,buf+6,&tc,&tt,&tag,&s,&l)==0);	// not enough input, second return 0
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
