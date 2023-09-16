#include "asn1.h"

size_t scan_asn1STRING(const char* src,const char* max,const char** s,size_t* l) {
  size_t tmp;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if ((tmp=scan_asn1string(src,max,&tc,&tt,&tag,s,l)))
    if (tc==UNIVERSAL && tt==PRIMITIVE && tag==OCTET_STRING)
      return tmp;
  return 0;
}

#ifdef UNITTEST
#include <string.h>
#include <assert.h>

#undef UNITTEST
#include "scan_asn1tag.c"
#include "scan_asn1tagint.c"
#include "scan_asn1length.c"
#include "scan_asn1string.c"

int main() {
  char buf[100];
  const char* s;
  size_t l;
  strcpy(buf,"\x04\x05""fnord");	// 0x04 = UNIVERSAL PRIMITIVE OCTET_STRING, 0x05 = length 5, "fnord" = the string
  assert(scan_asn1STRING(buf,buf+7,&s,&l)==7 && s==buf+2 && l==5);
  assert(scan_asn1STRING(buf,buf+6,&s,&l)==0);	// short input, make scan_asn1string fail
  buf[0]=0x13;	// 0x13 = UNIVERSAL PRIMITIVE PrintableString
  assert(scan_asn1STRING(buf,buf+7,&s,&l)==0);	// scan_asn1string succeeds but line 9 fails
  // we only care for 100% coverage of this file, the others have their own unit tests */
  return 0;
}
#endif
