#include <asn1.h>

size_t fmt_asn1sint(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,signed long l) {
  size_t len,tmp;
  /* first the tag */
  if (!dest) return fmt_asn1tag(0,tc,tt,tag)+1+fmt_asn1sintpayload(0,l);
  len=fmt_asn1tag(dest,tc,tt,tag);
  tmp=fmt_asn1sintpayload(dest+len+1,l);
  if (fmt_asn1length(dest+len,tmp)!=1) return 0;
  return len+tmp+1;
}

#ifdef UNITTEST
#include <assert.h>
#include <string.h>
#undef UNITTEST
#include <fmt_asn1tag.c>
#include <fmt_asn1intpayload.c>
#include <fmt_asn1sintpayload.c>
#include <fmt_asn1length.c>
#include <fmt_asn1tagint.c>

int main() {
  char buf[100];
  buf[3]='!';
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, 0)==3 && !memcmp(buf,"\x02\x01\x00!",4));
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, -1)==3 && !memcmp(buf,"\x02\x01\xff!",4));
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, 0x23)==3 && !memcmp(buf,"\x02\x01\x23!",4));
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, 127)==3 && !memcmp(buf,"\x02\x01\x7f!",4));
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, 128)==4 && !memcmp(buf,"\x02\x02\x00\x80",4));
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, 256)==4 && !memcmp(buf,"\x02\x02\x01\x00",4));
  buf[3]='!';
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, -128)==3 && !memcmp(buf,"\x02\x01\x80!",4));
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, -129)==4 && !memcmp(buf,"\x02\x02\xff\x7f",4));
  assert(fmt_asn1sint(buf, UNIVERSAL, PRIMITIVE, INTEGER, -2147483648)==6 && !memcmp(buf,"\x02\x04\x80\x00\x00\x00",6));
}
#endif
