#include <asn1.h>

int fmt_asn1int(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,unsigned long l) {
  int len,tmp;
  /* first the tag */
  if (!dest) return 2+fmt_asn1intpayload(0,l);
  len=fmt_asn1tag(dest,tc,tt,tag);
  tmp=fmt_asn1intpayload(dest+len+1,l);
  if (fmt_asn1length(dest+len,tmp)!=1) return 0;
  return len+tmp+1;
}
