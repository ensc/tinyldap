#include "asn1.h"

static long int handleint(const unsigned char* c,int len) {
  long l=0;
  while (len) {
    l=l*256+*c;
    --len; ++c;
  }
  return l;
}

int scan_asn1int(const char* src,const char* max,enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag,unsigned long* l) {
  int len,tmp;
  long tlen;
  if (!(len=scan_asn1tag(src,max,tc,tt,tag))) return 0;
  if (!(tmp=scan_asn1length(src+len,max,&tlen))) return 0;
  len+=tmp;
  *l=handleint(src+len,tlen);
  return len+tlen;
}
