#include "asn1.h"

int scan_asn1oid(const char* src,const char* max) {
  int res,tmp;
  unsigned long tag,tlen;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  if (!(res=scan_asn1tag(src,max,&tc,&tt,&tag))) goto error;
  if (!(tmp=scan_asn1length(src+res,max,&tlen))) goto error;
  res+=tmp;
  {
    unsigned int i,x,y;
    tmp=0;
    for(i=0;src[res+i]&128;++i)
      tmp=(tmp<<7)+((unsigned char)src[res+i]&(~128));
    tmp=(tmp<<7)+(unsigned char)src[res+i]; ++i;
    x=tmp/40; y=tmp-x*40;
    /* AFAIK gilt fuer alle bisher zugewiesenen OIDs: x<=2 & y<40 */
#if 1
    /* Hier wird das Beispiel aus dem Standard korrekt geparst. */
    while (x>2) { --x; y+=40; }
#else
    /* Hier nicht. Dennoch arbeiten einige ASN.1 Parser ebenso. */
    while (y>40) { y-=40; ++x; }
#endif
#if 0
    buffer_putulong(buffer_2,x);
    buffer_puts(buffer_2,".");
    buffer_putulong(buffer_2,y);
#endif
    for(;i<tlen;++i) {
      tmp=0;
      for(;src[res+i]&128;++i)
        tmp=(tmp<<7)+((unsigned char)src[res+i]&(~128));
      tmp=(tmp<<7)+(unsigned char)src[res+i];
#if 0
      buffer_puts(buffer_2,".");
      buffer_putulong(buffer_2,tmp);
#endif
    }
#if 0
    buffer_putsflush(buffer_2,"\n");
#endif
  }
  return res+tlen;
error:
  return 0;
}

