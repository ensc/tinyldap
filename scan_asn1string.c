#include "asn1.h"

int scan_asn1string(const char* src,const char* max,
		    enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag,
		    const char** s,unsigned long* l) {
  int len,tmp;
  if (!(len=scan_asn1tag(src,max,tc,tt,tag))) return 0;
  if (!(tmp=scan_asn1length(src+len,max,l))) return 0;
  len+=tmp;
  if (src+len+*l>max) return 0;
  *s=src+len;
  return len+*l;
}
