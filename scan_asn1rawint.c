#include "asn1.h"

unsigned int scan_asn1rawint(const char* src,const char* max,unsigned int len,long* l) {
  unsigned int i,j;
  long m;
  if (*src<0) m=-1; else m=0;
  for (i=j=0; i<len; ++i,++j) {
    if ((m==0 && *src==0) || (m==-1 && *src==-1)) --j;
    m=(m<<8)|(unsigned char)*src;
    ++src;
    if (src>max) return 0;
  }
  if (j>sizeof(long)) return 0;
  *l=m;
  return len;
}
