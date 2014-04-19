#include "asn1.h"

size_t scan_asn1rawint(const char* src,const char* max,size_t len,long* l) {
  size_t i;
  long m;
  if (src>=max) return 0;		// 0 bytes input buffer
  if (*src<0) m=-1; else m=0;		// negative number?
  if (len>1 && *src==m) {
    // we want to catch things like 00 01
    // but a leading 0 byte is needed for 00 a0 because otherwise it would be -96
    if ((src[1]>>7)==m) return 0;	// non-minimal encoding
    if (len>sizeof(m)+1) return 0;	// value too large, does not fit
  } else
    if (len>sizeof(m)) return 0;	// value too large, does not fit
  if (src+i>=max) return 0;		// input buffer not sufficient
  for (i=0; i<len; ++i) {
    m=(m<<8)|(unsigned char)src[i];
  }
  *l=m;
  return len;
}
