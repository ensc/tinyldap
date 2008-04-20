#include <stddef.h>
#include <ctype.h>

/* "ou=fnord; O=fefe; c=de" -> "ou=fnord,o=fefe,c=de" */
/* returns the length of the new string */
size_t normalize_dn(char* dest,const char* src,int len) {
  int makelower=1;
  char* orig=dest;
  while (len) {
    if (*src==';' || *src==',') {
      *dest=',';
      while (len>1 && src[1]==' ') { ++src; --len; }
      makelower=1;
    } else {
      if (makelower)
	*dest=tolower(*src);
      else
	*dest=*src;
      if (*dest=='=') makelower=0;
    }
    ++dest;
    ++src;
    --len;
  }
  return dest-orig;
}
