#include <string.h>
#include <libowfat/str.h>
#include <libowfat/uint32.h>

int bstr_diff(const char* a,const char* b) {
  const char* A,* B;
  int j;
  /* like str_diff, just for bstrs */
  if (*a && *b)
    return str_diff(a,b);
  if (*a) A=a+str_len(a); else { A=a+5+uint32_read(a+1); a+=5; }
  if (*b) B=b+str_len(b); else { B=b+5+uint32_read(b+1); b+=5; }
  for (;;) {
    if (a==A) {
      if (b==B)
	return 0;
      else
	return -1;
    } else
      if (b==B)
	return 1;
    if ((j=(*a-*b))) break;
    ++a; ++b;
  }
  return j;
}
