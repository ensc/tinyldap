#include <string.h>
#include "str.h"
#include "uint32.h"
#include "bstr.h"

int bstr_diff2(const char* a,const char* b,unsigned int blen) {
  const char* A,* B;
  int j;
  /* like str_diff, just for bstrs */
  if (*a) A=a+str_len(a); else { A=a+5+uint32_read(a+1); a+=5; }
  B=b+blen;
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
