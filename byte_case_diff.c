#include <ctype.h>

int byte_case_diff(const void* a, unsigned int len, const void* b) {
  register const char* s=a;
  register const char* t=b;
  register const char* u=t+len;
  register int j;
  j=0;
  for (;;) {
    if (t==u) break; if ((j=(tolower(*s)-tolower(*t)))) break; ++s; ++t;
  }
  return j;
}

