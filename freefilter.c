#include "ldap.h"
#include <stdlib.h>

void freefilter(struct Filter* f) {
  if (f) {
    freeava(f->a);
    if (f->x) freefilter(f->x);
    if (f->next) freefilter(f->next);
    while (f->substrings) {
      struct Substring* s=f->substrings->next;
      free(f->substrings);
      f->substrings=s;
    }
    free(f);
  }
}
