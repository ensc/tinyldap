#include "ldap.h"
#include <stdlib.h>

void freefilter(struct Filter* f) {
  if (f) {
    freeava(f->a);
    if (f->x) freefilter(f->x);
    if (f->next) freefilter(f->next);
    free(f);
  }
}
