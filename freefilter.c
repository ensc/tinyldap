#include "ldap.h"
#include <stdlib.h>

void freefilter(struct Filter* f) {
  if (f) {
    while (f->a) {
      struct AttributeList* a=f->a->next;
      free(f->a);
      f->a=a;
    }
    if (f->x) freefilter(f->x);
    if (f->next) freefilter(f->next);
    free(f);
  }
}
