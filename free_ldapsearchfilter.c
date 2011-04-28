#include <stdlib.h>
#include "ldap.h"

void free_ldapsearchfilter(struct Filter* f) {
  while (f) {
    struct Filter* tmp=f->next;
    switch (f->type) {
    case AND: case OR: case NOT:
      free_ldapsearchfilter(f->x);
      break;
    case SUBSTRING:
      while (f->substrings) {
	struct Substring* s=f->substrings->next;
	free(f->substrings);
	f->substrings=s;
      }
    default:
      break;
    }
    free(f); f=tmp;
  }
}
