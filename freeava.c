#include <stdlib.h>
#include "ldap.h"

void freeava(struct AttributeList* a) {
  while (a) {
    struct AttributeList* tmp=a->next;
    free(a);
    a=tmp;
  }
}
