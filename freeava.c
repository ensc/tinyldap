#include <stdlib.h>
#include "ldap.h"

void freeava(struct AttributeDescriptionList* a) {
  while (a) {
    struct AttributeDescriptionList* tmp=a->next;
    free(a);
    a=tmp;
  }
}
