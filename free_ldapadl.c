#include <stdlib.h>
#include "ldap.h"

void free_ldapadl(struct AttributeDescriptionList* a) {
  while (a) {
    struct AttributeDescriptionList* tmp=a->next;
    free(a); a=tmp;
  }
}

