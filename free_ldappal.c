#include <stdlib.h>
#include "ldap.h"

void free_ldappal(struct PartialAttributeList* a) {
  while (a) {
    struct PartialAttributeList* tmp=a->next;
    free_ldapadl(a->values);
    free(a); a=tmp;
  }
}

