#include <stdlib.h>
#include "ldap.h"

void freepal(struct PartialAttributeList* l) {
  while (l) {
    struct PartialAttributeList* x=l->next;
    while (l->values) {
      struct AttributeDescriptionList* y=l->values->next;
      free(l->values);
      l->values=y;
    }
    free(l);
    l=x;
  }
}
