#include "ldap.h"

void free_ldapsearchresultentry(struct SearchResultEntry* e) {
  freepal(e->attributes);
}
