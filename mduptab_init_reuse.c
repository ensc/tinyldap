#include "mduptab.h"

void mduptab_init_reuse(mduptab_t* t,mstorage_t* s) {
  mstorage_init(&t->table);
  t->Strings=s;
}
