#include "mduptab.h"

void mduptab_init(mduptab_t* t) {
  mstorage_init(&t->table);
  mstorage_init(&t->strings);
  t->Strings=&t->strings;
}
