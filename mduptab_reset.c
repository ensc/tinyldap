#include "mstorage.h"
#include "mduptab.h"

void mduptab_reset(mduptab_t* t) {
  mstorage_unmap(&t->table);
  mstorage_unmap(&t->strings);
}
