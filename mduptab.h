/* save memory for constant strings by keeping a list of the ones that
 * we already saw and not allocating memory for each new one.  The only
 * API is "add string and return offset".  The offset is relative to the
 * root of the pstorage_t.  Will try to insert the string in the table.
 * If the same string was already there, it will return offset of that
 * string, otherwise it will insert a copy of the new string. */

#include "mstorage.h"

typedef struct mduptable {
  mstorage_t table,strings;
} mduptab_t;

void mduptab_init(mduptab_t* t);
long mduptab_add(mduptab_t* t,const char* s,unsigned int len);
long mduptab_adds(mduptab_t* t,const char* s);
