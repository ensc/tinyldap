/* save memory for constant strings by keeping a list of the ones that
 * we already saw and not allocating memory for each new one.  The only
 * API is "add string and return pointer".  Will try to insert the
 * string in the table.  If the same string was already there, it will
 * return a pointer to that string, otherwise it will insert a copy of
 * the new string. */

struct stringduptable {
  size_t n,a;
  const char** s;
};

const char* strduptab_add(struct stringduptable* t,const char* s);
