/* provide a string allocator.  It is add-only, you can't free a string
 * later.  On the plus side, the allocation overhead is close to zero.
 * Will a stored copy of the string. */

const char* strstorage_add(const char* s,int n);
