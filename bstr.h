
int bstr_diff(const char* a,const char* b);
#define bstr_equal(s,t) (!bstr_diff((s),(t)))

int bstr_diff2(const char* a,const char* b,unsigned int blen);
#define bstr_equal2(s,t,l) (!bstr_diff2((s),(t),(l)))

int bstrlen(const char* a);
int bstrstart(const char* a); /* offset of first byte of bstring */

const char* bstrfirst(const char* a); /* pointer to first byte of bstring */
