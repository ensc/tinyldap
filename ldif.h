#include <ldap.h>

/* how many attributes do we allow per record? */
#define ATTRIBS 8

struct attribute {
  const char* name,* value;
};

struct ldaprec {
  const char* dn,* mail,* sn,* cn;	/* most often encountered records */
  int n;	/* number of attributes */
  struct attribute a[ATTRIBS];
  struct ldaprec* next;
};

extern const char* dn,* mail,* sn,* cn,* objectClass;
extern struct ldaprec *first;

int ldif_parse(const char* filename);

/* return non-zero if the record matches the search request */
int ldap_match(struct ldaprec* r,struct SearchRequest* sr);
