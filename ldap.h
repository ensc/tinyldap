#ifndef _LDAP_H
#define _LDAP_H

#include <stddef.h>
#include <inttypes.h>
#include "asn1.h"

/* return zero if same, otherwise nonzero */
int matchstring(struct string* s,const char* c);
int matchcasestring(struct string* s,const char* c);
int matchprefix(struct string* s,const char* c);
int matchcaseprefix(struct string* s,const char* c);

/* "ou=fnord; O=fefe; c=de" -> "ou=fnord,o=fefe,c=de" */
/* returns the length of the new string */
size_t normalize_dn(char* dest,const char* src,int len);

struct AttributeValueAssertion {
  struct string desc, value;
};

struct AttributeDescriptionList {
  struct string a;
  uint32_t attrofs;
  struct AttributeDescriptionList *next;
};

struct PartialAttributeList {
  struct string type;
  struct AttributeDescriptionList* values;
  struct PartialAttributeList* next;
};

struct Substring {
  enum { prefix=0, any=1, suffix=2 } substrtype;
  struct string s;
  struct Substring* next;
};

enum FilterType {
  AND=0, OR=1, NOT=2, EQUAL=3, SUBSTRING=4, GREATEQUAL=5, LESSEQUAL=6, PRESENT=7, APPROX=8, EXTENSIBLE=9
};

struct Filter {
  enum FilterType type;
  struct AttributeValueAssertion ava;
  uint32_t attrofs; /* offset of attribute name in index */
  uint32_t attrflag; /* "case sensitivity" flag from index */
  struct Substring* substrings;
  struct AttributeDescriptionList *a;
  struct Filter* x,*next;
    /* x is the subject of this filter (AND, OR and NOT) */
    /* next is used to form a linked list of subjects */
};

struct SearchRequest {
  struct string baseObject;
  enum { baseObject=0, singleLevel=1, wholeSubtree=2 } scope;
  enum {
    neverDerefAliases=0,
    derefInSearching=1,
    derefFindingBaseObj=2,
    derefAlways=3
  } derefAliases;
  unsigned long sizeLimit, timeLimit;
  int typesOnly;
  struct Filter* filter;
  struct AttributeDescriptionList* attributes;
};

struct SearchResultEntry {
  struct string objectName;
  struct PartialAttributeList* attributes;
};

struct Modification {
  enum { Add=0, Delete=1, Replace=2 } operation;
  struct string AttributeDescription; /* ? */
  struct AttributeDescriptionList* vals;
  struct Modification* next;
};

struct Addition {
  struct string AttributeDescription;
  struct AttributeDescriptionList vals;
  struct Addition* next;
};

struct ModifyRequest {
  struct string object;
  struct Modification m;
};

struct AddRequest {
  struct string entry;
  struct Addition a;
};

struct ModifyDNRequest {
  struct string entry, newrdn;
  int deleteoldrdn;
  struct string newsuperior;
};

enum ldapops {
  BindRequest=0, BindResponse=1,
  UnbindRequest=2,
  SearchRequest=3, SearchResultEntry=4, SearchResultDone=5,
  ModifyRequest=6, ModifyResponse=7,
  AddRequest=8, AddResponse=9,
  DelRequest=10, DelResponse=11,
  ModifyDNRequest=12, ModifyDNResponse=13,
  CompareRequest=14, CompareResponse=15,
  AbandonRequest=16,
  ExtendedRequest=23 /* coincidence?  I think not. */,
  ExtendedResponse=24
};

enum ldaperrors {
  success=0,
  operationsError=1,
  protocolError=2,
  timeLimitExceeded=3,
  sizeLimitExceeded=4,
  compareFalse=5,
  compareTrue=6,
  authMethodNotSupported=7,
  strongAuthRequired=8,
  referral=10,
  adminLimitExceeded=11,
  unavailableCriticalExtension=12,
  confidentialityRequired=13,
  saslBindInProgress=14,
  noSuchAttribute=16,
  undefinedAttributeType=17,
  inappropriateMatching=18,
  constraintViolation=19,
  attributeOrValueExists=20,
  invalidAttributeSyntax=21,
  noSuchObject=32,
  aliasProblem=33,
  invalidDNSyntax=34,
  aliasDereferencingProblem=36,
  inappropriateAuthentication=48,
  invalidCredentials=49,
  insufficientAccessRights=50,
  busy=51,
  unavailable=52,
  unwillingToPerform=53,
  loopDetect=54,
  namingViolation=64,
  objectClassViolation=65,
  notAllowedOnNonLeaf=66,
  notAllowedOnRDN=67,
  entryAlreadyExists=68,
  objectClassModsProhibited=69,
  affectsMultipleDSAs=71,
};

void freefilter(struct Filter* f);
void freeava(struct AttributeDescriptionList* a);
void freepal(struct PartialAttributeList* a);

size_t scan_ldapstring(const char* src,const char* max,struct string* s);
size_t scan_ldapmessage(const char* src,const char* max,
			unsigned long* messageid,unsigned long* op,
			size_t* len);

size_t scan_ldapmessage_nolengthcheck(const char* src,const char* max,size_t* len);

size_t scan_ldapbindrequest(const char* src,const char* max,
			    unsigned long* version,struct string* name,
			    unsigned long* method);
size_t scan_ldapbindresponse(const char* src,const char* max,
			     unsigned long* result,struct string* matcheddn,
			     struct string* errormessage,struct string* referral);
size_t scan_ldapava(const char* src,const char* max,struct AttributeValueAssertion* a);
size_t scan_ldapsearchfilter(const char* src,const char* max,struct Filter** f);
size_t scan_ldapsearchrequest(const char* src,const char* max,struct SearchRequest* s);
size_t scan_ldapsearchresultentry(const char* src,const char* max,struct SearchResultEntry* sre);
size_t scan_ldapresult(const char* src,const char* max,unsigned long* result,
		       struct string* matcheddn,struct string* errormessage,
		       struct string* referral);
size_t scan_ldapmodifyrequest(const char* src,const char* max,struct ModifyRequest* m);
size_t scan_ldapaddrequest(const char* src, const char * max, struct AddRequest * a);
size_t scan_ldapsearchfilterstring(const char* src,struct Filter** f);
size_t scan_ldapdeleterequest(const char* src,const char* max,struct string* s);
size_t scan_ldapmodifydnrequest(const char* src,const char* max,struct ModifyDNRequest* mdr);

size_t fmt_ldapstring(char* dest,const struct string* s);
size_t fmt_ldapmessage(char* dest,long messageid,long op,size_t len);
size_t fmt_ldapbindrequest(char* dest,long version,const char* name,const char* simple);
size_t fmt_ldapsearchfilter(char* dest,const struct Filter* f);
size_t fmt_ldapsearchrequest(char* dest,const struct SearchRequest* s);
size_t fmt_ldapsearchresultentry(char* dest,const struct SearchResultEntry* sre);
size_t fmt_ldapresult(char* dest,long result,const char* matcheddn,const char* errormessage,const char* referral);
size_t fmt_ldappal(char* dest,const struct PartialAttributeList* pal);
size_t fmt_ldapava(char* dest,const struct AttributeValueAssertion* a);
size_t fmt_ldapadl(char* dest,const struct AttributeDescriptionList* adl);
size_t fmt_ldapavl(char* dest,const struct AttributeDescriptionList* adl);
size_t fmt_ldapmodifyrequest(char* dest,const struct ModifyRequest* m);
size_t fmt_ldapaddrequest(char* dest,const struct AddRequest* m);
size_t fmt_ldapsearchfilterstring(char* dest,const struct Filter* f);
size_t fmt_ldapdeleterequest(char* dest,const struct string* s);
size_t fmt_ldapmodifydnrequest(char* dest,const struct ModifyDNRequest* mdr);

#define fmt_ldapbindresponse(a,b,c,d,e) fmt_ldapresult(a,b,c,d,e)
#define fmt_ldapsearchresultdone(a,b,c,d,e) fmt_ldapresult(a,b,c,d,e)

void free_ldapadl(struct AttributeDescriptionList* a);
void free_ldappal(struct PartialAttributeList* a);
void free_ldapsearchfilter(struct Filter* f);
/* does not free s itself */
void free_ldapsearchrequest(struct SearchRequest* s);
/* does not free m itself */
void free_ldapmodifyrequest(struct ModifyRequest* m);
/* does not free a itself */
void free_ldapaddrequest(struct AddRequest * a);
/* does not free e itself */
void free_ldapsearchresultentry(struct SearchResultEntry* e);

int ldap_matchfilter_sre(struct SearchResultEntry* sre,struct Filter* f);

int matchint(struct Filter* f,const char* t);
int substringmatch(struct Substring* x,const char* attr,int ignorecase);

#endif
