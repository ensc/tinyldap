#ifndef _LDAP_H
#define _LDAP_H

#include "uint32.h"

struct string {
  unsigned long l;
  const char* s;
};

int matchstring(struct string* s,const char* c);
int matchcasestring(struct string* s,const char* c);
int matchprefix(struct string* s,const char* c);
int matchcaseprefix(struct string* s,const char* c);

struct AttributeValueAssertion {
  struct string desc, value;
};

struct AttributeDescriptionList {
  struct string a;
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

struct Filter {
  enum {
    AND=0, OR=1, NOT=2, EQUAL=3, SUBSTRING=4, GREATEQUAL=5, LESSEQUAL=6, PRESENT=7, APPROX=8, EXTENSIBLE=9
  } type;
  struct AttributeValueAssertion ava;
  uint32 attrofs; /* offset of attribute name in index */
  uint32 attrflag; /* "case sensitivity" flag from index */
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
  unsigned long sizeLimit, timeLimit, typesOnly;
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
  struct AttributeDescriptionList vals;
  struct Modification* next;
};

struct ModifyRequest {
  struct string object;
  struct Modification m;
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

void freefilter(struct Filter* f);
void freeava(struct AttributeDescriptionList* a);
void freepal(struct PartialAttributeList* a);

int scan_ldapstring(const char* src,const char* max,struct string* s);
int scan_ldapmessage(const char* src,const char* max,
		     long* messageid,long* op,long* len);
int scan_ldapbindrequest(const char* src,const char* max,
			 long* version,struct string* name,long* method);
int scan_ldapbindresponse(const char* src,const char* max,
			  long* result,struct string* matcheddn,
			  struct string* errormessage,struct string* referral);
int scan_ldapava(const char* src,const char* max,struct AttributeValueAssertion* a);
int scan_ldapsearchfilter(const char* src,const char* max,struct Filter** f);
int scan_ldapsearchrequest(const char* src,const char* max,struct SearchRequest* s);
int scan_ldapsearchresultentry(const char* src,const char* max,struct SearchResultEntry* sre);
int scan_ldapresult(const char* src,const char* max,long* result,
		    struct string* matcheddn,struct string* errormessage,
		    struct string* referral);
int scan_ldapmodifyrequest(const char* src,const char* max,struct ModifyRequest* m);

int fmt_ldapstring(char* dest,struct string* s);
int fmt_ldapmessage(char* dest,long messageid,long op,long len);
int fmt_ldapbindrequest(char* dest,long version,char* name,char* simple);
int fmt_ldapsearchfilter(char* dest,struct Filter* f);
int fmt_ldapsearchrequest(char* dest,struct SearchRequest* s);
int fmt_ldapsearchresultentry(char* dest,struct SearchResultEntry* sre);
int fmt_ldapresult(char* dest,long result,char* matcheddn,char* errormessage,char* referral);
int fmt_ldappal(char* dest,struct PartialAttributeList* pal);
int fmt_ldapava(char* dest,struct AttributeValueAssertion* a);
int fmt_ldapadl(char* dest,struct AttributeDescriptionList* adl);
int fmt_ldapavl(char* dest,struct AttributeDescriptionList* adl);
int fmt_ldapmodifyrequest(char* dest,struct ModifyRequest* m);

#define fmt_ldapbindresponse(a,b,c,d,e) fmt_ldapresult(a,b,c,d,e)
#define fmt_ldapsearchresultdone(a,b,c,d,e) fmt_ldapresult(a,b,c,d,e)

void free_ldapadl(struct AttributeDescriptionList* a);
void free_ldappal(struct PartialAttributeList* a);
void free_ldapsearchfilter(struct Filter* f);
/* does not free s itself */
void free_ldapsearchrequest(struct SearchRequest* s);
/* does not free m itself */
void free_ldapmodifyrequest(struct ModifyRequest* m);


#endif
