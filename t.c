#include "open.h"
#include "buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stralloc.h>

#if 0
        LDAPMessage ::= SEQUENCE {
                messageID       MessageID,
                protocolOp      CHOICE {
                        bindRequest     BindRequest,
                        bindResponse    BindResponse,
                        unbindRequest   UnbindRequest,
                        searchRequest   SearchRequest,
                        searchResEntry  SearchResultEntry,
                        searchResDone   SearchResultDone,
                        searchResRef    SearchResultReference,
                        modifyRequest   ModifyRequest,
                        modifyResponse  ModifyResponse,
                        addRequest      AddRequest,
                        addResponse     AddResponse,
                        delRequest      DelRequest,
                        delResponse     DelResponse,
                        modDNRequest    ModifyDNRequest,
                        modDNResponse   ModifyDNResponse,
                        compareRequest  CompareRequest,
                        compareResponse CompareResponse,
                        abandonRequest  AbandonRequest,
                        extendedReq     ExtendedRequest,
                        extendedResp    ExtendedResponse },
                 controls       [0] Controls OPTIONAL }

        MessageID ::= INTEGER (0 .. maxInt)

        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --

        LDAPString ::= OCTET STRING

        LDAPOID ::= OCTET STRING

        LDAPDN ::= LDAPString

        RelativeLDAPDN ::= LDAPString
#endif

static long int handleint(unsigned char* c,int len) {
  long l=0;
  while (len) {
    l=l*256+*c;
    --len; ++c;
  }
  return l;
}

static int gethibitlen(unsigned char* c,unsigned char* max,unsigned long* len) {
  unsigned char* orig=c;
  if (*c&0x80) {
    int chars=*c&0x7f;
    *len=0;
    while (chars>0) {
      if (++c>=max) return 0;
      *len=*len*256+*c;
      --chars;
    }
  } else
    *len=*c&0x7f;
  return c-orig+1;
}

static int parsetag(unsigned char* c,unsigned char* max,unsigned long* tag,unsigned long* len) {
  unsigned char* orig=c;
  if (max<c+2) return 0;
  *tag=*len=0;
  /* find tag and length */
  if ((*c&0x1f)==0x1f)
    for (;;) {
      if (++c>=max) return 0;
      *tag=*tag*128+(*c&0x7F);
      if (!(*c&0x80)) break;
    }
  else
    *tag=*c&0x1f;
  ++c;
  c+=gethibitlen(c,max,len);
  return c-orig;
}

static void interpret(unsigned char* c,int dlen) {
//  unsigned char *max=c+dlen;
//  enum { PRIMITIVE, CONSTRUCTED } type;
  unsigned long tag=0;
  unsigned long len=0;
  switch (*c>>6) {
  case 0: puts("universal"); break;
  case 1: puts("application"); break;
  case 2: puts("context-specific"); break;
  case 3: puts("private"); break;
  }
  if (!(*c & 0x20)) {	/* primitive encoding */
    puts("primitive, definite-length");
  } else {
    puts("constructed, definite-length");
  }
  if ((*c&0x1f) == 0x1f) {	/* high-tag-number form */
    for (;;) {
      ++c;
      tag=tag*128+(*c&0x7F);
      if (!(*c&0x80)) break;
    }
  } else
    tag=*c&0x1f;
  ++c;
  if (*c&0x80) {
    int chars=*c&0x7f;
    while (chars>0) {
      ++c;
      len=len*256+*c;
      --chars;
    }
  } else
    len=*c&0x7f;
  ++c;
  switch (tag) {
  case 2:
    printf("  -> INTEGER: %ld\n",handleint(c,len));
    break;
  case 4:
    printf("  -> OCTET STRING: "); fwrite(c,len,1,stdout); printf("\n");
    break;
  case 10:
    printf("  -> ENUMERATED: %ld\n",handleint(c,len));
    break;
  case 16:
    puts("SEQUENCE OF");
    break;
  default:
    printf("unknown tag %lu (%lx)\n",tag,tag);
  }
  if (tag!=16) c+=len;
//  if (c<max) interpret(c,max-c);
}

/* parse ASN.1 INTEGER, return length or 0 on parse error */
static unsigned int parseintlike(unsigned char* buf,unsigned char* max,int Tag,long int* l) {
  int res;
  unsigned long tag,len;
  unsigned char* orig=buf;
  if ((res=parsetag(buf,max,&tag,&len))) {
    if (tag!=Tag) return 0;
    buf+=res;
    *l=0;
    while (len>sizeof(long)) {
      if (*buf) return 0;		/* number larger than native int size */
      ++buf; --len;
    }
    while (len) {
      *l=*l*256+*buf;
      ++buf; --len;
    }
    return buf-orig;
  }
  return 0;
}

static unsigned int parseint(unsigned char* buf,unsigned char* max,long int* l) {
  return parseintlike(buf,max,2,l);
}

static unsigned int parseenum(unsigned char* buf,unsigned char* max,long int* l) {
  return parseintlike(buf,max,10,l);
}

static unsigned int parsebool(unsigned char* buf,unsigned char* max,long int* l) {
  return parseintlike(buf,max,1,l);
}

/* parse ASN.1 OCTET STRING, return length or 0 on parse error */
static unsigned int parseoctetstring(unsigned char* buf,unsigned char* max,unsigned char** s,unsigned long* slen) {
  int res;
  unsigned long tag;
  unsigned char* orig=buf;
  if ((res=parsetag(buf,max,&tag,slen))) {
    if (tag!=4) return 0;
    buf+=res;
    *s=buf;
    buf+=*slen;
    return buf-orig;
  }
  return 0;
}

static int handlebind(unsigned char* buf,unsigned char* max,long messageid,int answerfd) {
  int res;
  long bindversion;
  unsigned char* s;
  unsigned long slen;
  /* int version */
  if (!(res=parseint(buf,max,&bindversion))) return -1;
  buf+=res;
  printf("bind version %ld\n",bindversion);
#if 0
  if (bindversion>3) {
    char buf[100];
    int b=8,e=8;
  }
#endif
  /* ldapdn name */
  if (!(res=parseoctetstring(buf,max,&s,&slen))) return -1;
  buf+=res;
  printf("name \""); fwrite(s,slen,1,stdout); printf("\"\n");
  /* authentication authenticationchoice */
  /* since we are such a trivial LDAP server, we discard bind requests */
  return 0;
}

struct attributevalueassertion {
  unsigned char* desc,* value;
  long dlen, vlen;
};

struct attributelist {
  unsigned char* a;
  long alen;
  struct attributelist* next;
};

static int parseava(unsigned char* buf,unsigned char* max, struct attributevalueassertion* ava) {
  /* SEQUENCE { desc: OCTET STRING, value: OCTET STRING } */
  int res;
  unsigned char* orig=buf;
  if (!(res=parseoctetstring(buf,max,&ava->desc,&ava->dlen))) return 0;
  buf+=res;
  if (!(res=parseoctetstring(buf,max,&ava->value,&ava->vlen))) return 0;
  buf+=res;
  printf("attribute value assertion: \"");
  fwrite(ava->desc,ava->dlen,1,stdout);
  printf("\" \"");
  fwrite(ava->value,ava->vlen,1,stdout);
  printf("\"\n");
  return buf-orig;
}

struct filter {
  enum {
    AND=0, OR=1, NOT=2, EQUAL=3, SUBSTRING=4, GREATEQUAL=5, LESSEQUAL=6, PRESENT=7, APPROX=8, EXTENSIBLE=9
  } type;
  struct attributevalueassertion ava;
  struct attributelist *a;
  enum {
    PREFIX=0, ANY=1, SUFFIX=2
  } substrtype;
  struct filter* x,*next;
};

static int parsefilter(unsigned char* buf,unsigned char* max,struct filter** f) {
/*
        Filter ::= CHOICE {
                and             [0] SET OF Filter,
                or              [1] SET OF Filter,
                not             [2] Filter,
                equalityMatch   [3] AttributeValueAssertion,
                substrings      [4] SubstringFilter,
                greaterOrEqual  [5] AttributeValueAssertion,
                lessOrEqual     [6] AttributeValueAssertion,
                present         [7] AttributeDescription,
                approxMatch     [8] AttributeValueAssertion,
                extensibleMatch [9] MatchingRuleAssertion }

        SubstringFilter ::= SEQUENCE {
                type            AttributeDescription,
                -- at least one must be present
                substrings      SEQUENCE OF CHOICE {
                        initial [0] LDAPString,
                        any     [1] LDAPString,
                        final   [2] LDAPString } }

        MatchingRuleAssertion ::= SEQUENCE {
                matchingRule    [1] MatchingRuleId OPTIONAL,
                type            [2] AttributeDescription OPTIONAL,
                matchValue      [3] AssertionValue,
                dnAttributes    [4] BOOLEAN DEFAULT FALSE }
*/
  unsigned char* orig=buf;
  unsigned long slen,tag;
  int res;
  *f=0;
  if ((buf[0]>>6)!=2) goto error;	/* context-specific */
  if (!(res=parsetag(buf,max,&tag,&slen))) goto error;
  if (tag<0 || tag>9) goto error;
  *f=malloc(sizeof(struct filter));
  (*f)->x=(*f)->next=0;
  (*f)->type=tag;
  buf+=res;
  switch (tag) {
  case 3: case 5: case 6: case 8:
    if (!(res=parseava(buf,buf+slen,&(*f)->ava))) goto error;
    buf+=res;
    break;
  case 0: puts("AND"); return 0;
  case 1:
    puts("OR");
    (*f)->x=0;
    while (buf<max) {
      struct filter* F=(*f)->x;
      int res;
      if (!(res=parsefilter(buf,max,&(*f)->x))) {
	if (F) {	/* OK, end of sequence */
	  (*f)->x=F;
	  return buf-orig;
	}
//	interpret(buf,max-buf);
	(*f)->x=F;
	goto error;
      }
      (*f)->x->next=F;
      buf+=res;
    }
//    interpret(buf,max-buf);
    return 0;
  case 2: puts("NOT"); return 0;
  case 4:
    {
      unsigned char* nmax=buf+slen;
      long l,tlen;
      if (!(res=parseoctetstring(buf,nmax,&(*f)->ava.desc,&(*f)->ava.dlen))) goto error;
      buf+=res;
      printf("substr in attribute \""); fwrite((*f)->ava.desc,(*f)->ava.dlen,1,stdout); printf("\"\n");
      if (!(res=parsetag(buf,nmax,&l,&tlen))) goto error;
      buf+=res;
      if (l != 16) goto error;	/* sequence of */
      if (buf+tlen != nmax) goto error;		/* no more tags after the sequence */
      while (buf<nmax) {
	if (!(res=parsetag(buf,nmax,&l,&tlen))) goto error;
	buf+=res;
	(*f)->ava.value=buf; (*f)->ava.vlen=tlen;
	buf+=tlen;
	if (l<0 || l>2) goto error;
	(*f)->substrtype=l;
	switch (l) {
	case 0: printf("prefix \""); break;
	case 1: printf("substr \""); break;
	case 2: printf("suffix \""); break;
	}
	fwrite((*f)->ava.value,(*f)->ava.vlen,1,stdout); printf("\"\n");
      }
      break;
    }
  case 7: puts("PRESENT"); return 0;
  case 9: puts("EXTENSIBLE"); return 0;
  default: goto error;
  }
  return buf-orig;
error:
  if (*f) { free(*f); *f=0; }
  return 0;
}

static void freefilter(struct filter* f) {
  if (f) {
    while (f->a) {
      struct attributelist* a=f->a->next;
      free(f->a);
      f->a=a;
    }
    if (f->x) freefilter(f->x);
    if (f->next) freefilter(f->next);
    free(f);
  }
}

static int handlesearch(unsigned char* buf,unsigned char* max) {
  int res;
  unsigned char* s;
  unsigned long slen,scope,deref,sizelimit,timelimit,typesonly;
  struct filter* f;
  f=0;
  /* int version */
  if (!(res=parseoctetstring(buf,max,&s,&slen))) goto error;
  buf+=res;
  printf("baseObject \""); fwrite(s,slen,1,stdout); printf("\"\n");
  /* scope enumerated; 0=baseObject, 1=singleLevel, 2=wholeSubtree */
  if (!(res=parseenum(buf,max,&scope))) goto error;
  buf+=res;
  printf("scope: ");
  switch (scope) {
  case 0: puts("baseObject"); break;
  case 1: puts("singleLevel"); break;
  case 2: puts("wholeSubtree"); break;
  default: goto error;
  }
  /* derefaliases enumerated; 0=never, 1=in searching, 2=baseobject, * 3=always */
  if (!(res=parseenum(buf,max,&deref))) goto error;
  buf+=res;
  printf("derefaliases: ");
  switch (scope) {
  case 0: puts("never"); break;
  case 1: puts("in searching"); break;
  case 2: puts("baseobject"); break;
  case 3: puts("always"); break;
  default: goto error;
  }
  /* int sizelimit */
  if (!(res=parseint(buf,max,&sizelimit))) goto error;
  buf+=res;
  printf("size limit %lu\n",sizelimit);
  /* int timelimit */
  if (!(res=parseint(buf,max,&timelimit))) goto error;
  buf+=res;
  printf("time limit %lu\n",timelimit);
  /* bool typesonly */
  if (!(res=parsebool(buf,max,&typesonly))) goto error;
  buf+=res;
  printf("typesonly %lu\n",typesonly);
  /* filter */
  if (!(res=parsefilter(buf,max,&f))) goto error;
  buf+=res;
  /* attributes */
  {
    unsigned char* nmax;
    long seqlen;
    struct attributelist** a=&f->a;
    if (buf[0]!='0') goto error;
    ++buf;
    buf+=gethibitlen(buf,max,&seqlen);
    nmax=buf+seqlen;
    if (nmax>max) goto error;
    for (;;) {
      if (buf>max) goto error;
      if (buf==max) break;
      if (!*a) *a=malloc(sizeof(struct attributelist));
      (*a)->next=0;
      if (!(res=parseoctetstring(buf,max,&(*a)->a,&(*a)->alen))) goto error;
      buf+=res;
      printf("attribute \""); fwrite((*a)->a,(*a)->alen,1,stdout); printf("\"\n");
      a=&(*a)->next;
    }
  }
  puts("ok");
  return 0;
error:
  freefilter(f);
  return -1;
}

#define TEST

/* return length of query that was parsed OK or 0 on parse error */
static unsigned int parseldapquery(unsigned char* buf,unsigned char* max,int answerfd) {
  long seqlen;
  int res;
  long messageid;
  unsigned long tag,len;
  unsigned char* orig=buf;
//  interpret(buf,max-buf);
  /* SEQUENCE OF */
  if (buf[0]!='0') goto error;
  ++buf;
  buf+=gethibitlen(buf,max,&seqlen);
  /* INTEGER message id */
  if (!(res=parseint(buf,max,&messageid))) goto error;
  buf+=res;
  printf("message id %ld\n",messageid);
  /* CHOICE */
  if ((buf[0]>>6)!=1) return 0;	/* application */
  if (!(res=parsetag(buf,max,&tag,&len))) goto error;
  buf+=res;
  switch (tag) {
  case 0:
    puts("bind");
    if (handlebind(buf,max,messageid,answerfd)) goto error;
    break;
  case 2:
    puts("unbind");
    break;
  case 3:
    puts("search");
    if (handlesearch(buf,buf+len)) goto error;
    break;
  case 16:
    printf("abandon %lu\n",handleint(buf,len));
    break;
#ifdef TEST
  case 1:
    puts("bindreply");
    /*
        BindResponse ::= [APPLICATION 1] SEQUENCE {
             COMPONENTS OF LDAPResult,
             serverSaslCreds    [7] OCTET STRING OPTIONAL }
     */
    {
      long code,alen;
      int res;
      unsigned char* a;
      len+=(buf-orig);
      if (!(res=parseenum(buf,orig+len,&code))) goto error;
      printf("code %ld\n",code);
      buf+=res;
      if (!(res=parseoctetstring(buf,max,&a,&alen))) goto error;
      buf+=res;
      printf("matchedDN \""); fwrite(a,alen,1,stdout); printf("\"\n");
      if (!(res=parseoctetstring(buf,max,&a,&alen))) goto error;
      buf+=res;
      printf("errorMessage \""); fwrite(a,alen,1,stdout); printf("\"\n");
      return len;
    }
    break;
  case 4:
    puts("searchResult");
    {
      int res;
      long tag,alen;
      unsigned char* a;
      if (!(res=parseoctetstring(buf,max,&a,&alen))) goto error;
      buf+=res;
      printf("objectName \""); fwrite(a,alen,1,stdout); printf("\"\n");

      if (!(res=parsetag(buf,max,&tag,&alen))) goto error;
      if (tag != 16) goto error;
      printf("sequence length %ld\n",alen);
      buf+=res;
    }
    return 0;
#endif
  default:
    printf("unknown op %ld\n",tag);
    return 0;
  }
  printf("skipping len %ld\n",len);
  buf+=len;
  return buf-orig;
error:
  return 0;
}

int main(int argc,char* argv[]) {
  char buf[8192];
  char* max;
  int l,fd,res;
//  fd=open_read("/tmp/ldap/127.000.000.001.32875-127.000.000.001.00389");
  fd=open_read(argv[1] ? argv[1] : "data");
//  fd=open_read("/tmp/ldap/127.000.000.001.38433-127.000.000.001.00389");
//  fd=open_read("/tmp/ldap/127.000.000.001.00389-127.000.000.001.32779");
//  fd=open_read("answer");
  l=read(fd,buf,8192);
  max=buf+l;
  close(fd);
  l=0;
  for (;;) {
    res=parseldapquery(buf+l,max,1);
    printf("res= %d\n",res);
    if (res==0) break;
    l+=res;
  }
//  interpret(buf,l);
  return 0;
}
