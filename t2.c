#include <unistd.h>
#include <stdio.h>
#include "mmap.h"
#include "asn1.h"
#include "ldap.h"

/* this is some sort of protocol analyzer.  You give it a file name with
 * a network dump of an LDAP correspondence, and it will try to parse it
 * and display it in human readable form */

void printava(struct AttributeValueAssertion* a,const char* rel) {
  printf("[%.*s %s %.*s]",(int)a->desc.l,a->desc.s,rel,(int)a->value.l,a->value.s);
}

void printal(struct AttributeDescriptionList* a) {
  while (a) {
    printf("%.*s",(int)a->a.l,a->a.s);
    a=a->next;
    if (a) printf(",");
  }
  printf("\n");
}

void printfilter(struct Filter* f) {
  switch (f->type) {
  case AND:
    printf("&(");
mergesub:
    printfilter(f->x);
    printf(")");
    break;
  case OR:
    printf("|(");
    goto mergesub;
    break;
  case NOT:
    printf("!(");
    goto mergesub;
  case EQUAL:
    printava(&f->ava,"==");
    break;
  case SUBSTRING:
    {
      struct Substring* s=f->substrings;
      int first=1;
      printf("%.*s has ",(int)f->ava.desc.l,f->ava.desc.s);
      while (s) {
	if (!first) printf(" and "); first=0;
	switch(s->substrtype) {
	case prefix: printf("prefix \""); break;
	case any: printf("substr \""); break;
	case suffix: printf("suffix \""); break;
	}
	printf("%.*s\"",(int)s->s.l,s->s.s);
	s=s->next;
      }
    }
    break;
  case GREATEQUAL:
    printava(&f->ava,">=");
    break;
  case LESSEQUAL:
    printava(&f->ava,"<=");
    break;
  case PRESENT:
    printava(&f->ava,"\\exist");
    break;
  case APPROX:
    printava(&f->ava,"\\approx");
    break;
  case EXTENSIBLE:
    printf("[extensible]");
    break;
  }
  if (f->next) {
    printf(",");
    printfilter(f->next);
  }
}

int main(int argc,char* argv[]) {
#if 1
  unsigned long size;
//  char* ldapsequence=mmap_read("req",&size);
  char* ldapsequence=mmap_read(argc>1?argv[1]:"/tmp/ldap/127.000.000.001.00389-127.000.000.001.38433",&size);
  long messageid, op, len;
  int res,done=0;
  while (done<size) {
    printf("scan_ldapmessage: %d\n",res=scan_ldapmessage(ldapsequence+done,ldapsequence+size,&messageid,&op,&len));
    if (!res) { puts("punt!"); break; }
    printf("message id %lu, op %lu, len %lu\n",messageid,op,len);
    switch (op) {
    case BindRequest:
      puts("  >> BindRequest <<");
      {
	long version,method;
	struct string name;
	int tmp;
	printf("scan_ldapbindrequest: %d\n",tmp=scan_ldapbindrequest(ldapsequence+done+res,ldapsequence+done+res+len,&version,&name,&method));
	printf("version %lu, name \"%.*s\", method %lu\n",version,(int)name.l,name.s,method);
	if (method==0) {
	  enum asn1_tagclass tc;
	  enum asn1_tagtype tt;
	  long tag;
	  if (scan_asn1string(ldapsequence+done+res+tmp,ldapsequence+size,&tc,&tt,&tag,&name.s,&name.l) &&
	      tc==PRIVATE && tt==PRIMITIVE && tag==0)
	    printf("simple \"%.*s\"\n",(int)name.l,name.s);
	  else
	    puts("method 0 but couldn't parse simple");
	} else
	  puts("unknown method!");
	break;
      }
    case BindResponse:
      puts("  >> BindResponse <<");
      {
	long result;
	struct string matcheddn,errormessage,referral;
	int tmp;
	printf("scan_ldapbindresponse: %d\n",
	       tmp=scan_ldapbindresponse(ldapsequence+done+res,ldapsequence+done+res+len,
					 &result,&matcheddn,&errormessage,&referral));
	printf("result %lu, matcheddn \"%.*s\", errormessage \"%.*s\", referral \"%.*s\"\n",
	       result,(int)matcheddn.l,matcheddn.s,
	       (int)errormessage.l,errormessage.s,
	       (int)referral.l,referral.s);
	break;
      }
      break;
    case SearchRequest:
      puts("  >> SearchRequest <<");
      {
	struct SearchRequest br;
	int tmp;
	printf("scan_ldapsearchrequest %d\n",tmp=scan_ldapsearchrequest(ldapsequence+done+res,ldapsequence+done+res+len,&br));
	if (tmp) {
	  printf("baseObject: \"%.*s\"\n",(int)br.baseObject.l,br.baseObject.s);
	  printfilter(br.filter); printf("\n");
	}
	printal(br.attributes);
	break;
      }
    case SearchResultEntry:
      puts("  >> SearchResultEntry <<");
      {
	struct SearchResultEntry sre;
	int tmp;
	int first=1;
	if ((tmp=scan_ldapsearchresultentry(ldapsequence+done+res,ldapsequence+done+res+len,&sre))) {
	  struct PartialAttributeList* pal=sre.attributes;
ausgeben:
	  printf("objectName \"%.*s\"\n",(int)sre.objectName.l,sre.objectName.s);
	  while (pal) {
	    struct AttributeDescriptionList* adl=pal->values;
	    printf("  %.*s:",(int)pal->type.l,pal->type.s);
	    while (adl) {
	      printf("%.*s",(int)adl->a.l,adl->a.s);
	      if (adl->next) printf(", ");
	      adl=adl->next;
	    }
	    printf("\n");
	    pal=pal->next;
	  }
	  if (!first) exit(0); first=0;

	  {
	    char *buf=alloca(len+1000);
	    int mylen;
	    printf("fmt_ldapsearchresultentry: %d vs %ld\n",
		   mylen=fmt_ldapsearchresultentry(buf,&sre),len);
	    memset(&sre,0,sizeof(sre));
	    if (tmp=scan_ldapsearchresultentry(buf,buf+mylen,&sre)) {
	      pal=sre.attributes;
	      goto ausgeben;
	    }
	  }
	  exit(0);
	} else
	  puts("punt!");
      }
      break;
    case SearchResultDone:
      puts("  >> SearchResultDone <<");
      puts("to be done");
      break;
    case UnbindRequest:
      puts("  >> UnbindRequest <<");
      break;
    case AbandonRequest:
      puts("  >> AbandonRequest <<");
      {
	unsigned long which;
	if (scan_asn1rawint(ldapsequence+done+res,ldapsequence+done+res+len,len,&which))
	  printf("Abandon: %lu\n",which);
      }
      break;
    default:
      puts("  >> unklar << ;)");
    }
    done+=len+res;
  }
#endif
#if 0
  char buf[1024];
  enum asn1_tagtype tt;
  enum asn1_tagclass tc;
  long tag,len;
  int res;
  const char* c;
  printf("%d\n",res=fmt_asn1int(buf,UNIVERSAL,PRIMITIVE,INTEGER,0x01020304));
  printf("%d\n",scan_asn1int(buf,buf+res,&tc,&tt,&tag,&len));
  printf("got %lx\n",len);
  printf("%d\n",res=fmt_asn1string(buf,UNIVERSAL,PRIMITIVE,OCTET_STRING,"fnord",5));
  printf("%d\n",scan_asn1string(buf,buf+res,&tc,&tt,&tag,&c,&len));
  printf("got %.*s\n",(int)len,c);
#endif
  return 0;
}
