#include <unistd.h>
#include <stdlib.h>
#include "byte.h"
#include "buffer.h"
#include "ldap.h"
#include "ldif.h"

#define BUFSIZE 8192

int main() {
  char buf[BUFSIZE];
  int len=0;
  ldif_parse("exp.ldif");
  for (;;) {
    int tmp=read(0,buf+len,BUFSIZE-len);
    int res;
    long messageid,op,Len;
    if (tmp==0)
      if (!len) { write(2,"eof!\n",5); return 0; }
    if (tmp<0) { write(2,"error!\n",7); return 1; }
    len+=tmp;
    res=scan_ldapmessage(buf,buf+len,&messageid,&op,&Len);
    if (res>0) {
      buffer_puts(buffer_2,"got message of length ");
      buffer_putulong(buffer_2,Len);
      buffer_puts(buffer_2," with id ");
      buffer_putulong(buffer_2,messageid);
      buffer_puts(buffer_2,": op ");
      buffer_putulong(buffer_2,op);
      buffer_putsflush(buffer_2,".\n");
      switch (op) {
      case BindRequest:
	{
	  long version,method;
	  struct string name;
	  int tmp;
	  tmp=scan_ldapbindrequest(buf+res,buf+res+len,&version,&name,&method);
	  if (tmp>=0) {
	    buffer_puts(buffer_2,"bind request: version ");
	    buffer_putulong(buffer_2,version);
	    buffer_puts(buffer_2," for name \"");
	    buffer_put(buffer_2,name.s,name.l);
	    buffer_puts(buffer_2,"\" with method ");
	    buffer_putulong(buffer_2,method);
	    buffer_putsflush(buffer_2,".\n");
	    {
	      char outbuf[1024];
	      int s=100;
	      int len=fmt_ldapbindresponse(outbuf+s,0,"","go ahead","");
	      int hlen=fmt_ldapmessage(0,messageid,BindResponse,len);
	      fmt_ldapmessage(outbuf+s-hlen,messageid,BindResponse,len);
	      write(1,outbuf+s-hlen,len+hlen);
	    }
	  }
	}
	break;
      case SearchRequest:
	{
	  struct SearchRequest sr;
	  int tmp;
	  if ((tmp=scan_ldapsearchrequest(buf+res,buf+res+len,&sr))) {
	    struct ldaprec* r=first;
	    while (r) {
	      if (ldap_match(r,&sr)) {
		struct SearchResultEntry sre;
		struct PartialAttributeList** pal=&sre.attributes;
		sre.objectName.s=r->dn; sre.objectName.l=strlen(r->dn);
		sre.attributes=0;
		/* now go through list of requested attributes */
		{
		  struct AttributeDescriptionList* adl=sr.attributes;
		  while (adl) {
		    const char* val=0;
		    int i=0;
		    buffer_puts(buffer_2,"looking for attribute \"");
		    buffer_put(buffer_2,adl->a.s,adl->a.l);
		    buffer_putsflush(buffer_2,"\"\n");
		    if (!matchstring(&adl->a,"dn")) val=r->dn; else
		    if (!matchstring(&adl->a,"cn")) val=r->cn; else
		    if (!matchstring(&adl->a,"mail")) val=r->mail; else
		    if (!matchstring(&adl->a,"sn")) val=r->sn; else
		    for (; i<r->n; ++i) {
		      buffer_puts(buffer_2,"comparing with \"");
		      buffer_puts(buffer_2,r->a[i].name);
		      buffer_putsflush(buffer_2,"\"\n");
		      if (!matchstring(&adl->a,r->a[i].name))
			val=r->a[i].value;
		    }
		    if (val) {
		      *pal=malloc(sizeof(struct PartialAttributeList));
		      if (!*pal) {
nomem:
			buffer_putsflush(buffer_2,"out of virtual memory!\n");
			exit(1);
		      }
		      (*pal)->type=adl->a;
		      {
			struct AttributeDescriptionList** a=&(*pal)->values;
			while (i<r->n) {
			  *a=malloc(sizeof(struct AttributeDescriptionList));
			  if (!*a) goto nomem;
			  (*a)->a.s=val;
			  (*a)->a.l=strlen(val);
			  (*a)->next=0;
			  for (;i<r->n; ++i)
			    if (!matchstring(&adl->a,r->a[i].name)) {
			      val=r->a[i].value;
			      break;
			    }
			}
		      }
		      (*pal)->next=0;
		      pal=&(*pal)->next;
		    }
		    adl=adl->next;
		  }
		}
		{
		  long l=fmt_ldapsearchresultentry(0,&sre);
		  char *buf=alloca(l+300); /* you never know ;) */
		  long tmp;
		  buffer_puts(buffer_2,"sre len ");
		  buffer_putulong(buffer_2,l);
		  buffer_putsflush(buffer_2,".\n");
		  tmp=fmt_ldapmessage(buf,++messageid,SearchResultEntry,l);
		  fmt_ldapsearchresultentry(buf+tmp,&sre);
		  write(1,buf,l+tmp);
		}
		{
		  char buf[1000];
		  long l=fmt_ldapsearchresultdone(buf+100,0,"","","");
		  int hlen=fmt_ldapmessage(0,++messageid,SearchResultDone,l);
		  fmt_ldapmessage(buf+100-hlen,messageid,SearchResultDone,l);
		  write(1,buf+100-hlen,l+hlen);
		}
		buffer_puts(buffer_2,"found: ");
		buffer_puts(buffer_2,r->dn);
		buffer_putsflush(buffer_2,"\n");
	      }
	      r=r->next;
	    }
	  }
	}
	break;
      default:
	exit(1);
      }
      Len+=res;
      if (Len<len) {
	byte_copy(buf,len-Len,buf+Len);
	len-=Len;
      }
    } else
      exit(2);
  }
}
