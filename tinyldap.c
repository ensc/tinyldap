#include <unistd.h>
#include <stdlib.h>
#include "byte.h"
#include "buffer.h"
#include "ldap.h"
#include "ldif.h"
#include "open.h"
#include "socket.h"
#include "ip6.h"
#ifdef STANDALONE
#include <wait.h>
#endif

static int verbose=0;

#define BUFSIZE 8192

int handle(int in,int out) {
  int len;
  char buf[BUFSIZE];
  for (len=0;;) {
    int tmp=read(in,buf+len,BUFSIZE-len);
    int res;
    long messageid,op,Len;
    if (tmp==0)
      if (!len) { return 0; }
    if (tmp<0) { write(2,"error!\n",7); return 1; }
    len+=tmp;
    res=scan_ldapmessage(buf,buf+len,&messageid,&op,&Len);
    if (res>0) {
      if (verbose) {
	buffer_puts(buffer_2,"got message of length ");
	buffer_putulong(buffer_2,Len);
	buffer_puts(buffer_2," with id ");
	buffer_putulong(buffer_2,messageid);
	buffer_puts(buffer_2,": op ");
	buffer_putulong(buffer_2,op);
	buffer_putsflush(buffer_2,".\n");
      }
      switch (op) {
      case BindRequest:
	{
	  long version,method;
	  struct string name;
	  int tmp;
	  tmp=scan_ldapbindrequest(buf+res,buf+res+len,&version,&name,&method);
	  if (tmp>=0) {
	    if (verbose) {
	      buffer_puts(buffer_2,"bind request: version ");
	      buffer_putulong(buffer_2,version);
	      buffer_puts(buffer_2," for name \"");
	      buffer_put(buffer_2,name.s,name.l);
	      buffer_puts(buffer_2,"\" with method ");
	      buffer_putulong(buffer_2,method);
	      buffer_putsflush(buffer_2,".\n");
	    }
	    {
	      char outbuf[1024];
	      int s=100;
	      int len=fmt_ldapbindresponse(outbuf+s,0,"","go ahead","");
	      int hlen=fmt_ldapmessage(0,messageid,BindResponse,len);
	      fmt_ldapmessage(outbuf+s-hlen,messageid,BindResponse,len);
	      write(out,outbuf+s-hlen,len+hlen);
	    }
	  }
	}
	break;
      case SearchRequest:
	{
	  struct SearchRequest sr;
	  int tmp;
#if 0
	  {
	    int fd=open_write("request");
	    write(fd,buf,res+len);
	    close(fd);
	  }
#endif
	  if ((tmp=scan_ldapsearchrequest(buf+res,buf+res+len,&sr))) {
	    struct ldaprec* r=first;
#if 0
	    buffer_puts(buffer_2,"baseObject: \"");
	    buffer_put(buffer_2,sr.baseObject.s,sr.baseObject.l);
	    buffer_putsflush(buffer_2,"\"\n");
#endif
	    while (r) {
#if 0
	      buffer_puts(buffer_2,"ldap_match(\"");
	      buffer_puts(buffer_2,r->dn);
	      buffer_putsflush(buffer_2,"\"\n");
#endif
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
#if 0
		    buffer_puts(buffer_2,"looking for attribute \"");
		    buffer_put(buffer_2,adl->a.s,adl->a.l);
		    buffer_putsflush(buffer_2,"\"\n");
#endif
		    if (!matchstring(&adl->a,"dn")) val=r->dn; else
		    if (!matchstring(&adl->a,"cn")) val=r->cn; else
		    if (!matchstring(&adl->a,"mail")) val=r->mail; else
		    if (!matchstring(&adl->a,"sn")) val=r->sn; else
		    for (; i<r->n; ++i) {
#if 0
		      buffer_puts(buffer_2,"comparing with \"");
		      buffer_puts(buffer_2,r->a[i].name);
		      buffer_putsflush(buffer_2,"\"\n");
#endif
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
		  if (verbose) {
		    buffer_puts(buffer_2,"sre len ");
		    buffer_putulong(buffer_2,l);
		    buffer_putsflush(buffer_2,".\n");
		  }
		  tmp=fmt_ldapmessage(buf,messageid,SearchResultEntry,l);
		  fmt_ldapsearchresultentry(buf+tmp,&sre);
		  write(out,buf,l+tmp);
		}
		if (verbose) {
		  buffer_puts(buffer_2,"found: ");
		  buffer_puts(buffer_2,r->dn);
		  buffer_putsflush(buffer_2,"\n");
		}
	      }
	      r=r->next;
	    }
	  } else {
	    buffer_putsflush(buffer_2,"couldn't parse search request!\n");
	    exit(1);
	  }
	  {
	    char buf[1000];
	    long l=fmt_ldapsearchresultdone(buf+100,0,"","","");
	    int hlen=fmt_ldapmessage(0,messageid,SearchResultDone,l);
	    fmt_ldapmessage(buf+100-hlen,messageid,SearchResultDone,l);
	    write(out,buf+100-hlen,l+hlen);
	  }
	}
	break;
      default:
	exit(1);
      }
      Len+=res;
#if 0
      buffer_puts(buffer_2,"byte_copy(buf,");
      buffer_putulong(buffer_2,len-Len);
      buffer_puts(buffer_2,",buf+");
      buffer_putulong(buffer_2,Len);
      buffer_putsflush(buffer_2,");\n");
#endif
      if (Len<len) {
	byte_copy(buf,len-Len,buf+Len);
	len-=Len;
      } else len=0;
    } else
      exit(2);
  }
}

int main() {
#ifdef STANDALONE
  int sock;
#endif
  ldif_parse("exp.ldif");
  if (!first) {
    buffer_putsflush(buffer_2,"keine Datenbasis?!");
  }

#ifdef STANDALONE
  if ((sock=socket_tcp6())==-1) {
    buffer_putsflush(buffer_2,"socket failed!\n");
    exit(1);
  }
  if (socket_bind6_reuse(sock,V6any,389,0)) {
    buffer_putsflush(buffer_2,"bind failed!\n");
    exit(1);
  }
  if (socket_listen(sock,32)) {
    buffer_putsflush(buffer_2,"listen failed!\n");
    exit(1);
  }
  for (;;) {
    char ip[16];
    uint16 port;
    uint32 scope_id;
    int asock;
    {
      int status;
      while ((status=waitpid(-1,0,WNOHANG))!=0 && status!=(pid_t)-1); /* reap zombies */
    }
    asock=socket_accept6(sock,ip,&port,&scope_id);
    if (asock==-1) {
      buffer_putsflush(buffer_2,"accept failed!\n");
      exit(1);
    }
#ifdef DEBUG
    handle(asock,asock);
    exit(0);
#else
#endif
    switch (fork()) {
    case -1: buffer_putsflush(buffer_2,"fork failed!\n"); exit(1);
    case 0: /* child */
      handle(asock,asock);
      exit(0); /* not reached */
    default:
      close(asock);
    }
  }
#else
  handle(0,1);
#endif
  return 0;
}
