#include <unistd.h>
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
	  struct SearchRequest br;
	  int tmp;
	  if ((tmp=scan_ldapsearchrequest(buf+res,buf+res+len,&br))) {
	    struct ldaprec* r=first;
	    while (r) {
	      if (ldap_match(r,&br)) {
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
