#include <unistd.h>
#include "byte.h"
#include "buffer.h"
#include "ldap.h"
#include "socket.h"
#include "ip4.h"

#define BUFSIZE 8192

int main() {
  int sock;
  char buf[BUFSIZE];
  int len=0;
  long messageid=1;

  sock=socket_tcp4();
  {
    char ip[4];
    scan_ip4(ip,"127.0.0.1");
    if (socket_connect4(sock,ip,389)) {
      buffer_putsflush(buffer_2,"could not connect to ldap server!\n");
      return 1;
    }
  }
  {
    char outbuf[1024];
    int s=100;
    int len=fmt_ldapbindrequest(outbuf+s,3,"","");
    int hlen=fmt_ldapmessage(0,messageid,BindRequest,len);
    fmt_ldapmessage(outbuf+s-hlen,messageid,BindRequest,len);
    write(sock,outbuf+s-hlen,len+hlen);
  }
  for (;;) {
    int tmp=read(sock,buf+len,BUFSIZE-len);
    int res;
    long messageid,op,Len;
    if (tmp==0) { write(2,"eof!\n",5); return 0; }
    if (tmp<1) { write(2,"error!\n",7); return 1; }
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
      case BindResponse:
	{
	  long result;
	  struct string matcheddn,errormessage,referral;
	  res=scan_ldapbindresponse(buf+res,buf+res+len,&result,&matcheddn,&errormessage,&referral);
	  if (res>=0) {
	    buffer_puts(buffer_2,"bind response: result ");
	    buffer_putulong(buffer_2,result);
	    buffer_puts(buffer_2,", matched dn \"");
	    buffer_put(buffer_2,matcheddn.s,matcheddn.l);
	    buffer_puts(buffer_2,"\", error message \"");
	    buffer_put(buffer_2,errormessage.s,errormessage.l);
	    buffer_puts(buffer_2,"\", referral \"");
	    buffer_put(buffer_2,referral.s,referral.l);
	    buffer_putsflush(buffer_2,"\".\n");
	  }
	}
      }
      if (Len<len) {
	byte_copyr(buf,len-Len,buf+len);
	len-=Len;
      }
    }
  }
}
