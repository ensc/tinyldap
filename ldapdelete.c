#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libowfat/byte.h>
#include <libowfat/buffer.h>
#include "ldap.h"
#include <libowfat/socket.h>
#include <libowfat/ip4.h>
#include <libowfat/str.h>
#include <libowfat/textcode.h>

#include <fcntl.h>
#include <sys/socket.h>

#define BUFSIZE 8192

static unsigned long messageid=1;

static int ldapbind(int sock) {
  char outbuf[1024];
  int s=100;
  size_t len=fmt_ldapbindrequest(outbuf+s,3,"","");
  size_t hlen=fmt_ldapmessage(0,messageid,BindRequest,len);
  size_t res,Len;
  unsigned long op,result;
  struct string matcheddn,errormessage,referral;
  fmt_ldapmessage(outbuf+s-hlen,messageid,BindRequest,len);
  if ((size_t)write(sock,outbuf+s-hlen,len+hlen)!=len+hlen) return 0;;
  len=read(sock,outbuf,1024);
  res=scan_ldapmessage(outbuf,outbuf+len,&messageid,&op,&Len);
  if (!res) return 0;
  if (op!=BindResponse) return 0;
  res=scan_ldapbindresponse(outbuf+res,outbuf+res+Len,&result,&matcheddn,&errormessage,&referral);
  if (!res) return 0;
  if (result) return 0;
  return 1;
}

int main(int argc,char* argv[]) {
  int sock;
  char buf[BUFSIZE];
  int len=0;

  if (argc<2) {
usage:
    buffer_putsflush(buffer_2,"usage: ldapdelete ip dn\n");
    return 0;
  }

  sock=socket_tcp4b();
  {
    char ip[4];
    if (argv[1][scan_ip4(argv[1],ip)]) goto usage;
    if (socket_connect4(sock,ip,389)) {
      buffer_putsflush(buffer_2,"could not connect to ldap server!\n");
      return 1;
    }
  }
  if (ldapbind(sock)) {
    struct string s;

    s.l=strlen(argv[2]);
    s.s=argv[2];

    len=fmt_ldapdeleterequest(buf+100,&s);
    {
      int tmp=fmt_ldapmessage(0,++messageid,DelRequest,len);
      fmt_ldapmessage(buf+100-tmp,messageid,DelRequest,len);
      write(sock,buf+100-tmp,len+tmp);
    }
    shutdown(sock,SHUT_WR);
    {
      char buf[32*1024];	/* arbitrary limit, bad! */
      int len=0,tmp,tmp2;
      char* max;

      unsigned long mid,op;
      size_t slen;
      int cur=0;

      tmp=read(sock,buf+len,sizeof(buf)-len);

      if (tmp<=0) {
	buffer_putsflush(buffer_2,"read error.\n");
	return 2;
      }
      len+=tmp;
      if ((tmp2=scan_ldapmessage(buf+cur,buf+len,&mid,&op,&slen))) {
	max=buf+cur+slen+tmp2;
	if (op==DelResponse) {
	  unsigned long result;
	  struct string matcheddn, errormessage, referral;
	  if (scan_ldapresult(buf+cur+tmp2,max,&result,&matcheddn,&errormessage,&referral)>0) {
	    if (result==success) {
	      buffer_putsflush(buffer_2,"ok\n");
	    } else {
	      buffer_puts(buffer_2,"fail, code ");
	      buffer_putulong(buffer_2,result);
	      if (errormessage.l) {
		buffer_puts(buffer_2,", error message \"");
		buffer_put(buffer_2,errormessage.s,errormessage.l);
		buffer_puts(buffer_2,"\n");
	      }
	      buffer_putsflush(buffer_2,".\n");
	    }
	  } else
	    buffer_putsflush(buffer_2,"failed to parse result message.\n");
	} else
	  buffer_putsflush(buffer_2,"unexpected response.\n");
      } else
	buffer_putsflush(buffer_2,"failed to parse ldap message.\n");
    }
  } else {
    buffer_putsflush(buffer_2,"ldapbind failed\n");
    return 2;
  }
  close(sock);

  return 0;
}
