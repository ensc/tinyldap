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
#include <netinet/in.h>
#include <netinet/tcp.h>

#define BUFSIZE 8192

static void buffer_putescaped(buffer* b,const char* x,size_t l) {
  size_t needed=fmt_ldapescape2(0,x,l,"");
  char* buf;
  if (needed>100000)
    buf=0;
  buf=alloca(needed);
  fmt_ldapescape2(buf,x,l,"");
  buffer_put(b,buf,needed);
}

static unsigned long messageid=1;

static int ldapbind(int sock) {
  char outbuf[1024];
  int s=100;
  char* u=getenv("LDAP_USER"),* p=getenv("LDAP_PASSWD");
  if (!u) u="";
  if (!p) p="";
  if (strlen(u)>100 || strlen(p)>100)
    return 0;
  size_t len=fmt_ldapbindrequest(outbuf+s,3,u,p);
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
  int sock=0;
  char buf[BUFSIZE];
  int len=0;
  char* me;
  long n,durchlauf;
  int bench,bench2;
  if ((me=strrchr(argv[0],'/')))
    ++me;
  else
    me=argv[0];
  n=1;
  if ((bench=!strcmp(me,"ldapbench"))) {
    char* c=getenv("NUM");
    if (!c) goto usage;
    n=atoi(c);
    if (n<1) goto usage;
    if (getenv("CONNECT"))
      bench=2;
    buffer_putsflush(buffer_2,"benchmark mode\n");
  }
  bench2=0;

  if (argc<4) {
usage:
    buffer_puts(buffer_2,"usage: ldapclient ip baseObject filter [foo...]\n");
    if (bench)
      buffer_puts(buffer_2,"and set $NUM to the number of iterations,\nand $CONNECT to anything to do only one connection (instead of one per request).\n");
    buffer_putsflush(buffer_2,"To use basic authentication, set $LDAP_USER to the dn and $LDAP_PASSWD to the password.\n"
		     "Note that this is for debugging in trusted environments only, as other users can see this in ps(8).\n");
    return 0;
  }
  for (durchlauf=0; durchlauf<n; ++durchlauf) {
    if (bench==2 && bench2) goto skipconnect;
    sock=socket_tcp4b();
    {
      char ip[4];
      if (argv[1][scan_ip4(argv[1],ip)]) goto usage;
      if (socket_connect4(sock,ip,389)) {
	buffer_putsflush(buffer_2,"could not connect to ldap server!\n");
	return 1;
      }
    }
    {
      int one=1;
      setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
    }
    if (ldapbind(sock)) {
      static struct Filter *f;
      static struct AttributeDescriptionList adl;
      static struct AttributeDescriptionList *next;
      static struct SearchRequest sr;
      int i;
      if (!scan_ldapsearchfilterstring(argv[3],&f)) {
	buffer_putsflush(buffer_2,"could not parse filter!\n");
	close(sock);
	return 1;
      }
      i=4; /* This should be the first index to an attribute argument in argv[] */
      if (argc>4) {
	adl.a.s=argv[i];
	adl.a.l=str_len(argv[i]);
	next=&adl;
	++i;
	while (i<argc) {
	  struct AttributeDescriptionList *n;
	  n=malloc(sizeof(struct AttributeDescriptionList));
	  n->a.s=argv[i]; n->a.l=str_len(argv[i]);
	  n->next=0;
	  next->next=n;
	  next=n;

#if 0
	  buffer_puts(buffer_2,"requesting ");
	  buffer_puts(buffer_2,argv[i]);
	  buffer_putnlflush(buffer_2);
#endif

	  i++;
	}
	sr.attributes=&adl;
      } else {
	sr.attributes=0;
      }
      sr.baseObject.s=argv[2]; sr.baseObject.l=str_len(sr.baseObject.s);
      sr.scope=wholeSubtree; sr.derefAliases=neverDerefAliases;
      sr.sizeLimit=sr.timeLimit=sr.typesOnly=0;
      sr.filter=f;
      bench2=1;
skipconnect:
      len=fmt_ldapsearchrequest(buf+100,&sr);
      {
	int tmp=fmt_ldapmessage(0,++messageid,SearchRequest,len);
	fmt_ldapmessage(buf+100-tmp,messageid,SearchRequest,len);
	write(sock,buf+100-tmp,len+tmp);
      }
      if (bench!=2)
	shutdown(sock,SHUT_WR);
      {
	char buf[32*1024];	/* arbitrary limit, bad! */
	int len=0,tmp,tmp2;
	char* max;
	struct SearchResultEntry sre;
	int matches=0;
	len=0;
	for (;;) {
	  unsigned long mid,op;
	  size_t slen;
	  int cur=0;

	  tmp=read(sock,buf+len,sizeof(buf)-len);

#if 0
	  buffer_puts(buffer_2,"DEBUG: read ");
	  buffer_putulong(buffer_2,tmp);
	  buffer_putsflush(buffer_2," bytes.\n");
#endif

	  if (tmp<=0) {
	    buffer_putsflush(buffer_2,"read error.\n");
	    return 0;
	  }
  //	cur=len;
	  len+=tmp;
nextmessage:
	  if ((tmp2=scan_ldapmessage(buf+cur,buf+len,&mid,&op,&slen))) {
	    max=buf+cur+slen+tmp2;
	    if (op==SearchResultEntry) {
	      ++matches;
	      if ((tmp=scan_ldapsearchresultentry(buf+cur+tmp2,max,&sre))) {
		struct PartialAttributeList* pal=sre.attributes;

#if 0
		buffer_puts(buffer_2,"DEBUG: sre size ");
		buffer_putulong(buffer_2,tmp);
		buffer_putsflush(buffer_2,".\n");
#endif

		if (durchlauf==0) {
		  buffer_puts(buffer_1,"dn: ");
		  buffer_putescaped(buffer_1,sre.objectName.s,sre.objectName.l);
		  buffer_puts(buffer_1,"\n");
		  while (pal) {
		    struct AttributeDescriptionList* adl=pal->values;
		    do {
//		      buffer_puts(buffer_1,"  ");
		      buffer_putescaped(buffer_1,pal->type.s,pal->type.l);
		      buffer_puts(buffer_1,": ");
		      if (adl) {
			buffer_putescaped(buffer_1,adl->a.s,adl->a.l);
			buffer_puts(buffer_1,"\n");
			adl=adl->next;
			if (!adl) break;
		      }
		    } while (adl);
		    pal=pal->next;
		  }
		  buffer_putsflush(buffer_1,"\n");
		}
		free_ldapsearchresultentry(&sre);
	      } else {
		buffer_putsflush(buffer_2,"goto\n");
		goto copypartialandcontinue;
	      }
	    } else if (op==SearchResultDone) {
	      unsigned long result;
	      struct string matcheddn,errormessage,referral;
	      if (scan_ldapresult(buf+cur+tmp2,max,&result,&matcheddn,&errormessage,&referral)>0) {
		if (result!=0) {
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
		buffer_putsflush(buffer_2,"scan_ldapresult failed!\n");
	      if (!matches)
		buffer_putsflush(buffer_2,"no matches.\n");
	      if (bench && durchlauf!=0)
		write(1,"+",1);
	      break;
//	      return 0;
	    } else {
	      buffer_putsflush(buffer_2,"unexpected response.\n");
	      return 0;
	    }
	    if (max<buf+len) {
	      cur+=slen+tmp2;
	      goto nextmessage;
	    } else {
	      len=0;
	    }
	  } else {
	    /* copy partial message */
copypartialandcontinue:
	    byte_copy(buf,len-cur,buf+cur);
	    len-=cur;
	  }
	}

#if 0
	{
	  int fd=open("/tmp/searchresultentry",O_WRONLY|O_CREAT,0600);
	  write(fd,buf+tmp2,max-buf+tmp2);
	  close(fd);
	}
#endif
      }
    } else {
      buffer_putsflush(buffer_2,"ldapbind failed\n");
      return 2;
    }
    if (bench!=2)
      close(sock);
  }
  if (bench) write(1,"\n",1);
  return 0;
}
