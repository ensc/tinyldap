#include <buffer.h>
#include <scan.h>
#include <open.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include "mduptab.h"
#include "mstorage.h"
#include "str.h"
#include "ldif.h"

mduptab_t attributes,classes;
mstorage_t stringtable;

long dn, objectClass;

unsigned long ldifrecords;

static void addattribute(struct ldaprec** l,long name,long val) {
  if (name==dn) (*l)->dn=val; else
    if ((*l)->n<ATTRIBS) {
      (*l)->a[(*l)->n].name=name;
      (*l)->a[(*l)->n].value=val;
      ++(*l)->n;
    } else {
      buffer_putsflush(buffer_2,"LDIF parse error: too many attributes!\n");
      exit(1);
    }
}

/* "ou=fnord; O=fefe; c=de" -> "ou=fnord,o=fefe,c=de" */
/* returns the length of the new string */
static int normalize_dn(char* dest,const char* src,int len) {
  int makelower=1;
  char* orig=dest;
  while (len) {
    if (*src==';' || *src==',') {
      *dest=',';
      while (len>1 && src[1]==' ') { ++src; --len; }
      makelower=1;
    } else {
      if (makelower)
	*dest=tolower(*src);
      else
	*dest=*src;
      if (*dest=='=') makelower=0;
    }
    ++dest;
    ++src;
    --len;
  }
  return dest-orig;
}

static int parserec(buffer* b, struct ldaprec** l) {
  char buf[8192];
  int n,i,eof=0,ofs=0;
  if (!(*l=malloc(sizeof(struct ldaprec)))) return 2;
  (*l)->dn=-1;
  (*l)->next=0; (*l)->n=0;
  ldifrecords=0;
  do {
    long tmp, val;
    n=ofs+buffer_get_token(b,buf+ofs,8192-ofs,":",1);
    i=scan_whitenskip(buf,n);
    buf[n]=0;
    if ((tmp=mduptab_add(&attributes,buf+i))<0) {
nomem:
      buffer_putsflush(buffer_2,"out of memory!\n");
      return 1;
    }
    n=buffer_get_token(b,buf,8192,"\n",1);
    if (n==0) break;
    i=scan_whitenskip(buf,n);
    buf[n]=0;
lookagain:
    {
      char c;
      switch (buffer_getc(b,&c)) {
      case 0: eof=1; break;
      case -1: buffer_putsflush(buffer_2,"read error!\n"); return 1;
      }
      if (c==' ') {	/* continuation */
//	puts("continuation!");
	n+=buffer_get_token(b,buf+n,8192-n,"\n",1);
	goto lookagain;
      } else if (c=='\n') {
	struct ldaprec* m=malloc(sizeof(struct ldaprec));
	if (!m) return 2;

	if (tmp==objectClass) {
	  if ((val=mduptab_add(&classes,buf+i))<0) goto nomem;
	} else if (tmp==dn) {
	  char* newdn=alloca(n-i+1);
	  if ((val=mstorage_add(&stringtable,newdn,normalize_dn(newdn,buf+i,n-i+1)))<0) goto nomem;
	} else
	  if ((val=mstorage_add(&stringtable,buf+i,n-i+1))<0) goto nomem;
	addattribute(l,tmp,val);

	(*l)->next=m;
	m->n=0; m->dn=-1; m->next=0;
	ofs=0;
//	dumprec(*l);
	l=&((*l)->next);
	++ldifrecords;
	continue;
      } else {
	ofs=1;
	buf[0]=c;
      }
    }
//    buf[n]=0;
#if 1
    if (tmp==objectClass) {
      if ((val=mduptab_add(&classes,buf+i))<0) goto nomem;
    } else if (tmp==dn) {
      char* newdn=alloca(n-i+1);
      if ((val=mstorage_add(&stringtable,newdn,normalize_dn(newdn,buf+i,n-i+1)))<0) goto nomem;
    } else
      if ((val=mstorage_add(&stringtable,buf+i,n-i+1))<0) goto nomem;
    addattribute(l,tmp,val);
#endif
  } while (!eof);
  if ((*l)->dn<0) {
    struct ldaprec* m=(*l)->next;
    free((*l));
    (*l)=m;
  }
  return 0;
}

struct ldaprec *first=0;

int ldif_parse(const char* filename) {
  char buf[4096];
  int fd=open_read(filename);
  buffer in=BUFFER_INIT(read,fd,buf,sizeof buf);
  if (fd<0) return 1;
  dn=mduptab_add(&attributes,"dn");
  objectClass=mduptab_add(&attributes,"objectClass");
  {
    int res=parserec(&in,&first);
    close(fd);
    return res;
  }
}

