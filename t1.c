#include <libowfat/buffer.h>
#include <libowfat/scan.h>
#include <libowfat/open.h>
#include <unistd.h>
#include <stdlib.h>
#include "strduptab.h"
#include "strstorage.h"
#include <libowfat/str.h>

/* how many attributes do we allow per record? */
#define ATTRIBS 8

struct attribute {
  const char* name,* value;
};

struct ldaprec {
  const char* dn,* mail,* sn,* cn;	/* most often encountered records */
  int n;	/* number of attributes */
  struct attribute a[ATTRIBS];
  struct ldaprec* next;
};

static struct stringduptable tags;
static struct stringduptable classes;

const char* dn,* mail,* sn,* cn,* objectClass;

int parserec(buffer* b, struct ldaprec** l) {
  char buf[8192];
  int n,i,eof=0,ofs=0;
  if (!(*l=malloc(sizeof(struct ldaprec)))) return 2;
  do {
    const char* tmp,* val;
    n=ofs+buffer_get_token(b,buf+ofs,8192-ofs,":",1);
    i=scan_whitenskip(buf,n);
    buf[n]=0;
    if (!(tmp=strduptab_add(&tags,buf+i))) {
nomem:
      buffer_putsflush(buffer_2,"out of memory!\n");
      return 1;
    }
#if 0
    buffer_puts(buffer_1,"found tag ");
    buffer_put(buffer_1,buf+i,n-i);
    buffer_putsflush(buffer_1,".\n");
#endif
    n=buffer_get_token(b,buf,8192,"\n",1);
    if (n==0) break;
    i=scan_whitenskip(buf,n);
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
#if 1
	struct ldaprec* m=malloc(sizeof(struct ldaprec));
	if (!m) return 2;
	(*l)->next=m;
	m->n=0; m->dn=m->mail=m->sn=m->cn=0; m->next=0;
	ofs=0;
	l=&((*l)->next);
#else
	struct ldaprec* m=malloc(sizeof(struct ldaprec));
	if (!m) return 2;
	m->next=*l;
	*l=m;
	m->n=0; m->dn=m->mail=m->sn=m->cn=0;
	ofs=0;
#endif
      } else {
	ofs=1;
	buf[0]=c;
      }
    }
    buf[n]=0;
    if (tmp==objectClass) {
      if (!(val=strduptab_add(&classes,buf+i))) goto nomem;
    } else
      if (!(val=strstorage_add(buf+i,n-i+1))) goto nomem;
    if (tmp==dn) (*l)->dn=val; else
    if (tmp==mail) (*l)->mail=val; else
    if (tmp==sn) (*l)->sn=val; else
    if (tmp==cn) (*l)->cn=val; else {
      if ((*l)->n<ATTRIBS) {
	(*l)->a[(*l)->n].name=tmp;
	(*l)->a[(*l)->n].value=val;
	++(*l)->n;
      }
    }
#if 0
    buffer_puts(buffer_1,"found value \"");
    buffer_put(buffer_1,buf+i,n-i);
    buffer_putsflush(buffer_1,"\".\n");
#endif
//    write(2,".",1);
  } while (!eof);
  if (!(*l)->dn) {
    struct ldaprec* m=(*l)->next;
    free((*l));
    (*l)=m;
  }
  return 0;
}

struct ldaprec *first=0;

int parse_ldif(const char* filename) {
  char buf[4096];
  int fd=open_read(filename);
  buffer in;
  if (fd<0) return 1;
  buffer_init(&in,(void*)read,fd,buf,sizeof buf);
  dn=strduptab_add(&tags,"dn");
  mail=strduptab_add(&tags,"mail");
  sn=strduptab_add(&tags,"sn");
  cn=strduptab_add(&tags,"cn");
  objectClass=strduptab_add(&tags,"objectClass");
  parserec(&in,&first);
  close(fd);
  return 0;
}

#ifndef INCLUDE
int main() {
  parse_ldif("exp.ldif");
//  read(0,buf,1);
#if 0
  /* dump structure */
  while (first) {
    printf("dn= %s\n",first->dn);
    first=first->next;
  }
#endif
  return 0;
}
#endif
