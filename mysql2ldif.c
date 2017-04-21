#include <libowfat/stralloc.h>
#include <libowfat/buffer.h>
#include <libowfat/array.h>
#include <libowfat/fmt.h>
#include <libowfat/errmsg.h>
#include <libowfat/str.h>
#include <ctype.h>

#define _BSD_SOURCE
#include <string.h>

static unsigned long line;

static void parseerror(char* message) {
  char buf[FMT_ULONG];
  buf[fmt_ulong(buf,line)]=0;
  die(1,"parse error in line ",buf,": ",message,"!\n");
}

static void nomem() {
  die(1,"out of memory");
}

int main() {
  static stralloc sa;
  static array fn;	/* field names */
  static char* table;
  int mode=0;
  int pkey=-1;

  while (buffer_getnewline_sa(buffer_0,&sa)==1) {
    ++line;
    if (!stralloc_0(&sa)) nomem();
    if (stralloc_starts(&sa,"CREATE TABLE ")) {
      char* tmp=sa.s+14;
      unsigned int i;
      mode=1;
      for (i=0; i<sa.len-14 && tmp[i]!=' '; ++i);
      if (tmp+i+1>sa.s+sa.len)
	parseerror("expected ' ' after table name");
      tmp[i]=0;
      free(table);
      table=strdup(tmp);
      if (!table) nomem();
      array_trunc(&fn);
      continue;
    } else if (mode==1 && stralloc_starts(&sa,") TYPE=")) {
      mode=2;
      continue;
    }
    if (mode==1) {
      /* parsing CREATE TABLE */
      if (!stralloc_starts(&sa,"  ")) parseerror("expected two leading spaces");
      if (stralloc_starts(&sa,"  PRIMARY KEY ")) {
	char* tmp=sa.s+14;
	int i;
	while (*tmp && *tmp!='(') ++tmp;
	if (*tmp != '(') parseerror("expected '('");
	++tmp;
	for (i=0; tmp[i] && tmp[i]!=')'; ++i) ;
	if (tmp[i]!=')') parseerror("expected ')'");
	tmp[i]=0; pkey=-1;
	for (i=0; i<array_length(&fn,sizeof(char*)); ++i) {
	  char** x=array_get(&fn,sizeof(char*),i);
	  if (!x) die(1,"internal error");
//	  buffer_putmflush(buffer_1,"comparing ",*x," with ",tmp,"...\n");
	  if (!strcmp(*x,tmp)) {
	    pkey=i;
	    break;
	  }
	}
	if (pkey==-1) die(1,"primary key not found?!\n");
      } else if (stralloc_starts(&sa,"  KEY "))
	continue;
      else {
	char* tmp=sa.s+2;
	while (*tmp && *tmp!=' ') ++tmp;
	if (*tmp==' ') {
	  *tmp=0;
//	  buffer_putmflush(buffer_1,"adding field ",sa.s+2,"...\n");
	  tmp=strdup(sa.s+2);
	  if (!tmp) nomem();
	  array_catb(&fn,(void*)&tmp,sizeof(tmp));
	  if (array_failed(&fn)) nomem();
	} else parseerror("expected ' ' after field name");
      }
    } else if (mode==2) {
      if (stralloc_starts(&sa,"INSERT INTO ")) {
	static char** c;
	char** k=array_start(&fn);
	int max=array_length(&fn,sizeof(char*));
	int i,n;
	char* tmp;
	if (!c) c=alloca(array_bytes(&fn));
	for (tmp=sa.s; *tmp && *tmp!='('; ++tmp) ;
	if (*tmp != '(') parseerror("expected '(' in INSERT statement");
	++tmp;
	for (i=n=0; i<max; ++i) {
	  if (*tmp=='\'') {
	    char* out;
	    ++tmp;
	    c[n]=tmp;
	    out=tmp;
	    while (*tmp) {
	      if (*tmp=='\\') {
		if (tmp[1]==0) parseerror("\\ at line ending");
		*out=tmp[1];
		++tmp;
	      } else
		if (*tmp=='\'') break;
	      *out=*tmp;
	      ++tmp;
	      ++out;
	    }
	    if (*tmp!='\'') parseerror("expected closing '");
	    *out=0;
	    ++tmp;
	    if (*tmp!=',' && *tmp!=')') parseerror("expected ',' or ')'");
	    ++tmp;
	  } else if (str_start(tmp,"NULL")) {
	    c[n]=0;
	    tmp+=4;
	    if (*tmp!=',' && *tmp!=')') parseerror("expected ',' or ')'");
	    ++tmp;
	  } else if (isdigit(*tmp)) {
	    c[n]=tmp;
	    while (isdigit(*tmp)) ++tmp;
	    if (*tmp!=',' && *tmp!=')') parseerror("expected ',' or ')'");
	    *tmp=0;
	    ++tmp;
	  } else
	    parseerror("expected NULL, 'string' or 1234");
	  ++n;
	}
	if (pkey==-1 || !c[pkey]) {
	  parseerror("primary key empty");
	}
	buffer_putm(buffer_1,"dn: ",c[pkey],"\nobjectClass: mysql2ldif\n");
	for (i=0; i<max; ++i) {
	  if (c[i])
	    buffer_putm(buffer_1,k[i],": ",c[i],"\n");
	}
	buffer_puts(buffer_1,"\n");
      }
    }
  }
  buffer_flush(buffer_1);
  return 0;
}
