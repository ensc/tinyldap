/*
  tinyldap acl syntax:

    acl login-in-as-dn target-dn attrib

  e.g.

    # root@fefe.de can do everything
    acl dn:cn=root,o=fefe,c=de * +rwdR;
    # noone can read userPassword
    acl * * userPassword -r;
    # but everyone can authenticate using it
    acl * self +a;
    # admins at fefe.de can write in their tree
    acl dn:*ou=admin,o=fefe,c=de dn:*,o=fefe,c=de +rwdR;
 */

#include <buffer.h>
#include <stralloc.h>
#include <str.h>
#include <uint32.h>
#include <string.h>
#include <errmsg.h>
#include <fmt.h>
#include <byte.h>

const char Any[]="*";
const char Self[]="self";
const char Dn[]="dn";

enum {
  acl_read = 1,
  acl_write = 2,
  acl_auth = 4,
  acl_delete = 8,
  acl_rendn = 16,
};

struct assertion {
  const char* attr;
  uint32 where;
  const char* what;
  struct assertion* sameas;
};

struct acl {
  struct assertion login,target;
  const char* attrib;
  short may,maynot;
  struct acl* next;
};

static unsigned long lines;
static stralloc x;

void parseerror() {
  char buf[FMT_ULONG];
  buf[fmt_ulong(buf,lines)]=0;
  die(1,"parse error in line ",buf);
}

int skipws(buffer* in) {
  char c;
  for (;;) {
    if (in->p < in->n && buffer_feed(in)<1) return 0;
    c=*buffer_peek(in);
    if (c=='\n') ++lines;
    if (c==' ' || c=='\n' || c=='\t') {
      buffer_getc(in,&c);
      continue;
    } else if (c=='#') {
      for (;;) {
	int r=buffer_getc(in,&c);
	if (r!=1) return r;
	if (c=='\n') break;
      }
    } else return 1;
  }
  return 1;
}

int parseacldn(buffer* in,struct assertion* a) {
  int r;
  /* possible forms:
	*	-> "dn", Any
        dn:*foo -> "dn", "*foo" */
  a->sameas=0;
  if ((r=skipws(in))!=1) return r;
  stralloc_zero(&x);
  do {
    r=buffer_get_token_sa(in,&x," \t",2);
    if (r!=1) return r;
  } while (!x.len || x.s[x.len-1]!='\\');
  stralloc_chop(&x);
  if (!stralloc_0(&x)) return -1;
  r=byte_chr(x.s,x.len,':');
  if (x.s[r]==':') {
    x.s[r]=0;
    if (str_equal(x.s,"dn")) {
      a->attr=Dn;
      a->what=strdup(x.s+r+1);
      if (!a->what) return -1;
    } else {
      a->attr=malloc(x.len);
      if (!a->attr) return -1;
      byte_copy((char*)a->attr,x.len,x.s);
      a->what=a->attr+r+1;
    }
  } else {
    a->attr=Dn;
    if (str_equal(x.s,"*"))
      a->what=Any;
    else if (str_equal(x.s,"self"))
      a->what=Self;
    else {
      a->what=strdup(x.s);
      if (!a->what) return -1;
    }
  }
  return 1;
}

int parseaclattrib(buffer* in,struct acl* a) {
  /* possible forms:
       cn,sn
       mail
       *
   */
  int r;
  a->attrib=0;
  if ((r=skipws(in))!=1) return r;
  r=buffer_get_new_token_sa(in,&x," \t",2);
  if (r!=1) return r;
  stralloc_chop(&x);
  if (!stralloc_0(&x)) return -1;
  if (str_equal(x.s,"*")) {
    a->attrib=Any;
    return 1;
  }
  return ((a->attrib=strdup(x.s))?1:-1);
}

int parseaclpermissions(buffer* in,struct acl* a) {
  char c;
  int r;
  short* s;
  a->may=a->maynot=0; s=&a->may;
  for (;;) {
    r=buffer_getc(in,&c);
    if (r<1) return r;
    switch (c) {
    case '+': s=&a->may; break;
    case '-': s=&a->maynot; break;
    case 'r': *s|=acl_read; break;
    case 'w': *s|=acl_write; break;
    case 'a': *s|=acl_auth; break;
    case 'd': *s|=acl_delete; break;
    case 'R': *s|=acl_rendn; break;
    case ' ': case '\t': case '\n': break;
    case ';': return 1;
    default: parseerror();
    }
  }
}

static int parseacl(buffer* in,struct acl* a) {
  int i,r;
  char c;
  if ((r=skipws(in))!=1) return r;
  for (i=0; i<3; ++i)
    if (buffer_getc(in,&c)!=1 && c!="acl"[i]) parseerror();
  if ((r=parseacldn(in,&a->login))!=1) return r;
  if ((r=parseacldn(in,&a->target))!=1) return r;
  if ((r=parseaclattrib(in,a))!=1) return r;
  if ((r=parseaclpermissions(in,a))!=1) return r;
  a->next=0;
  return 1;
}

static void fold(struct assertion* a,struct assertion* b) {
  if (a->sameas || b->sameas) return;
  if (a->attr==b->attr || str_equal(a->attr,b->attr))
    if (a->what==b->what || str_equal(a->what,b->what))
      b->sameas=a;
}

static void optimize(struct acl* a) {
  struct acl* b;
  for (; a; a=a->next)
    for (b=a; b; b=b->next) {
      fold(&a->login,&b->login);
      fold(&a->target,&b->target);
      fold(&a->login,&a->target);
      fold(&a->login,&b->target);
      fold(&b->login,&a->target);
      fold(&b->login,&b->target);
    }
}

int main() {
  buffer b;
  struct acl* root,**next, a;
  int r;
  root=0; next=&root;

  if (buffer_mmapread(&b,"acls")==-1) diesys(1,"buffer_mmapread");

  while ((r=parseacl(&b,&a))!=-1) {
    *next=malloc(sizeof(struct acl));
    if (!*next) diesys(1,"malloc");
    **next=a;
    next=&(*next)->next;
    if (r==0) break;
  }
  if (r==-1) parseerror();

  buffer_close(&b);
  optimize(root);
  return 0;
}
