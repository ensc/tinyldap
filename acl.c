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
#include <mmap.h>
#include <case.h>
#include <ldap.h>

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
  char* filterstring;
  struct Filter* f;
  struct assertion* sameas;
};

struct acl {
  struct assertion login,target;
  const char* attrib;
  uint32 anum;
  unsigned short may,maynot;
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
	if (c=='\n') { ++lines; break; }
      }
    } else return 1;
  }
  return 1;
}

int parseacldn(buffer* in,struct assertion* a) {
  int r,l;
  /* possible forms:
	*	-> "dn", Any
        dn:*foo -> "dn", "*foo" */
  byte_zero(a,sizeof(*a));
  a->sameas=0;
  if ((r=skipws(in))!=1) return r;
  stralloc_zero(&x);
  l=0;
  for (;;) {
    char tmp;
    r=buffer_getc(in,&tmp);
    if (r!=1) return 0;
    if (!stralloc_append(&x,&tmp)) return 0;
    if (tmp=='(') ++l;
    if (tmp==')') {
      --l;
      if (l==0) break;
    }
    if (stralloc_equals(&x,"*")) {
      a->filterstring=Any;
      return 1;
    }
    if (stralloc_equals(&x,"self")) {
      a->filterstring=Self;
      return 1;
    }
  }
  if (x.len+1<x.len) return 0;	/* catch integer overflow */
  a->filterstring=malloc(x.len+1);
  byte_copy(a->filterstring,x.len,x.s);
  a->filterstring[x.len]=0;

  if (scan_ldapsearchfilterstring(a->filterstring,&a->f) != x.len) {
    free_ldapsearchfilter(a->f);
    return 0;
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

  if (in->p < in->n && buffer_feed(in)<1) return 0;
  {
    char c=*buffer_peek(in);
    if (c=='+' || c=='-') {
      a->attrib=Any;
      return 1;
    }
  }

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
  unsigned short* s;
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
    if ((r=buffer_getc(in,&c))!=1 && c!="acl"[i]) {
      if (r==0 && i==0) return 0;
      parseerror();
    }
  if ((r=parseacldn(in,&a->login))!=1) return r;
  if ((r=parseacldn(in,&a->target))!=1) return r;
  if ((r=parseaclattrib(in,a))!=1) return r;
  if ((r=parseaclpermissions(in,a))!=1) return r;
  a->next=0;
  return 1;
}

static void fold(struct assertion* a,struct assertion* b) {
  if (a->sameas || b->sameas) return;
  if (!strcmp(a->filterstring,b->filterstring))
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

static struct acl* root;

int readacls(const char* filename) {
  buffer b;
  struct acl **next, a;
  int r;
  root=0; next=&root;
  if (buffer_mmapread(&b,filename)==-1) return -1;
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

#if 0

/* given a DN a (logged in as DN b), we need to quickly find out what
 * kind of permissions we have for an attribute c.  To make this extra
 * quick, I'm only comparing DNs if the rule
 *   a) grants or denies the permission I'm interested in (bit test)
 *   b) actually says something about the attribute I'm interested in.
 * To make b) cheap, I'll not actually compare attribute strings, but
 * I'll compare the offset of the attribute name in the mmapped file.
 * The * attribute is represented as 0.  An attribute that is not found
 * in the mmapped file is represented as -1. */

static uint32 acl_map(char* map,char* x,const char* s,unsigned int attribute_count) {
  unsigned int i;
  for (i=0; i<attribute_count; ++i) {
    uint32 j=uint32_read(x+i*4);
    if (case_equals(s,map+j))
      return j;
  }
  return -1;
}

void acl_offsets(char* map,unsigned long maplen) {
  uint32 attribute_count=uint32_read(map+4);
  uint32 size_of_string_table=uint32_read(map+4*4);
  uint32 dn_ofs,oc_ofs;
  char* x=map+5*4+size_of_string_table;
  unsigned int i;
  struct acl* a;

  dn_ofs=oc_ofs=0;
  for (i=0; i<attribute_count; ++i) {
    uint32 j=uint32_read(x+i*4);
    if (j>maplen-2) { carp("invalid offset in attribute table"); return; }	/* can't happen */
    if (case_equals(map+j,"dn"))
      dn_ofs=j;
    else if (case_equals(map+j,"objectClass"))
      oc_ofs=j;
  }

  for (a=root; a; a=a->next) {
    a->anum=(uint32)-1;
    if (a->attrib==Any)
      a->anum=0;
    else
      a->anum=acl_map(map,maplen,x,a->attrib,attribute_count);

    if (a->login.attr==Dn) a->login.where=dn_ofs;
    else if (case_equals(a->login.attr,"objectClass")) a->login.where=oc_ofs;
    else a->login.where=acl_map(map,x,a->login.attr,attribute_count);

    if (a->target.attr==Dn) a->target.where=dn_ofs;
    else if (case_equals(a->target.attr,"objectClass")) a->target.where=oc_ofs;
    else a->target.where=acl_map(map,x,a->target.attr,attribute_count);

#if 0
    if (a->anum==-1)
      printf("no offset found for %s\n",a->attrib);
    if (a->login.where==-1)
      printf("no offset found for %s\n",a->login.attr);
    if (a->target.where==-1)
      printf("no offset found for %s\n",a->target.attr);
#endif
  }
}

extern uint32 dn_ofs,objectClass_ofs;

int acl_allowed(char* map,unsigned long maplen,const char* logindn,const char* targetdn,uint32 attr,unsigned short wanted) {
  struct acl* a;
  struct assertion* l;
  for (a=root; a; a=a->next) {
    if (((a->may|a->maynot)&wanted) &&	/* acl applies to action we want to do */
        (!a->anum || a->anum==attr)) {	/* acl applies to this attribute */

      l=&a->login; if (l->sameas) l=l->sameas;

      /* first, see if logindn matches */
      if (logindn==0) {
	/* special case: anonymous bind.
	 * Do not match if login assertion is not "Any" */
	if (l->attr != Any) continue;
      } else if (logindn>=map && logindn<=map+maplen) {
	uint32 n=uint32_read(logindn);
	uint32 v=0;
	if (l->attr != Any) {
	  v=ldap_find_attr_value(logindn,l->where);
	  if (v==0) continue;	/* attribute not there, no match */
	  if (l->what != Any) {
	    if (l->what[0]=='*') {
	      /* suffix match */
	    } else if (l->what[strlen(l->what)-1]=='*') {
	      /* prefix match */
	    } else {
	      /* direct match */
	      /* TODO XXX FIXME */
	    }
	  }
	}
      } else
	die(1,"unhandled case: logindn outside map");
    }

#if 0
struct assertion {
  const char* attr;
  uint32 where;
  const char* what;
  struct assertion* sameas;
};
#endif

  }
}

#endif

#ifdef MAIN
int main() {
  unsigned long filelen;
  char* map=mmap_read("data",&filelen);

  if (readacls("acls")==-1) die(1,"readacls failed");
//  acl_offsets(map,filelen);
  return 0;
}
#endif
