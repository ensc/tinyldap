#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libowfat/str.h>
#include <libowfat/case.h>
#include <libowfat/byte.h>
#include <libowfat/buffer.h>
#include "ldap.h"
#include "mduptab.h"
#include "ldif.h"
#include <libowfat/open.h>
#include <libowfat/mmap.h>
#include <libowfat/uint32.h>
#include "auth.h"
#include "bstr.h"
#ifdef STANDALONE
#include <libowfat/socket.h>
#include <libowfat/ip6.h>
#include <libowfat/scan.h>
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/wait.h>
#else
#include <wait.h>
#endif
#endif
#include <libowfat/case.h>
#include <signal.h>
#include <libowfat/uint16.h>
#include "acl.h"
#include <ctype.h>
#include <assert.h>
#include <fcntl.h>
#include <libowfat/errmsg.h>
#include <libowfat/textcode.h>
#include <libowfat/fmt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <libowfat/rangecheck.h>
#include <libowfat/safemult.h>

#if defined(STANDALONE) || defined(DEBUG)
#include <sys/types.h>
#include <pwd.h>
#endif

#ifdef DEBUG
#include <sys/poll.h>
#define verbose 1
#define debug 1
#else
#define verbose 0
#define debug 0
#endif

const char journalfilename[]="journal";

int oneshot;	// oneshot can be set via $ONESHOT env var
int bindreqs;	// if oneshot mode is 1, only allow one BindRequest
		// TODO: oneshot == 2: allow one anon BindRequest and then one non-anon BindRequest

#define HUGE_SIZE_FOR_SANITY_CHECKS 1024*1024

/* basic operation: the whole data file is mmapped read-only at the beginning and stays there. */
const char* map;	/* where the file is mapped */
size_t filelen;	/* how many bytes are mapped (the whole file) */
uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;
		/* these are the first values from the file, see the file "FORMAT"
		 * basic counts and offsets needed to calculate the positions of
		 * the data structures in the file. */

static uint32* getrecptr(size_t recno) {
  if (recno>=record_count) return 0;
  uint32_t thisrec = uint32_read(map+indices_offset+4*recno);
  return (uint32*)(map+thisrec);
}


/* We do queries with indexes by evaluating all the filters (subexpressions) that can be
 * answered with an index, and then getting a bit vector, one bit for each record. */

/* how many longs are needed to have one bit for each record? */
uint32 record_set_length;

/* some pre-looked-up attribute offsets to speed up ldap_match_mapped */
uint32 dn_ofs,objectClass_ofs,userPassword_ofs,any_ofs;




/* journal hash structures */
struct attribute2 {
  unsigned char* a,* v;
};

/* we have chained hashing (that's what next is for), but we also have a linear list of
 * all the entries in the journal (that's what linear is for), so we can traverse the
 * entries in the same order they were put in the journal */
struct hashnode {
  struct hashnode* next,* linear;
  unsigned long hashval;
  unsigned char* dn;
  size_t n;
  int overwrite;
  struct attribute2 a[1];
};




/* to avoid string compares, we don't work with char* but with uint32 (offsets within
 * the mmapped file) whenever it's about values that will be mentioned in the file, such
 * as attribute names.  So, for each filter we get sent, we look up the attributes in the
 * file, so we have the offsets to save the strcmp later.
 * In the same step, we also get the attribute flags.  tinyldap does not have LDAP
 * schemas, so it does not know which attributes are case sensitive and which aren't.  So,
 * this is saved in a flag, which is currently set by addindex when a case insensitive
 * index is created. */

/* This routine is called when we got a Filter and now want to look up the offsets for
 * each attribute mentioned in it */

/* recursively fill in attrofs and attrflag */
static void fixup(struct Filter* f) {
  if (!f) return;
  switch (f->type) {
  case EQUAL:
  case SUBSTRING:
  case GREATEQUAL:
  case LESSEQUAL:
  case PRESENT:
  case APPROX:
    {
      const char* x=map+5*4+size_of_string_table;
      size_t i;
      f->attrofs=f->attrflag=0;
      for (i=0; i<attribute_count; ++i) {
	uint32 j=uint32_read(x);
	if (!matchcasestring(&f->ava.desc,map+j)) {
	  f->attrofs=j;
	  uint32_unpack(x+attribute_count*4,&f->attrflag);
	  break;
	}
	x+=4;
      }
      if (!f->attrofs) {
	buffer_puts(buffer_2,"cannot find attribute \"");
	buffer_put(buffer_2,f->ava.desc.s,f->ava.desc.l);
	buffer_putsflush(buffer_2,"\"!\n");
      }
    }
    /* fall through */
  case AND:
  case OR:
  case NOT:
    if (f->x) fixup(f->x);
  default:
    break;
  }
  if (f->next) fixup(f->next);
}

static void fixupadl(struct AttributeDescriptionList* a) {
  while (a) {
    const char* x=map+5*4+size_of_string_table;
    size_t i;
    a->attrofs=0;
    for (i=0; i<attribute_count; ++i) {
      uint32 j=uint32_read(x);
      if (!matchcasestring(&a->a,map+j)) {
	a->attrofs=j;
	break;
      }
      x+=4;
    }
    if (!a->attrofs) {
      buffer_puts(buffer_2,"cannot find attribute \"");
      buffer_put(buffer_2,a->a.s,a->a.l);
      buffer_putsflush(buffer_2,"\"!\n");
    }
    a=a->next;
  }
}








/*
            _                                    _
  __ _  ___| |  ___ _   _ _ __  _ __   ___  _ __| |_
 / _` |/ __| | / __| | | | '_ \| '_ \ / _ \| '__| __|
| (_| | (__| | \__ \ |_| | |_) | |_) | (_) | |  | |_
 \__,_|\___|_| |___/\__,_| .__/| .__/ \___/|_|   \__|
                         |_|   |_|
*/

uint32 filters,acls;		/* number of filters and acls in the ACL section of the data file */
uint32 filtertab,acltab;	/* offsets of the filter and acl table in the data file */
char* acl_ec_subjects;		/* if the n'th byte here is nonzero, then the current subject
				   (the dn the user is logged in as) matches the n'th filter, i.e.
				   the ACLs with this subject need to be applied. */
struct Filter** Filters;
char Self[]="self";
char Any[]="*";
uint32 authenticated_as;
char* authenticated_as_str;

struct acl {
  uint32 subject,object;	/* index of filter for subject,object */
  uint16 may,maynot;
  uint32 attrs;
  uint32 Attrs[1];
};

struct acl** Acls;

static void load_acls() {
  struct acl** oldAcls=Acls;
  size_t oldacls=acls;
  uint32 ofs;
  uint32 acl_ofs;
  acl_ofs=0;
  for (ofs=indices_offset+record_count*4; ofs<filelen;) {
    uint32 index_type,next;
    uint32_unpack(map+ofs,&index_type);
    uint32_unpack(map+ofs+4,&next);
    if (index_type==2) { acl_ofs=ofs; break; }
    if (next<ofs || next>filelen) {
kaputt:
      buffer_putsflush(buffer_1,"broken data file!\n");
      exit(1);
    }
    ofs=next;
  }
  filters=acls=0; acl_ec_subjects=0;
  if (acl_ofs) {
    uint32 i;
    ofs=acl_ofs+8;
    filters=uint32_read(map+ofs);
    acl_ec_subjects=malloc(2*filters);
    filtertab=ofs+4;
    ofs=filtertab+filters*4;
    if (ofs<filtertab) goto kaputt;
    Filters=malloc(sizeof(Filters[0])*filters);
    if (!Filters) goto kaputt;
    for (i=0; i<filters; ++i) {
      struct Filter* f;
      ofs=uint32_read(map+filtertab+i*4);
      if (ofs<filtertab || ofs>filelen) goto kaputt;
      if (byte_equal(map+ofs,4,"self"))
	f=(struct Filter*)Self;
      else if (byte_equal(map+ofs,2,"*"))
	f=(struct Filter*)Any;
      else if (scan_ldapsearchfilter(map+ofs,map+filelen,&f)!=0) {
	fixup(f);
	if (debug) {
	  size_t l=fmt_ldapsearchfilterstring(0,f);
	  char* buf=malloc(l+23);
	  if (!buf) goto kaputt;
	  buf[fmt_ldapsearchfilterstring(buf,f)]=0;
	  free(buf);
	}
      } else goto kaputt;
      Filters[i]=f;
    }
    ofs=uint32_read(map+filtertab+filters*4);
    if (ofs<filtertab || ofs>filelen-4) goto kaputt;
    acls=uint32_read(map+ofs);
    acltab=ofs+4;
    Acls=malloc(sizeof(Acls[0])*acls);
    if (!Acls) goto kaputt;
    for (i=0; i<acls; ++i) {
      uint32 j;
      uint32 tmp,cnt;
      ofs=uint32_read(map+acltab+i*4);
      if (ofs>filelen-16) goto kaputt;
      cnt=0;
      for (tmp=ofs+12; tmp<filelen; tmp+=4) {
	uint32 j=uint32_read(map+tmp);
	if (j>tmp) goto kaputt;
	if (!j) break;
	++cnt;
      }
      Acls[i]=malloc(sizeof(struct acl)+cnt*sizeof(uint32));
      if (!Acls[i]) goto kaputt;
      Acls[i]->subject=uint32_read(map+ofs);
      Acls[i]->object=uint32_read(map+ofs+4);
      Acls[i]->may=uint16_read(map+ofs+8);
      Acls[i]->maynot=uint16_read(map+ofs+10);
      Acls[i]->attrs=cnt;

      tmp=ofs+12;
      for (j=0; j<cnt; ++j) {
	uint32 x;
	Acls[i]->Attrs[j]=x=uint32_read(map+tmp+4*j);
	if (any_ofs==0 && map[x]=='*' && map[x+1]==0) any_ofs=x;
      }
    }
  }
  if (acls) {
    uint32 i;
    for (i=0; i<filters; ++i)
      acl_ec_subjects[i]=(Filters[i]==(struct Filter*)Any);
  }
  if (oldAcls) {
    size_t i;
    for (i=0; i<oldacls; ++i)
      free(oldAcls[i]);
    free(oldAcls);
  }
}

/* End of ACL code */

static const char* datafilename;
static struct stat ss_data;
static struct stat ss_journal;

void map_datafile(const char* filename) {
  // we fundamentally trust the datafile
  // in our threat model the datafile has higher integrity than us
  // we worry about us corrupting the data, not the data corrupting us
  map=mmap_read(datafilename=filename,&filelen);
  stat(datafilename,&ss_data);
  if (!map) {
    buffer_putsflush(buffer_2,"could not open data!\n");
    exit(1);
  }
  if (filelen<4*4) {
    buffer_putsflush(buffer_2,"data file corrupt!\n");
    exit(1);
  }
  uint32_unpack(map,&magic);
  uint32_unpack(map+4,&attribute_count);
  uint32_unpack(map+2*4,&record_count);
  uint32_unpack(map+3*4,&indices_offset);
  uint32_unpack(map+4*4,&size_of_string_table);
  record_set_length=(record_count+sizeof(unsigned long)*8-1) / (sizeof(long)*8);
  
  {
    uint32_t v=5*4;
    uint32_t w;
    // some sanity checks in case the file is truncated
    // we implicitly trust the file, there are many other opportunities for it to be
    // corrupt that we don't check here
    if (add_of(v,v,size_of_string_table) ||
	!umult32(attribute_count,8,&w) || add_of(v,v,w) ||
	!umult32(record_count,4,&w) || add_of(v,v,w) ||
	v > indices_offset || indices_offset > filelen) {
      buffer_putsflush(buffer_2,"data file corrupt!\n");
      exit(1);
    }
  }

  /* look up "dn" and "objectClass" */
  {
    const char* x=map+5*4+size_of_string_table;
    size_t i;
    dn_ofs=objectClass_ofs=userPassword_ofs=any_ofs=0;
    for (i=0; i<attribute_count; ++i) {
      uint32 j;
      j=uint32_read(x);
      if (case_equals("dn",map+j))
	dn_ofs=j;
      else if (case_equals("objectClass",map+j))
	objectClass_ofs=j;
      else if (case_equals("userPassword",map+j))
	userPassword_ofs=j;
      x+=4;
    }
    if (!dn_ofs || !objectClass_ofs) {
      buffer_putsflush(buffer_2,"can't happen error: dn or objectClass not there?!\n");
      exit(0);
    }
  }
  load_acls();
}

/*
     _      _                                 _
  __| | ___| |__  _   _  __ _    ___ ___   __| | ___
 / _` |/ _ \ '_ \| | | |/ _` |  / __/ _ \ / _` |/ _ \
| (_| |  __/ |_) | |_| | (_| | | (_| (_) | (_| |  __/
 \__,_|\___|_.__/ \__,_|\__, |  \___\___/ \__,_|\___|
                        |___/
*/

#define BUFSIZE 8192
#define MAXBUFSIZE 1024*1024

#if (debug != 0)
/* debugging support functions, adapted from t2.c */
static void printava(struct AttributeValueAssertion* a,const char* rel) {
  buffer_puts(buffer_2,"(");
  buffer_put(buffer_2,a->desc.s,a->desc.l);
//  buffer_puts(buffer_2," ");
  buffer_puts(buffer_2,rel);
//  buffer_puts(buffer_2," ");
  buffer_put(buffer_2,a->value.s,a->value.l);
  buffer_puts(buffer_2,")");
}

static void printal(struct AttributeDescriptionList* a) {
  while (a) {
    buffer_put(buffer_2,a->a.s,a->a.l);
    a=a->next;
    if (a) buffer_puts(buffer_2,",");
  }
  if (a) buffer_puts(buffer_2,"\n");
}

static void printfilter(struct Filter* f) {
  switch (f->type) {
  case AND:
    buffer_puts(buffer_2,"(&");
mergesub:
    printfilter(f->x);
    buffer_puts(buffer_2,")\n");
    break;
  case OR:
    buffer_puts(buffer_2,"(|");
    goto mergesub;
    break;
  case NOT:
    buffer_puts(buffer_2,"(!");
    goto mergesub;
  case EQUAL:
    printava(&f->ava,"=");
    break;
  case SUBSTRING:
    {
      struct Substring* s=f->substrings;
      int first=1;
      buffer_put(buffer_2,f->ava.desc.s,f->ava.desc.l);
      buffer_puts(buffer_2," has ");
      while (s) {
	if (!first) buffer_puts(buffer_2," and ");
	first=0;
	switch(s->substrtype) {
	case prefix: buffer_puts(buffer_2,"prefix \""); break;
	case any: buffer_puts(buffer_2,"substr \""); break;
	case suffix: buffer_puts(buffer_2,"suffix \""); break;
	}
	buffer_put(buffer_2,s->s.s,s->s.l);
	buffer_puts(buffer_2,"\"");
	s=s->next;
      }
    }
    break;
  case GREATEQUAL:
    printava(&f->ava,">=");
    break;
  case LESSEQUAL:
    printava(&f->ava,"<=");
    break;
  case PRESENT:
    printava(&f->ava,"=*");
    break;
  case APPROX:
    printava(&f->ava,"\\approx");
    break;
  case EXTENSIBLE:
    buffer_puts(buffer_2,"[extensible]");
    break;
  }
  if (f->next) {
//    buffer_puts(buffer_2,",");
    printfilter(f->next);
  }
  buffer_flush(buffer_2);
}
#endif




/*
 _           _                           _
(_)_ __   __| | _____  __   ___ ___   __| | ___
| | '_ \ / _` |/ _ \ \/ /  / __/ _ \ / _` |/ _ \
| | | | | (_| |  __/>  <  | (_| (_) | (_| |  __/
|_|_| |_|\__,_|\___/_/\_\  \___\___/ \__,_|\___|
*/

/* find out whether this filter can be accelerated with the indices */
static int indexable(struct Filter* f) {
  struct Filter* y=f->x;
  if (!f) return 0;
  switch (f->type) {
  case AND:
    while (y) {
      if (indexable(y)) return 1;
      y=y->next;
    }
    return 0;
  case OR:
    while (y) {
      if (!indexable(y)) return 0;
      y=y->next;
    }
    /* fall through */
  case PRESENT:
    return 0;
#if 0
  /* doesn't make much sense to try to speed up negated queries */
  case NOT:
    return indexable(y);
#endif
  case SUBSTRING:
    if (f->substrings->substrtype!=prefix) return 0;
    /* fall through */
  case EQUAL:
  case LESSEQUAL:
  case GREATEQUAL:
    {
      uint32 ofs;
      for (ofs=indices_offset+record_count*4; ofs<filelen;) {
	uint32 index_type,next,indexed_attribute;
	index_type=uint32_read(map+ofs);
	next=uint32_read(map+ofs+4);
	indexed_attribute=uint32_read(map+ofs+8);
	if (index_type<=1 || (index_type==3 && f->type==EQUAL))
	  if (!matchstring(&f->ava.desc,map+indexed_attribute))
	    return 1;
	ofs=next;
      }
    }
    /* fall through */
  default:
    return 0;
  }
}

/* each record can have more than one attribute with the same name, i.e.  two email
 * addresses.  Thus, the index can't just be a sorted list of pointers the records
 * (because a record with two email addresses needs to be in the index twice, once for
 * each email address).  So our index is a sorted list of pointers to the attributes.
 * Thus, a look-up in the index does not yield the record but the attribute.  We need to
 * be able to find the record for a given attribute.  To do that, we exploit the fact that
 * the strings in the string table are in the same order as the records, so we can do a
 * binary search over the record table to find the record with the attribute.  This does
 * not work for objectClass, because the classes are stored in a different string table to
 * remove duplicates. */

/* Yes, this is an evil kludge to keep index size small.  However, it turned out that it
 * also dominated lookup time for a relatively minor index size reduction.  So index type
 * 1 was added (flag f to addindex), which does not need this.  The benefit is so big that
 * tinyldap will drop support for type 0 indices sooner or later.  Type 1 indexes are
 * twice as large, and save the record number besides each index entry. */

/* find record given a data pointer */
static long findrec(uint32 dat) {
  uint32* records=(uint32*)(map+indices_offset);
  uint32 bottom=0;
  uint32 top=record_count-1;

  while ((top>=bottom)) {
    uint32 mid=(top+bottom)/2;
    uint32 l;

    l=uint32_read(map+uint32_read((char*)(&records[mid]))+8);
    if (l<=dat) {
      if (mid>=record_count-1)
	l=uint32_read(map+uint32_read((char*)(&records[0]))+12);
      else
	l=uint32_read(map+uint32_read((char*)(&records[mid+1]))+8);
      if (l>dat) {
	return mid;	/* found! */
      }
      bottom=mid+1;
    } else
      if (mid)
	top=mid-1;
      else
	break;
  }
  buffer_putsflush(buffer_2,"findrec failed!\n");
  return -1;
}

#define RANGECHECK 1

struct bitfield {
  unsigned long* bits;
#ifdef RANGECHECK
  size_t n;
#endif
  size_t first,last;
};

/* basic bit-set support: set all bits to 0 */
static inline void emptyset(struct bitfield* b) {
  size_t i;
#ifdef RANGECHECK
  b->n=
#endif
    b->first=record_count;
  b->last=0;
  for (i=0; i<record_set_length; ++i) b->bits[i]=0;
}

/* basic bit-set support: set all bits to 1 */
static inline void fillset(struct bitfield* b) {
  size_t i;
  b->first=0;
#ifdef RANGECHECK
  b->n=
#endif
  b->last=record_count;
  for (i=0; i<record_set_length; ++i) b->bits[i]=(unsigned long)-1;
}

static inline void invertset(struct bitfield* b) {
  size_t i;
  b->first=0;
#ifdef RANGECHECK
  b->n=
#endif
  b->last=record_count;
  for (i=0; i<record_set_length; ++i) b->bits[i] = ~b->bits[i];
}

/* basic bit-set support: set one bit to 1 */
static inline void setbit(struct bitfield* b,size_t bit) {
#ifdef RANGECHECK
  if (bit<=b->n) {
#endif
    if (bit<b->first) b->first=bit;
    if (bit>b->last) b->last=bit;
    b->bits[bit/(8*sizeof(long))] |= (1<<(bit&(8*sizeof(long)-1)));
#ifdef RANGECHECK
  }
#endif
}

/* basic bit-set support: see if given bit is set */
static inline int isset(struct bitfield* b,size_t bit) {
#ifdef RANGECHECK
  if (bit>b->n) return 0;
#endif
  return b->bits[bit/(8*sizeof(long))] & (1<<(bit&(8*sizeof(long)-1)));
}

/* use index (sorted table of offsets to records) to do a binary search
 * for all records that match the value in s.  Set the corresponding
 * bits to 1 in bitfield. */
static void tagmatches(uint32* index,size_t elements,struct string* s,
		       struct bitfield* b,int (*match)(struct string* s,const char* c),
		       uint32 index_type,enum FilterType ft) {
  uint32 bottom=0;
  uint32 top=elements-1;
  uint32 mid,k,m;
  long rec;
  rec=0;
  emptyset(b);

  if (!elements) return;

  while ((top>=bottom)) {
    int l;

    mid=(top+bottom)/2;
    k=uint32_read((char*)(&index[mid]));
#ifdef DEBUG
    buffer_puts(buffer_2,"match[");
    buffer_putulong(buffer_2,bottom);
    buffer_puts(buffer_2,"..");
    buffer_putulong(buffer_2,top);
    buffer_puts(buffer_2,"]: ");
    buffer_put(buffer_2,s->s,s->l);
    buffer_puts(buffer_2," <-> ");
    buffer_puts(buffer_2,map+k);
    buffer_putsflush(buffer_2,": ");
#endif
    if ((l=match(s,map+k))==0) {
      /* match! */
#ifdef DEBUG
      buffer_putsflush(buffer_2,"MATCH!\n");
#endif
      if (index_type==0)
	rec=findrec(k);
      else if (index_type==1)
	rec=uint32_read((char*)(&index[mid+elements]));
      else {
	buffer_puts(buffer_2,"unsupported index type ");
	buffer_putulong(buffer_2,index_type);
	buffer_puts(buffer_2," in tagmatches!\n");
	return;
      }
      if (rec>=0)
	setbit(b,rec);
      /* there may be multiple matches.
	* Look before and after mid, too */
      if (mid)	/* thx Andreas Stührk */
	for (k=mid-1; k!=(uint32_t)-1; --k) {
	  m=uint32_read((char*)(&index[k]));
	  if ((ft==LESSEQUAL) || (l=match(s,map+m))==0) {
	    if (index_type==0)
	      rec=findrec(m);
	    else if (index_type==1)
	      rec=uint32_read((char*)(&index[k+elements]));
	    if (rec>=0)
	      setbit(b,rec);
	  } else break;
	}
      for (k=mid+1; k<elements; ++k) {
	m=uint32_read((char*)(&index[k]));
	if ((ft==GREATEQUAL) || (l=match(s,map+m))==0) {
	  if (index_type==0)
	    rec=findrec(m);
	  else if (index_type==1)
	    rec=uint32_read((char*)(&index[k+elements]));
	  if (rec>=0)
	    setbit(b,rec);
	} else break;
      }
      return;
    }

    if (l<0) {
#ifdef DEBUG
      buffer_putsflush(buffer_2,"smaller!\n");
#endif
      if (mid)
	top=mid-1;
      else
	break;	/* since our offsets are unsigned, we need to avoid the -1 case */
    } else
#ifdef DEBUG
      buffer_putsflush(buffer_2,"larger!\n"),
#endif
      bottom=mid+1;
  }
  /* not found; we can still have matches if type==LESSEQUAL or
   * type==GREATEQUAL */
  if (ft==GREATEQUAL) {
    for (k=mid; k<elements; ++k) {
      m=uint32_read((char*)(&index[k]));
      if (index_type==0)
	rec=findrec(m);
      else if (index_type==1)
	rec=uint32_read((char*)(&index[k+elements]));
      if (rec>=0)
	setbit(b,rec);
    }
  } else if (ft==LESSEQUAL) {
    for (k=0; k<=mid; ++k) {
      m=uint32_read((char*)(&index[k]));
      if (index_type==0)
	rec=findrec(m);
      else if (index_type==1)
	rec=uint32_read((char*)(&index[k+elements]));
      if (rec>=0)
	setbit(b,rec);
    }
  }
}

static uint32 hash(const unsigned char* c,size_t keylen) {
  size_t h=0,i;
  for (i=0; i<keylen; ++i) {
    /* from djb's cdb */
    h += (h<<5);
    h ^= c[i];
  }
  return (uint32)h;
}

static uint32 hash_tolower(const unsigned char* c,size_t keylen) {
  size_t h=0,i;
  for (i=0; i<keylen; ++i) {
    /* from djb's cdb */
    h += (h<<5);
    h ^= tolower(c[i]);
  }
  return (uint32)h;
}

/* Use the indices to answer a query with the given filter.
 * For all matching records, set the corresponding bit to 1 in bitfield.
 * Note that this match can be approximate.  Before answering, the
 * matches are verified with ldap_match_mapped, so the index can also
 * be used if it only helps eliminate some of the possible matches (for
 * example an AND query where only one of the involved attributes has an
 * index). Return 1 is index helped, 0 if not. */
static int useindex(struct Filter* f,struct bitfield* b) {
  struct Filter* y=f->x;
  if (!f) {
    emptyset(b);
    return 1;
  }

  if (f->type==EQUAL) {		/* prefer a hash index if there is one */
    uint32 ofs;
    for (ofs=indices_offset+record_count*4; ofs<filelen;) {
      uint32 index_type,next,indexed_attribute;
      index_type=uint32_read(map+ofs);
      next=uint32_read(map+ofs+4);
      indexed_attribute=uint32_read(map+ofs+8);
      if (index_type==3)
	if (!matchstring(&f->ava.desc,map+indexed_attribute)) {
	  uint32 hashtabsize=uint32_read(map+ofs+12);
	  uint32 hashtab=ofs+16;
	  uint32 hashval=f->attrflag&1?hash_tolower((unsigned char*)f->ava.value.s,f->ava.value.l):hash((unsigned char*)f->ava.value.s,f->ava.value.l);
	  uint32 hashofs=uint32_read(map+hashtab+(hashval%hashtabsize)*4);
	  emptyset(b);
	  if (hashofs==(uint32)-1) return 1;
	  if (hashofs<ofs)
	    /* direct hit */
	    setbit(b,hashofs);
	  else {
	    uint32 n=uint32_read(map+hashofs);
	    hashofs+=4;
	    while (n) {
	      setbit(b,uint32_read(map+hashofs));
	      hashofs+=4;
	      --n;
	    }
	  }
	  return 1;
	}
      ofs=next;
    }
  }

  switch (f->type) {
  case AND:
    {
      struct bitfield tmp;
      int ok=0;
      tmp.bits=alloca(record_set_length*sizeof(unsigned long));
      if (y) {
	useindex(y,b);
	y=y->next;
      } else
	fillset(b);
      while (y) {
	if (useindex(y,&tmp)) {
	  size_t i;
	  for (i=0; i<record_set_length; ++i)
	    b->bits[i] &= tmp.bits[i];
	  if (tmp.first>b->first) b->first=tmp.first;
	  if (tmp.last<b->last) b->last=tmp.last;
	  ok=1;
	}
	y=y->next;
      }
      return ok;
    }
  case OR:
    {
      struct bitfield tmp;
      int ok=1;
      tmp.bits=alloca(record_set_length*sizeof(unsigned long));
      if (y) {
	useindex(y,b);
	y=y->next;
      } else
	emptyset(b);
      while (y) {
	if (useindex(y,&tmp)) {
	  size_t i;
	  for (i=0; i<record_set_length; ++i)
	    b->bits[i] |= tmp.bits[i];
	  if (tmp.first<b->first) b->first=tmp.first;
	  if (tmp.last>b->last) b->last=tmp.last;
	} else
	  ok=0;
	y=y->next;
      }
      return ok;
    }
  case NOT:
    {
      if (y) {
	emptyset(b);
	if (!useindex(y,b)) return 0;
	invertset(b);
      } else
	emptyset(b);
      return 1;
    }
  case SUBSTRING:
    if (f->substrings->substrtype!=prefix) { emptyset(b); return 0; }
    {
      uint32 ofs;
      for (ofs=indices_offset+record_count*4; ofs<filelen;) {
	uint32 index_type,next,indexed_attribute;
	index_type=uint32_read(map+ofs);
	next=uint32_read(map+ofs+4);
	indexed_attribute=uint32_read(map+ofs+8);
	if (index_type<=1)
	  if (!matchstring(&f->ava.desc,map+indexed_attribute)) {
	    tagmatches((uint32*)(map+ofs+12),(next-ofs-12)/(4<<index_type),&f->substrings->s,b,
		       f->attrflag&1?matchcaseprefix:matchprefix,index_type,f->type);
	    return 1;
	  }
	ofs=next;
      }
    }
    emptyset(b);
    return 0;
  case PRESENT:
    emptyset(b);
    return 0;
#if 0
    {
      /* now this is not exactly using an index, but a linear search
       * through the record table, but since each check is very cheap,
       * we pretend it's indexed */
      const char* x=map+5*4+size_of_string_table+attribute_count*8;
      size_t i;
      emptyset(b);
      for (i=0; i<record_count; ++i) {
	if (ldap_match_present(x-map,f->attrofs))
	  setbit(b,i);
	x+=uint32_read(x)*8;
      }
      return 1;
    }
#endif
  case LESSEQUAL:
  case GREATEQUAL:
  case EQUAL:
    {
      uint32 ofs;
      // record_count is in uint32, so x4 */
      for (ofs=indices_offset+record_count*4; ofs<filelen;) {
	uint32 index_type,next,indexed_attribute;
	// see FORMAT for explanation
	index_type=uint32_read(map+ofs);
	next=uint32_read(map+ofs+4);
	indexed_attribute=uint32_read(map+ofs+8);
	if (index_type<=1)
	  if (!matchstring(&f->ava.desc,map+indexed_attribute)) {
	    tagmatches((uint32*)(map+ofs+12),(next-ofs-12)/(4<<index_type),&f->ava.value,b,
		       f->attrflag&1?matchcasestring:matchstring,index_type,f->type);
	    return 1;
	  }
	ofs=next;
      }
    }
    /* fall through */
  default:
    emptyset(b);
    return 0;
  }
}



/*
                                                                 _
  __ _ _   _  ___ _ __ _   _    __ _ _ __  _____      _____ _ __(_)_ __   __ _
 / _` | | | |/ _ \ '__| | | |  / _` | '_ \/ __\ \ /\ / / _ \ '__| | '_ \ / _` |
| (_| | |_| |  __/ |  | |_| | | (_| | | | \__ \\ V  V /  __/ |  | | | | | (_| |
 \__, |\__,_|\___|_|   \__, |  \__,_|_| |_|___/ \_/\_/ \___|_|  |_|_| |_|\__, |
    |_|                |___/                                             |___/
*/

static int checkacl(uint32 recofs,uint32 attrofs,unsigned long operation,struct SearchResultEntry* sre) {
  uint32 j;
  for (j=0; j<acls; ++j) {
    /* does the ACL subject apply? */
    if (!acl_ec_subjects[Acls[j]->subject]) continue;
    /* does the ACL even apply to the wanted operation? */
    if ((Acls[j]->may | Acls[j]->maynot) & operation) {
      uint32 k;
      if (acl_ec_subjects[filters+Acls[j]->object]==-1) continue;
      if (acl_ec_subjects[filters+Acls[j]->object]==0) {
	int match=0;
	if (Filters[Acls[j]->object]==(struct Filter*)Any)
	  match=1;
	else if (Filters[Acls[j]->object]==(struct Filter*)Self) {
	  if (authenticated_as==0 && authenticated_as_str)
	    match=!strcmp(map+uint32_read(map+recofs+8),authenticated_as_str);
	  else
	    match=(recofs==authenticated_as);
	} else if (recofs)
	  match=ldap_matchfilter_mapped(recofs,Filters[Acls[j]->object]);
	else if (sre)
	  match=ldap_matchfilter_sre(sre,Filters[Acls[j]->object]);
	else
	  match=-1;
	if (match)
	  acl_ec_subjects[filters+Acls[j]->object]=1;
	else {
	  acl_ec_subjects[filters+Acls[j]->object]=-1;
	  continue;
	}
      }
      for (k=0; k<Acls[j]->attrs; ++k) {
	if (Acls[j]->Attrs[k]==any_ofs || attrofs==Acls[j]->Attrs[k]) {
	  if (Acls[j]->may&operation)
	    return 1;
	  else
	    return -1;
	  break;
	}
      }
    }
  }
  return 0;
}

static int ldap_matchfilter_hn(struct hashnode* hn,struct Filter* f);

static int checkacl_hn(struct hashnode* hn,const unsigned char* attr,unsigned long operation) {
  uint32 j;
  for (j=0; j<acls; ++j) {
    /* does the ACL subject apply? */
    if (!acl_ec_subjects[Acls[j]->subject]) continue;
    /* does the ACL even apply to the wanted operation? */
    if ((Acls[j]->may | Acls[j]->maynot) & operation) {
      uint32 k;
      if (acl_ec_subjects[filters+Acls[j]->object]==-1) continue;
      if (acl_ec_subjects[filters+Acls[j]->object]==0) {
	int match=0;
	if (Filters[Acls[j]->object]==(struct Filter*)Any)
	  match=1;
	else if (Filters[Acls[j]->object]==(struct Filter*)Self)
	  match=dn && !strcmp((char*)hn->dn,authenticated_as_str);
	else if (dn)
	  match=ldap_matchfilter_hn(hn,Filters[Acls[j]->object]);
	else
	  match=-1;
	if (match)
	  acl_ec_subjects[filters+Acls[j]->object]=1;
	else {
	  acl_ec_subjects[filters+Acls[j]->object]=-1;
	  continue;
	}
      }
      for (k=0; k<Acls[j]->attrs; ++k) {
/*	    if (Acls[j]->Attrs[k]==any_ofs || !matchstring(&adl->a,map+Acls[j]->Attrs[k])) { */
	if (Acls[j]->Attrs[k]==any_ofs || bstr_equal((char*)attr,map+Acls[j]->Attrs[k])) {
	  if (Acls[j]->may&operation)
	    return 1;
	  else
	    return -1;
	  break;
	}
      }
    }
  }
  return 0;
}


static struct hashnode** dn_in_journal(unsigned char* dn);

static void answerwith_hn(struct hashnode* hn,struct SearchRequest* sr,long messageid,int out);

/* this routine is called for each record matched the query.  It basically puts together
 * an answer LDAP message from the record and the list of attributes the other side said
 * it wanted to have. */
static void answerwith(uint32 ofs,struct SearchRequest* sr,long messageid,int out) {
  struct SearchResultEntry sre;
  struct PartialAttributeList** pal=&sre.attributes;
  struct hashnode** hn;

  if ((hn=dn_in_journal((unsigned char*)map+uint32_read(map+ofs+8))) && *hn) {
    (*hn)->overwrite=1;
    answerwith_hn(*hn,sr,messageid,out);
    return;
  }

#if (debug != 0)
  if (debug) {
    const char* x=map+ofs;
    uint32 j;
    buffer_putulong(buffer_2,j=uint32_read(x));
    buffer_puts(buffer_2," attributes:\n");
    x+=8;
    buffer_puts(buffer_2,"  dn: ");
    buffer_puts(buffer_2,map+uint32_read(x));
    buffer_puts(buffer_2,"\n  objectClass: ");
    x+=4;
    buffer_puts(buffer_2,map+uint32_read(x));
    buffer_puts(buffer_2,"\n");
    x+=4;
    for (; j>2; --j) {
      buffer_puts(buffer_2,"  ");
      buffer_puts(buffer_2,map+uint32_read(x));
      buffer_puts(buffer_2,": ");
      buffer_puts(buffer_2,map+uint32_read(x+4));
      buffer_puts(buffer_2,"\n");
      x+=8;
    }
    buffer_flush(buffer_2);
  }
#endif

  if (acls)
    byte_zero(acl_ec_subjects+filters,filters);

  if (acls && checkacl(ofs,dn_ofs,acl_read,0)!=1) return;

  sre.objectName.l=bstrlen(sre.objectName.s=map+uint32_read(map+ofs+8));
  sre.attributes=0;

  /* now go through list of requested attributes */
  {
    struct AttributeDescriptionList* adl=sr->attributes;
    if (!adl && attribute_count>2) {
      /* did not ask for any attributes.  send 'em all. */
      /* to do that, construct a list of all attributes */

      uint32 i;
      const char* x=map+5*4+size_of_string_table+4;
      if (attribute_count>HUGE_SIZE_FOR_SANITY_CHECKS/sizeof(struct AttributeDescriptionList))
	return;
      adl=alloca((attribute_count)*sizeof(struct AttributeDescriptionList));
      for (i=0; i<attribute_count-1; ++i) {
	uint32 j;
	uint32_unpack(x,&j);
	x+=4;
	adl[i].a.s=map+j;
	adl[i].a.l=str_len(map+j);
	adl[i].attrofs=j;
	adl[i].next=adl+i+1;
      }
      adl[attribute_count-2].next=0;
    }
    while (adl) {
      const char* val=0;
      uint32 i=2,j;

      if (!acls || checkacl(ofs,adl->attrofs,acl_read,0)==1) {
	uint32_unpack(map+ofs,&j);
#if 0
	buffer_puts(buffer_2,"looking for attribute \"");
	buffer_put(buffer_2,adl->a.s,adl->a.l);
	buffer_putsflush(buffer_2,"\"\n");
#endif
	if (!matchstring(&adl->a,"dn")) val=sre.objectName.s; else
	if (!matchstring(&adl->a,"objectClass"))
	  val=map+uint32_read(map+ofs+12);
	else {
	  for (; i<j; ++i)
/*	    if (!matchstring(&adl->a,map+uint32_read(map+ofs+i*8))) { */
	    if (adl->attrofs == uint32_read(map+ofs+i*8)) {
	      val=map+uint32_read(map+ofs+i*8+4);
	      ++i;
	      break;
	    }
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
	    struct AttributeDescriptionList** a;
	    a=&(*pal)->values;
add_attribute:
	    *a=malloc(sizeof(struct AttributeDescriptionList));
	    if (!*a) goto nomem;
	    (*a)->a.s=bstrfirst(val);
	    (*a)->a.l=bstrlen(val);
	    for (;i<j; ++i)
/*	      if (!matchstring(&adl->a,map+uint32_read(map+ofs+i*8))) { */
	      if (adl->attrofs == uint32_read(map+ofs+i*8)) {
		val=map+uint32_read(map+ofs+i*8+4);
		++i;
		a=&(*a)->next;
		goto add_attribute;
	      }
	    (*a)->next=0;
	  }
	  (*pal)->next=0;
	  pal=&(*pal)->next;
	}
      }
      adl=adl->next;
    }
  }
  {
    long l=fmt_ldapsearchresultentry(0,&sre);
    char *buf;
    long tmp;
    if (l<=HUGE_SIZE_FOR_SANITY_CHECKS) {
      buf=alloca(l+300); /* you never know ;) */
      if (debug) {
	buffer_puts(buffer_2,"sre len ");
	buffer_putulong(buffer_2,l);
	buffer_putsflush(buffer_2,".\n");
      }
      tmp=fmt_ldapmessage(buf,messageid,SearchResultEntry,l);
      fmt_ldapsearchresultentry(buf+tmp,&sre);
      write(out,buf,l+tmp);
    }
  }
  free_ldappal(sre.attributes);
}


/*
 _     _       _       _                _   _     _
| |__ (_) __ _| |__   | | _____   _____| | | | __| | __ _ _ __
| '_ \| |/ _` | '_ \  | |/ _ \ \ / / _ \ | | |/ _` |/ _` | '_ \
| | | | | (_| | | | | | |  __/\ V /  __/ | | | (_| | (_| | |_) |
|_| |_|_|\__, |_| |_| |_|\___| \_/ \___|_| |_|\__,_|\__,_| .__/
         |___/                                           |_|
*/

static int copystring(struct string* dest,struct string* src) {
  dest->s=malloc(src->l+1);
  if (!dest->s) return -1;
  byte_copy((char*)dest->s,src->l,src->s);
  dest->l=src->l;
  return 0;
}

/* deep copy an attribute description list */
static int copyadl(struct AttributeDescriptionList** dest,struct AttributeDescriptionList* src) {
  *dest=0;
  while (src) {
    if (!(*dest=malloc(sizeof(*src)))) return -1;
    byte_zero(*dest,sizeof(*src));
    if (copystring(&(*dest)->a,&src->a)) return -1;
    (*dest)->attrofs=src->attrofs;
    dest=&(*dest)->next;
    src=src->next;
  }
  return 0;
}

/* semi-deep copy an attribute description list */
static int copyadl2(struct AttributeDescriptionList** dest,struct AttributeDescriptionList* src) {
  *dest=0;
  while (src) {
    if (!(*dest=malloc(sizeof(*src)))) return -1;
    byte_zero(*dest,sizeof(*src));
    (*dest)->a=src->a;
    (*dest)->attrofs=src->attrofs;
    dest=&(*dest)->next;
    src=src->next;
  }
  return 0;
}




#if 0
/* deep copy a partial attribute list */
static int copypal(struct PartialAttributeList** dest,struct PartialAttributeList* src) {
  *dest=0;
  while (src) {
    if (!(*dest=malloc(sizeof(**dest)))) return -1;
    byte_zero(*dest,sizeof(**dest));
    if (copystring(&(*dest)->type,&src->type) ||
	copyadl(&(*dest)->values,src->values)) return -1;
    dest=&(*dest)->next;
    src=src->next;
  }
  return 0;
}
#endif

/* small helper for addreq2sre */
static int ar2sreh1(struct PartialAttributeList** dest,struct Addition* src) {
  *dest=0;
  while (src) {
    if (!(*dest=malloc(sizeof(**dest)))) return -1;
    byte_zero(*dest,sizeof(**dest));
    if (copystring(&(*dest)->type,&src->AttributeDescription) ||
	copyadl(&(*dest)->values,&src->vals)) return -1;
    dest=&(*dest)->next;
    src=src->next;
  }
  return 0;
}

/* convert an AddRequest to a SearchResultEntry */
static int addreq2sre(struct SearchResultEntry* sre,struct AddRequest* ar) {
  byte_zero(sre,sizeof(*sre));
  if (copystring(&sre->objectName,&ar->entry) ||
      !(sre->attributes=malloc(sizeof(*sre->attributes))) ||
      ar2sreh1(&sre->attributes,&ar->a)) {
    free_ldapsearchresultentry(sre);
    return -1;
  }
  return 0;
}

/* small helper for modreq2sre */
static int mr2sreh1(struct PartialAttributeList** dest,struct Modification* src) {
  *dest=0;
  while (src) {
    if (!(*dest=malloc(sizeof(**dest)))) return -1;
    byte_zero(*dest,sizeof(**dest));
    (*dest)->type=src->AttributeDescription;
    if (copyadl2(&(*dest)->values,src->vals)) return -1;
    dest=&(*dest)->next;
    src=src->next;
  }
  return 0;
}

/* We need two versions for the modify request.  The first one just creates a stupid
 * SearchResultEntry out of just the changed attributes, which is then only used for ACL
 * matching.  The second version merges in the existing record to form the modified
 * record.  This is the first version for ACL checking. */
static int modreq2sre(struct SearchResultEntry* sre,struct ModifyRequest* mr) {
  byte_zero(sre,sizeof(*sre));
  sre->objectName=mr->object;
  if (!(sre->attributes=malloc(sizeof(*sre->attributes))) ||
      mr2sreh1(&sre->attributes,&mr->m)) {
    free_ldapsearchresultentry(sre);
    return -1;
  }
  return 0;
}

static int applymodreq(struct hashnode* hn,struct ModifyRequest* mr,struct SearchResultEntry* sre) {
  struct PartialAttributeList** l;
  struct Modification* m;
  size_t i;
  sre->objectName.l=strlen((char*)hn->dn);
  sre->objectName.s=(char*)hn->dn;
  sre->attributes=0;
  l=&(sre->attributes);
  /* go through all the attributes in the hash node and apply the modifications */
  for (i=0; i<hn->n; ++i) {
    enum { Keep, Drop } todo=Keep;
    for (m=&mr->m; m; m=m->next) {
      if (!matchstring(&m->AttributeDescription,(char*)hn->a[i].a)) {
	/* same attribute */
	if (m->operation==Add)
	  continue;
	else if (m->operation==Delete) {
	  /* if it's delete, we need to check the value list */
	  struct AttributeDescriptionList* adl=m->vals;
	  if (!adl)
	    todo=Drop;	/* if the list is empty, drop all */
	  else
	    for (adl=m->vals; adl; adl=adl->next) {
	      if (!matchstring(&adl->a,(char*)hn->a[i].v)) {
		todo=Drop;
		break;
	      }
	    }
	} else
	  todo=Drop;
      }
      if (todo==Drop) break;
    }
    if (todo==Keep) {
      *l=malloc(sizeof(**l));
      if (!*l) return -1;
      (*l)->next=0;
      (*l)->type.s=bstrfirst((char*)hn->a[i].a);
      (*l)->type.l=bstrlen((char*)hn->a[i].a);
      if (!((*l)->values=malloc(sizeof(*(*l)->values)))) return -1;
      (*l)->values->a.s=bstrfirst((char*)hn->a[i].v);
      (*l)->values->a.l=bstrlen((char*)hn->a[i].v);
      (*l)->values->attrofs=0;
      (*l)->values->next=0;
      l=&(*l)->next;
    }
  }
  /* then add all the "replace" or "add" attributes */
  for (m=&mr->m; m; m=m->next) {
    if ((m->operation==Add || m->operation==Replace) && m->vals) {
      *l=malloc(sizeof(**l));
      if (!*l) return -1;
      (*l)->next=0;
      (*l)->type.s=m->AttributeDescription.s;
      (*l)->type.l=m->AttributeDescription.l;
      if (copyadl2(&(*l)->values,m->vals)==-1) return -1;
      l=&(*l)->next;
    }
  }
  return 0;
}

/* write a search result entry to a file */
static int writesretofd(int fd,struct SearchResultEntry* sre) {
  /* we have no locking, but we open using O_APPEND, so the OS synchronizes for us as long
   * as we write atomically.  Therefore we have to buffer here. */
  size_t i,l,nl;
  char* c;
  struct PartialAttributeList* pal=sre->attributes;
  l=5+fmt_ldapescape(0,sre->objectName.s,sre->objectName.l);	/* "\ndn: ...\n" */
  if (l<=5) return -1;
  while (pal) {
    struct AttributeDescriptionList* adl=pal->values;
    while (adl) {
      nl=fmt_ldapescape(0,pal->type.s,pal->type.l);
      if (nl>HUGE_SIZE_FOR_SANITY_CHECKS) return -1;
      l+=nl;
      nl=fmt_ldapescape(0,adl->a.s,adl->a.l);
      if (nl>HUGE_SIZE_FOR_SANITY_CHECKS) return -1;
      l+=nl;
      if (l+3>HUGE_SIZE_FOR_SANITY_CHECKS) return -1;
      l+=3;
      adl=adl->next;
    }
    pal=pal->next;
  }
  c=alloca(l+1);
  if (!c) return -1;
  i=fmt_str(c,"dn: ");
  i+=fmt_ldapescape(c+i,sre->objectName.s,sre->objectName.l);
  i+=fmt_str(c+i,"\n");
  pal=sre->attributes;
  while (pal) {
    struct AttributeDescriptionList* adl=pal->values;
    while (adl) {
      i+=fmt_ldapescape(c+i,pal->type.s,pal->type.l);
      i+=fmt_str(c+i,": ");
      i+=fmt_ldapescape(c+i,adl->a.s,adl->a.l);
      i+=fmt_str(c+i,"\n");
      adl=adl->next;
    }
    pal=pal->next;
  }
  i+=fmt_str(c+i,"\n");

  return (write(fd,c,i)==(ssize_t)i)?0:-1;
}

/* This is the high level LDAP handling code.  It reads queries from the socket at in, and
 * then writes the answers to out.  Normally in == out, but they are separate here so this
 * can also be called with in=stdin and out=stdout. */

static void answerwithjournal(struct SearchRequest* sr,long messageid,int out);
static struct hashnode** dn_in_journal2(const char* dn,size_t dnlen);

static int lookupdn(struct string* dn,size_t* index, struct hashnode** hn) {
  struct Filter f;
  struct hashnode** tmphn;
  if (dn->l<1 || !dn->s) {
    buffer_putsflush(buffer_2,"lookupdn called for NULL dn!\n");
    return -1;
  }
  if ((tmphn=dn_in_journal2(dn->s,dn->l)) && *tmphn) {
    *hn=*tmphn;
    *index=-1;
    return (*hn)->n > 0;
  }
  *hn=0;
  f.type=EQUAL;
  f.ava.desc.l=2; f.ava.desc.s="dn";
  f.ava.value=*dn;
  f.next=f.x=0;
  fixup(&f);
  if (!indexable(&f)) {
    buffer_putsflush(buffer_2,"no index for dn, lookup failed!\n");
    return -1;
  } else {
    struct bitfield result;
    size_t i;
    result.bits=alloca(record_set_length*sizeof(unsigned long));
    if (!useindex(&f,&result) || result.first>result.last)
      return 0;
//    assert(result.last<=record_count);
    for (i=result.first; i<=result.last; ) {
      if (!result.bits[i/(8*sizeof(long))]) {
	i+=8*sizeof(long);
	continue;
      }
      for (; i<=result.last; ++i) {
	if (isset(&result,i)) {
	  uint32 j;
	  uint32_unpack(map+indices_offset+4*i,&j);
	  uint32 k;
	  uint32_unpack(map+j+8,&k);
	  if (!matchstring(dn,map+k)) {
	    *index=i;
	    return 1;
	  }
	}
      }
    }
  }
  return 0;
}

/* return fake hashnode for record from data file.
 * all the internal pointers point into the data file, free on the pointer is sufficient
 * to clean up everything */
static struct hashnode* load_record_into_hashnode(size_t recno) {
  uint32* attr = getrecptr(recno);
  uint32 attrs;
  uint32 i;
  if (!attr) return 0;
  attrs = uint32_read((const char*)attr);
  struct hashnode* h = malloc(sizeof(struct hashnode)+attrs*sizeof(struct attribute2));
  if (!h) return 0;
  h->next=h->linear=0;
  h->hashval=0;
  h->dn=(unsigned char*)map+uint32_read((const char*)&(attr[2]));
  h->overwrite=1;
  h->a[0].a=(unsigned char*)"objectClass"; h->a[0].v=(unsigned char*)map+uint32_read((const char*)&(attr[3]));
  h->n=attrs-1;	// dn is extra
  for (i=2; i<attrs; ++i) {
    h->a[i-1].a=(unsigned char*)map+uint32_read((const char*)&(attr[i*2]));
    h->a[i-1].v=(unsigned char*)map+uint32_read((const char*)&(attr[i*2+1]));
  }
  return h;
}

static void normalize_string_dn(struct string* s) {
  /* OK this is a kludge.  s->s is supposed to be read-only because it points into the
   * buffer where we read it into from the network.
   * Since normalize_dn ends up using less or equal space, and we are not interested in
   * the non-normalized dn, we do the read-write cast and normalize in-place.
   * Kids, don't do this at home. */
  s->l=normalize_dn((char*)s->s,s->s,s->l);
}

static void update();

void reply_with_index(struct SearchRequest* sr,unsigned long* messageid,int out) {
  size_t returned=0;
  struct bitfield result;
  size_t i;
#if (debug != 0)
  if (debug) buffer_putsflush(buffer_2,"query can be answered with index!\n");
#endif
  result.bits=alloca(record_set_length*sizeof(unsigned long));
  /* Use the index to find matching data.  Put the offsets
    * of the matches in a table.  Use findrec to locate
    * the records that point to the data. */
  if (!useindex(sr->filter,&result)) {
    result.first=0; result.last=record_count;
    fillset(&result);
  }
//	      assert(result.last<=record_count);
  for (i=result.first; i<=result.last; ) {
    size_t ni=i+8*sizeof(long);
    if (!result.bits[i/(8*sizeof(long))]) {
      i=ni;
      continue;
    }
    if (ni>record_count) ni=record_count;
    for (; i<ni; ++i) {
      if (isset(&result,i)) {
	uint32 j;
	uint32_unpack(map+indices_offset+4*i,&j);
	if (ldap_match_mapped(j,sr)) {
	  if (sr->sizeLimit && sr->sizeLimit<++returned)
	    return;
	  answerwith(j,sr,*messageid,out);
	}
      }
    }
    if (i==record_count) break;
  }
}

/* a standard LDAP session looks like this:
 *   1. connect to server
 *   2. send a BindRequest
 *      get back a BindResponse
 *   3. send a SearchRequest
 *      get back n SearchResultEntries
 *      get back a SearchResultDone
 *   4. send an UnbindRequest
 *   5. close
 * tinyldap does not complain if you don't unbind before hanging up.
 */
static int handle(int in,int out) {
  size_t len;
  char stackbuf[BUFSIZE];
  size_t bufsize=BUFSIZE;
  char* buf=stackbuf;
  for (len=0;;) {
    int tmp;
    int res;
    unsigned long messageid,op;
    size_t Len;
    res=scan_ldapmessage(buf,buf+len,&messageid,&op,&Len);
    if (res==0) {
      /* Maybe the message is larger than the buffer. Attempt to find out how large the
       * buffer should be so we can capture the whole message */
      if (len>0) {
	res=scan_ldapmessage_nolengthcheck(buf,buf+len,&Len);
	if (res) {
	  /* we could parse the header and have a size. Now check if it is plausible. */

	  if (debug) {
	    buffer_puts(buffer_2,"got partial message (");
	    buffer_putulong(buffer_2,len);
	    buffer_puts(buffer_2," of ");
	    buffer_putulong(buffer_2,Len);
	    buffer_puts(buffer_2," bytes). bufsize is ");
	    buffer_putulong(buffer_2,bufsize);
	    buffer_putnlflush(buffer_2);
	  }

	  if (Len > MAXBUFSIZE-100) 
  outofmemory:
	  {
	    /* Peer wants to send us more than MAXBUFSIZE in a message. Abort. */
	    char outbuf[1024];
	    size_t s=100;
	    int response;
	    switch (op) {
	    case SearchRequest: response=SearchResultDone; break;
	    case ModifyRequest: response=ModifyResponse; break;
	    case AddRequest: response=AddResponse; break;
	    case DelRequest: response=DelResponse; break;
	    case ModifyDNRequest: response=ModifyDNResponse; break;
	    case CompareRequest: response=CompareResponse; break;
	    default: response=BindResponse;
	    }
	    size_t len=fmt_ldapresult(outbuf+s,sizeLimitExceeded,"","message too large","");
	    size_t hlen=fmt_ldapmessage(0,messageid,response,len);
	    fmt_ldapmessage(outbuf+s-hlen,messageid,response,len);
	    write(out,outbuf+s-hlen,len+hlen);
	    /* This is an attack. We don't continue talking to attackers. */
	    /* Also we would have to wastefully read Len bytes here if we wanted to continue. */
	    exit(3);
	  }
	  /* Peer wants to send more than BUFSIZE bytes, but less than MAXBUFSIZE. */
	  bufsize=Len+100;	// MAXBUFSIZE should be small enough that adding 100 won't overflow
	  if (bufsize<100) goto outofmemory;
	  char* newbuf;
	  if (buf==stackbuf) {
	    newbuf=malloc(bufsize);
	    if (newbuf) byte_copy(newbuf,len,stackbuf);
	  } else
	    newbuf=realloc(buf,bufsize);
	  if (!newbuf) {
	    if (buf!=stackbuf) free(buf);
	    goto outofmemory;
	  }
	  buf=newbuf;
	  if (debug) {
	    buffer_puts(buffer_2,"resized. bufsize now ");
	    buffer_putulong(buffer_2,bufsize);
	    buffer_putnlflush(buffer_2);
	  }
	}
      }
      tmp=read(in,buf+len,bufsize-len);

      if (debug) {
	buffer_puts(buffer_2,"read ");
	buffer_putlong(buffer_2,tmp);
	buffer_puts(buffer_2," bytes at ofs ");
	buffer_putulong(buffer_2,len);
	buffer_putnlflush(buffer_2);
      }

      if (tmp==0) {
	close(in);
	if (in!=out) close(out); 
	return 0;
  //      if (BUFSIZE-len) { return 0; }
      }
      if (tmp<0) { write(2,"error!\n",7); return 1; }
      len+=tmp;
      if (debug) {
	buffer_puts(buffer_2,"len now ");
	buffer_putulong(buffer_2,len);
	buffer_putnlflush(buffer_2);
      }

      continue;
//      res=scan_ldapmessage(buf,buf+len,&messageid,&op,&Len);
    }
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
      update();
      switch (op) {
      case BindRequest:
	{
	  unsigned long version,method;
	  struct string name;
	  size_t tmp;
	  tmp=scan_ldapbindrequest(buf+res,buf+len,&version,&name,&method);
	  if (tmp>0) {
	    if (verbose) {
	      buffer_puts(buffer_2,"bind request: version ");
	      buffer_putulong(buffer_2,version);
	      buffer_puts(buffer_2," for name \"");
	      buffer_put(buffer_2,name.s,name.l);
	      buffer_puts(buffer_2,"\" with method ");
	      buffer_putulong(buffer_2,method);
	      buffer_putsflush(buffer_2,".\n");
	    }
	    if (oneshot==1) {
	      if (bindreqs>0)
		goto authfailure;
	      else
		bindreqs=1;
	    }
	    if (name.l) {
	      struct string password;
	      size_t idx;
	      struct hashnode* hn;
	      int err=success;

	      scan_ldapstring(buf+res+tmp,buf+len,&password);

	      normalize_string_dn(&name);
	      switch (lookupdn(&name,&idx,&hn)) {
	      case -1: err=operationsError; break;
	      case 1: break;
	      case 0: err=noSuchObject; break;
	      default: err=operationsError;
	      }
	      if (err!=success)
		goto authfailure;
	      else {
		const char* c=0;
		uint32 authdn=0;
		char* authdn_str=0;
		if (idx==(size_t)-1) {	// found in journal
		  size_t i;
		  for (i=0; i<hn->n; ++i)
		    if (!strcmp((char*)hn->a[i].a,"userPassword")) {
		      c=(char*)hn->a[i].v;
		      authdn=0;
		      authdn_str=(char*)hn->dn;
		      break;
		    }
		} else {	// found in db
		  uint32 j;
		  uint32_unpack(map+indices_offset+4*idx,&j);
		  uint32_unpack(map+j+8,&authdn);
		  authdn_str=(char*)map+authdn;
		  authdn=j;
		  if (!(j=ldap_find_attr_value(j,userPassword_ofs))) {
		    buffer_putsflush(buffer_2,"no userPassword attribute found, bind failed!\n");
		    goto authfailure;
		  }
		  c=map+j;
		}

		if (check_password(c,&password)) {
		  authenticated_as=authdn;
		  authenticated_as_str=authdn_str;
		  if (acls) {
		    size_t i;
		    for (i=0; i<filters; ++i)
		      acl_ec_subjects[i]=(Filters[i]==(struct Filter*)Any);
		    for (i=0; i<acls; ++i) {
		      size_t j=Acls[i]->subject;
		      if (!acl_ec_subjects[j]) {
			if (authdn==0)	// authenticated against hashnode
			  acl_ec_subjects[j]=ldap_matchfilter_hn(hn,Filters[j]);
			else	// authenticated against mapped db
			  acl_ec_subjects[j]=ldap_matchfilter_mapped(authdn,Filters[j]);
		      }
		    }
		  }
		} else
authfailure:
		{
		  char outbuf[1024];
		  size_t s=100;
		  size_t len=fmt_ldapbindresponse(outbuf+s,invalidCredentials,"","authentication failure","");
		  size_t hlen=fmt_ldapmessage(0,messageid,BindResponse,len);
		  fmt_ldapmessage(outbuf+s-hlen,messageid,BindResponse,len);
		  write(out,outbuf+s-hlen,len+hlen);
		  break;
		}
	      }
	    }
	    {
	      char outbuf[1024];
	      size_t s=100;
	      size_t len=fmt_ldapbindresponse(outbuf+s,0,"","go ahead","");
	      size_t hlen=fmt_ldapmessage(0,messageid,BindResponse,len);
	      fmt_ldapmessage(outbuf+s-hlen,messageid,BindResponse,len);
	      write(out,outbuf+s-hlen,len+hlen);
	    }
	  }
	}
	break;
      case SearchRequest:
	{
	  struct SearchRequest sr;
	  size_t tmp;
#if 0
	  {
	    int fd=open_write("request");
	    write(fd,buf,res+len);
	    close(fd);
	  }
#endif
	  if ((tmp=scan_ldapsearchrequest(buf+res,buf+len,&sr))) {
	    size_t returned=0;

#if (debug != 0)
	    if (debug) {
	      const char* scopes[]={"baseObject","singleLevel","wholeSubtree"};
	      const char* alias[]={"neverDerefAliases","derefInSearching","derefFindingBaseObj","derefAlways"};
	      buffer_puts(buffer_2,"search request: baseObject \"");
	      buffer_put(buffer_2,sr.baseObject.s,sr.baseObject.l);
	      buffer_puts(buffer_2,"\", scope ");
	      buffer_puts(buffer_2,scopes[sr.scope]);
	      buffer_puts(buffer_2,", ");
	      buffer_puts(buffer_2,alias[sr.derefAliases]);
	      buffer_puts(buffer_2,"\nsize limit ");
	      buffer_putulong(buffer_2,sr.sizeLimit);
	      buffer_puts(buffer_2,", time limit ");
	      buffer_putulong(buffer_2,sr.timeLimit);
	      buffer_puts(buffer_2,"\n");
	      printfilter(sr.filter);
	      buffer_puts(buffer_2,"attributes: ");
	      printal(sr.attributes);
	      buffer_putsflush(buffer_2,"\n\n");
	    }
#endif
	    fixup(sr.filter);
	    fixupadl(sr.attributes);
	    if (indexable(sr.filter)) {
	      reply_with_index(&sr,&messageid,out);
	    } else {
	      const char* x=map+5*4+size_of_string_table+attribute_count*8;
	      size_t i;
#if (debug != 0)
	      if (debug) buffer_putsflush(buffer_2,"query can NOT be answered with index!\n");
#endif
	      for (i=0; i<record_count; ++i) {
		uint32 j;
		uint32_unpack(x,&j);
		if (ldap_match_mapped(x-map,&sr)) {
		  if (sr.sizeLimit && sr.sizeLimit<++returned)
		    break;
		  answerwith(x-map,&sr,messageid,out);
		}
		x+=j*8;
	      }
	    }

	    /* now answer with the results from the journal */
	    answerwithjournal(&sr,messageid,out);
	    free_ldapsearchrequest(&sr);
	  } else {
	    buffer_putsflush(buffer_2,"couldn't parse search request!\n");
	    exit(1);
	  }
	  {
	    char buf[1000];
	    size_t l=fmt_ldapsearchresultdone(buf+100,0,"","","");
	    size_t hlen=fmt_ldapmessage(0,messageid,SearchResultDone,l);
	    fmt_ldapmessage(buf+100-hlen,messageid,SearchResultDone,l);
	    write(out,buf+100-hlen,l+hlen);
	  }
	}
	break;
      case UnbindRequest:
	close(out); if (in!=out) close(in);
	return 0;
      case ModifyRequest:
	{
	  struct ModifyRequest mr;
	  size_t tmp,err=success;
	  buffer_putsflush(buffer_2,"modifyrequest!\n");
	  if ((tmp=scan_ldapmodifyrequest(buf+res,buf+len,&mr))) {
	    struct SearchResultEntry sre;
	    if (verbose) {
	      buffer_puts(buffer_1,"modify request: dn \"");
	      buffer_put(buffer_1,mr.object.s,mr.object.l);
	      buffer_putsflush(buffer_1,"\"\n");
	      switch (mr.m.operation) {
	      case 0: buffer_puts(buffer_1,"Add\n"); break;
	      case 1: buffer_puts(buffer_1,"Delete\n"); break;
	      case 2: buffer_puts(buffer_1,"Replace\n"); break;
	      }
	      buffer_put(buffer_1,mr.m.AttributeDescription.s,mr.m.AttributeDescription.l);
	      buffer_puts(buffer_1,"\n");
	      {
		struct AttributeDescriptionList* x=mr.m.vals;
		do {
		  buffer_puts(buffer_1," -> \"");
		  buffer_put(buffer_1,x->a.s,x->a.l);
		  buffer_putsflush(buffer_1,"\"\n");
		  x=x->next;
		} while (x);
	      }
	    }

	    normalize_string_dn(&mr.object);

	    if (acls) {
	      /* convert modifyrequest to searchresultentry */
	      modreq2sre(&sre,&mr);
	      /* 1. check ACLs */
	      if (checkacl(0,0,acl_write,&sre)!=1)
		err=insufficientAccessRights;
	      free_ldapsearchresultentry(&sre);
	    } else
	      err=insufficientAccessRights;
	    if (err==success) {
	      /* 2. check if there already is a record with this dn */
	      struct hashnode* hn;
	      size_t idx;
	      switch (lookupdn(&mr.object,&idx,&hn)) {
	      case -1: err=operationsError; break;
	      case 1: break;
	      case 0: err=noSuchObject; break;
	      default: err=operationsError;
	      }
	      if (err==success) {
#if 1
		/* 3. apply modifications to record to get new record */
		struct hashnode* h;
		if (hn)
		  h=hn;
		else
		  h=load_record_into_hashnode(idx);
		if (!h) {
		  err=operationsError;	// can't happen
		  goto modreqerror;
		}
		if (!applymodreq(h,&mr,&sre)) {
		  /* 4. write record to journal */
		  int fd=open(journalfilename,O_WRONLY|O_APPEND|O_CREAT,0600);
		  if (fd==-1)
		    err=operationsError;
		  else {
		    if (writesretofd(fd,&sre)==-1)
		      err=operationsError;
		    close(fd);
		  }
		} else
		  err=operationsError;
		if (h != hn) free(h);
modreqerror:
		free_ldapsearchresultentry(&sre);
#else
		err=operationsError;
#endif
	      }
	    }
	  } else {
	    buffer_putsflush(buffer_2,"could not parse modifyRequest!\n");
	    err=protocolError;
	  }

	  {
	    char outbuf[1024];
	    int s=100;
	    int len=fmt_ldapresult(outbuf+s,err,"","","");
	    int hlen=fmt_ldapmessage(0,messageid,ModifyResponse,len);
	    fmt_ldapmessage(outbuf+s-hlen,messageid,ModifyResponse,len);
	    write(out,outbuf+s-hlen,len+hlen);
	  }

	  free_ldapmodifyrequest(&mr);
	}
	break;
      case AbandonRequest:
	if (verbose) buffer_putsflush(buffer_2,"AbandonRequest!\n");
	/* do nothing */
	break;
      case AddRequest:
        {
	  int err=success;
	  struct AddRequest ar;
//          buffer_putsflush(buffer_2,"AddRequest!\n");
          if ((tmp=scan_ldapaddrequest(buf+res,buf+len,&ar))) {
	    struct SearchResultEntry sre;
	    normalize_string_dn(&ar.entry);
	    /* convert addrequest to searchresultentry */
	    addreq2sre(&sre,&ar);

	    /* 1. check ACLs */
	    if (checkacl(0,0,acl_add,&sre)==1) {
	      /* 2. check if there already is a record with this dn */
	      struct hashnode* hn;
	      size_t idx;
	      switch (lookupdn(&sre.objectName,&idx,&hn)) {
	      case -1: err=operationsError; break;
	      case 1: err=entryAlreadyExists; break;
	      case 0: break;
	      default: err=operationsError;
	      }
	      if (err==success) {
		/* 3. write record to journal */
		int fd=open(journalfilename,O_WRONLY|O_APPEND|O_CREAT,0600);
		if (fd==-1)
		  err=operationsError;
		else {
		  if (writesretofd(fd,&sre)==-1)
		    err=operationsError;
		  close(fd);
		}
	      }
	    } else
	      err=insufficientAccessRights;

#ifdef DEBUG
	    buffer_put(buffer_1,ar.entry.s,ar.entry.l);
	    buffer_putsflush(buffer_1,"\n");
	    if (verbose) { /* iterate all attributes */
	      struct Addition * x;
	      struct AttributeDescriptionList * y;
	      for (x = &ar.a;x;x=x->next) {
		for (y = &x->vals;y;y=y->next) {
		  buffer_put(buffer_1,x->AttributeDescription.s,x->AttributeDescription.l);
		  buffer_puts(buffer_1,": ");
		  buffer_put(buffer_1,y->a.s,y->a.l);
		  buffer_putsflush(buffer_1,"\n");
		}
	      }
	    }
#endif

	    free_ldapaddrequest(&ar);
	  } else
	    err=protocolError;

	  {
	    char outbuf[1024];
	    size_t s=100;
	    size_t len=fmt_ldapresult(outbuf+s,err,"","","");
	    size_t hlen=fmt_ldapmessage(0,messageid,AddResponse,len);
	    fmt_ldapmessage(outbuf+s-hlen,messageid,AddResponse,len);
	    write(out,outbuf+s-hlen,len+hlen);
	  }
	}
	break;
      case DelRequest:
	{
	  struct string s;
	  size_t l=scan_ldapdeleterequest(buf+res,buf+len,&s);
	  if (l>0) {
	    struct SearchResultEntry sre;
	    int err=success;
	    if (verbose) {
	      buffer_puts(buffer_2,"Delete Request for DN \"");
	      buffer_put(buffer_2,s.s,s.l);
	      buffer_putsflush(buffer_2,"\".\n");
	    }
	    normalize_string_dn(&s);
	    /* convert modifyrequest to searchresultentry */
	    sre.objectName=s;
	    sre.attributes=0;
	    /* 1. check ACLs */
	    if (checkacl(0,0,acl_delete,&sre)!=1)
	      err=insufficientAccessRights;
	    if (err==success) {
	      /* 2. check if there is a record with this dn */
	      struct hashnode* hn;
	      size_t idx;
	      switch (lookupdn(&s,&idx,&hn)) {
	      case -1: err=operationsError; break;
	      case 1: break;
	      case 0: err=noSuchObject; break;
	      default: err=operationsError;
	      }
	      if (err==success) {
		/* 3. write record to journal */
		int fd=open(journalfilename,O_WRONLY|O_APPEND|O_CREAT,0600);
		if (fd==-1)
		  err=operationsError;
		else {
		  if (writesretofd(fd,&sre)==-1)
		    err=operationsError;
		  close(fd);
		}
	      }
	    }
	    {
	      char outbuf[1024];
	      size_t s=100;
	      size_t len=fmt_ldapresult(outbuf+s,err,"","","");
	      size_t hlen=fmt_ldapmessage(0,messageid,DelResponse,len);
	      fmt_ldapmessage(outbuf+s-hlen,messageid,DelResponse,len);
	      write(out,outbuf+s-hlen,len+hlen);
	    }
	  }
	}
	break;
      case ModifyDNRequest:
	/* TODO */
      default:
	buffer_puts(buffer_2,"unknown request type ");
	buffer_putulong(buffer_2,op);
	buffer_putsflush(buffer_2,"\n");
	return 0;
//	exit(1);
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



/* journal reading code */

extern int (*ldif_parse_callback)(struct ldaprec* l);

extern mstorage_t stringtable;
extern mduptab_t attributes,classes;

static unsigned long hash2(const unsigned char* c) {
  unsigned long h=0;
  if (*c==0) {
    uint32 len=uint32_read((char*)c+1);
    return hash(c+5,len);
  }
  while (*c) {
    /* from djb's cdb */
    h += (h<<5);
    h ^= *c;
    ++c;
  }
  return (uint32)h;
}

#define HASHTABSIZE 8191

static unsigned char* bstrdup(unsigned char* c) {
  size_t len;
  unsigned char* x;
  if (*c)
    len=str_len((char*)c)+1;
  else {
    len=5+uint32_read((char*)c+1);
    if (len<5) return 0;
  }
  x=malloc(len);
  if (x) byte_copy(x,len,c);
  return x;
}

static unsigned char* bstrdup_attrib(unsigned char* c) {
  const char* x=map+5*4+size_of_string_table;
  size_t i,l;
  if (*c)
    l=str_len((char*)c)+1;
  else {
    l=uint32_read((char*)c+1);
    c+=5;
  }
  for (i=0; i<attribute_count; ++i) {
    uint32 j=uint32_read(x);
    if (case_equalb(c,l,map+j))
      return (unsigned char*)map+j;
    x+=4;
  }
  return bstrdup(c);
}

struct hashnode* hashtab[HASHTABSIZE];

static struct hashnode** dn_in_journal(unsigned char* dn) {
  unsigned long hashval;
  struct hashnode** hn;
  hashval=hash2(dn);
  hn=hashtab+(hashval%HASHTABSIZE);
  while (*hn) {
    if ((*hn)->hashval==hashval) {
      if (!bstr_diff((char*)(*hn)->dn,(char*)dn))
	break;
    }
    hn=&((*hn)->next);
  }
  return hn;
}

static struct hashnode** dn_in_journal2(const char* dn,size_t dnlen) {
  unsigned long hashval;
  struct hashnode** hn;
  hashval=hash((const unsigned char*)dn,dnlen);
//  printf("lookup: \"%.*s\" -> %lu\n",dnlen,dn,hashval);
  hn=hashtab+(hashval%HASHTABSIZE);
  while (*hn) {
    if ((*hn)->hashval==hashval) {
      if (!bstr_diff2((char*)(*hn)->dn,dn,dnlen))
	break;
    }
    hn=&((*hn)->next);
  }
  return hn;
}

struct hashnode* root;

static int parse_callback(struct ldaprec* l) {
  static struct hashnode** nextinlinearlist=&root;
  size_t i;
  unsigned long hashval;
  struct hashnode** hn;
  if (l->dn==(uint32)-1)
    return -1;
  hashval=hash2((unsigned char*)stringtable.root+l->dn);
//  printf("journal: \"%s\" -> %lu\n",stringtable.root+l->dn,hashval);
  hn=hashtab+(hashval%HASHTABSIZE);
  while (*hn) {
    if ((*hn)->hashval==hashval) {
      if (!bstr_diff((char*)(*hn)->dn,stringtable.root+l->dn))
	break;
    }
    hn=&((*hn)->next);
  }
  if (*hn) {
    /* a record with this dn exists */
    /* adjust it to the new reality */
    for (i=0; i<(*hn)->n; ++i) {
      free((*hn)->a[i].a);
      free((*hn)->a[i].v);
    }
    *hn = realloc(*hn,sizeof(**hn)-sizeof(struct attribute2)+l->n*sizeof(struct attribute2));
    if (!*hn) nomem: die(1,"out of memory!");
  } else {
    *hn = malloc(sizeof(**hn)-sizeof(struct attribute2)+l->n*sizeof(struct attribute2));
    if (!*hn) goto nomem;
    if (!((*hn)->dn=bstrdup((unsigned char*)stringtable.root+l->dn))) goto nomem;
    (*hn)->hashval=hashval;
    (*hn)->next=0;

    (*hn)->overwrite=0;
    /* put new entry in the linear list */
    *nextinlinearlist=*hn;
    (*hn)->linear=0;
    nextinlinearlist=&(*hn)->linear;
  }
  (*hn)->n=l->n;
  for (i=0; i<l->n; ++i) {
    if (!((*hn)->a[i].a=bstrdup_attrib((unsigned char*)attributes.strings.root+l->a[i].name)) ||
	!((*hn)->a[i].v=bstrdup((unsigned char*)((*hn)->a[i].a==(unsigned char*)map+objectClass_ofs?classes.strings.root:stringtable.root)+l->a[i].value))) goto nomem;
  }
  stringtable.used=0;
  return 0;
}

static void readjournal() {
  ldif_parse_callback=parse_callback;
  mduptab_init(&attributes);
  mduptab_init(&classes);
  if (ldif_parse(journalfilename,0,&ss_journal)) {
    buffer_putsflush(buffer_2,"Failed to parse journal!\n");
    exit(1);
  }
}

static void update() {
  struct stat new_data,new_journal;
  if (stat(datafilename,&new_data)==-1) {
    /* no data file?!  There is no way to salvage the situation. */
    buffer_putsflush(buffer_2,"ABEND: data file suddenly gone.\n");
    exit(1);
  }
  /* now see if the data file changed.  If it did, map it anew. */
  if (new_data.st_size!=ss_data.st_size ||
      new_data.st_mtime!=ss_data.st_mtime ||
      new_data.st_ino!=ss_data.st_ino) {
    buffer_putsflush(buffer_2,"Data file changed, reloading.\n");
    mmap_unmap(map,filelen);
    /* If the new data file is corrupt, map_datafile calls exit.
     * I don't believe in limping on.  If something is broken on such a fundamental level,
     * it's better to bail so that the problem does not go unnoticed and things get even
     * worse. */
    map_datafile(datafilename);
    /* OK, now that we have the datafile reloaded, we need to clean our idea of a journal
     * and reload the journal from scratch. */
resetjournal:
    mduptab_reset(&attributes);
    mduptab_reset(&classes);
    readjournal();
    return;
  }
  /* the data file did not change.  Maybe the journal did. */
  if (stat(journalfilename,&new_journal)==-1) {
    /* no journal; that means:
     * a) there never was one, totaly read-only data
     * b) there was one, but it has now been incorporated into the main database
     *    in this case: delete journal data
     */
    mduptab_reset(&attributes);
    mduptab_reset(&classes);
    return;
  }
  if (new_journal.st_size!=ss_journal.st_size ||
      new_journal.st_mtime!=ss_journal.st_mtime ||
      new_journal.st_ino!=ss_journal.st_ino) {
    /* Journal changed.  Since all we ever do is append, we just read the part from how
     * far we got last time, which happens to be ss_journal.st_size. */

    /* On the other hand, we should make a valiant effort to not break if someone edits
     * his journal manually. After all, that's why our journal is in text form.
     * We look for two clues that someone edited his journal:
     *   1. size is identical or smaller
     *   2. journal does not end with "\n\n"
     * If we detect meddling we just throw away our journal and read the new one. */
    int notkosher=0;
    if (new_journal.st_size>ss_journal.st_size && ss_journal.st_size>2) {
      int fd;
      fd=open(journalfilename,O_RDONLY);
      if (fd!=-1) {
	char buf[2];
	lseek(fd,ss_journal.st_size-2,SEEK_SET);
	if (read(fd,buf,2)!=2) 
	  if (buf[0]=='\n' && buf[1]=='\n')
	    notkosher=1;
	close(fd);
      }
    }
    if (notkosher) {
      buffer_putsflush(buffer_2,"Unsanctioned journal editing detected!  Re-reading journal.\n");
      goto resetjournal;
    }
    if (ldif_parse(journalfilename,ss_journal.st_size,&ss_journal)) {
      buffer_putsflush(buffer_2,"Failed to parse journal!\n");
      exit(1);
    }
    ss_data=new_data;
  }
}

static int ldap_matchfilter_hn(struct hashnode* hn,struct Filter* f) {
  struct Filter* y=f->x;
  size_t i;
  if (!hn->n) return 0;
  if (!f) return 1;
  switch (f->type) {
  case AND:
    while (y) {
      if (!ldap_matchfilter_hn(hn,y)) return 0;
      y=y->next;
    }
    return 1;
  case OR:
    while (y) {
      if (ldap_matchfilter_hn(hn,y)) return 1;
      y=y->next;
    }
    return 0;
  case NOT:
    return !ldap_matchfilter_hn(hn,y);
  case PRESENT:
    if (f->attrofs==dn_ofs)
      return 1;
    for (i=0; i<hn->n; ++i)
      if (!matchstring(&f->ava.desc,(char*)hn->a[i].a))
	return 1;
    return 0;
  case EQUAL:
  case LESSEQUAL:
  case GREATEQUAL:
    if (f->attrofs==dn_ofs)
      return matchint(f,(char*)hn->dn);
    for (i=0; i<hn->n; ++i)
      if (!matchstring(&f->ava.desc,(char*)hn->a[i].a) &&
	  matchint(f,(char*)hn->a[i].v)) return 1;
    return 0;
  case SUBSTRING:
    if (f->attrofs==dn_ofs)
      return substringmatch(f->substrings,(char*)hn->dn,f->attrflag&1);
    for (i=0; i<hn->n; ++i)
      if (!matchstring(&f->ava.desc,(char*)hn->a[i].a) &&
	  substringmatch(f->substrings,(char*)hn->a[i].v,f->attrflag&1)) return 1;
    return 0;
  default:
    write(2,"unsupported query type\n",23);
    return 0;
  }
  return 1;
}

/* return 0 if they didn't match, otherwise return length in b */
static int match(const char* a,int len,const char* b) {
  const char* A=a+len;
  const char* B=b+str_len(b);
  while (len>0 && A>a && B>b) {
    --A; --B; --len;
    while (*A==' ' && A>a) { --A; --len; }
    while (*B==' ' && B>b) --B;
    if (tolower(*A) != tolower(*B))
      return 0;
  }
  return str_len(B);
}

static int matchhashnode(struct hashnode* hn,struct SearchRequest* sr) {
  size_t i,len=bstrlen((char*)hn->dn);
  unsigned char* c;
  if (sr->baseObject.l>len)
    /* baseObject is longer than dn */
    return 0;
  if (sr->baseObject.l && !match(sr->baseObject.s,sr->baseObject.l,(char*)hn->dn))
    /* baseObject is not a suffix of dn */
    return 0;
  switch (sr->scope) {
  case wholeSubtree: break;
  case baseObject: if (len==sr->baseObject.l) break; return 0;
  default:
    c=hn->dn+bstrstart((char*)hn->dn);
    for (i=0; i<len; ++i)
      if (c[i]==',')
	break;
    if (i+2>=len-sr->baseObject.l) break;
    return 0;
  }
  return ldap_matchfilter_hn(hn,sr->filter);
}

static void answerwith_hn(struct hashnode* hn,struct SearchRequest* sr,long messageid,int out) {
  struct SearchResultEntry sre;
  struct PartialAttributeList** pal=&sre.attributes;

  if (!hn->n) return;
  if (acls)
    byte_zero(acl_ec_subjects+filters,filters);

  if (acls && checkacl_hn(hn,(unsigned char*)map+dn_ofs,acl_read)!=1) return;

  sre.objectName.l=bstrlen(sre.objectName.s=(char*)hn->dn);
  sre.attributes=0;

  /* now go through list of requested attributes */
  {
    struct AttributeDescriptionList* adl=sr->attributes;
    if (!adl && hn->n && hn->n<HUGE_SIZE_FOR_SANITY_CHECKS/sizeof(*adl)) {
      /* did not ask for any attributes.  send 'em all. */
      /* to do that, construct a list of all attributes */

      uint32 i,j,k;
      adl=alloca(hn->n*sizeof(*adl));
      for (i=k=0; i<hn->n; ++i) {
	adl[k].a.s=(char*)hn->a[i].a;
	adl[k].a.l=str_len((char*)hn->a[i].a);
	adl[k].attrofs=0;
	adl[k].next=adl+k+1;
	for (j=0; j<i; ++j) {
	  if (!strcmp((char*)hn->a[i].a,(char*)hn->a[j].a)) {
	    --k;
	    break;
	  }
	}
	++k;
      }
      if (k) adl[k-1].next=0;
    }
    while (adl) {
      const unsigned char* val=0;
      uint32 i=0;

      if (!acls || checkacl_hn(hn,(unsigned char*)adl->a.s,acl_read)==1) {
	if (!matchstring(&adl->a,"dn"))
	  val=hn->dn;
	else {
	  for (; i<hn->n; ++i)
	    if (!matchstring(&adl->a,(char*)hn->a[i].a)) {
	      val=hn->a[i].v;
	      ++i;
	      break;
	    }
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
	    struct AttributeDescriptionList** a;
	    a=&(*pal)->values;
add_attribute:
	    *a=malloc(sizeof(struct AttributeDescriptionList));
	    if (!*a) goto nomem;
	    (*a)->a.s=bstrfirst((char*)val);
	    (*a)->a.l=bstrlen((char*)val);
	    for (;i<hn->n; ++i)
	      if (!matchstring(&adl->a,(char*)hn->a[i].a)) {
		val=hn->a[i].v;
		++i;
		a=&(*a)->next;
		goto add_attribute;
	      }
	    (*a)->next=0;
	  }
	  (*pal)->next=0;
	  pal=&(*pal)->next;
	}
      }
      adl=adl->next;
    }
  }
  {
    long l=fmt_ldapsearchresultentry(0,&sre);
    char *buf;
    long tmp;
    if (l<HUGE_SIZE_FOR_SANITY_CHECKS) {
      buf=alloca(l+300); /* you never know ;) */
      if (verbose) {
	buffer_puts(buffer_2,"sre len ");
	buffer_putulong(buffer_2,l);
	buffer_putsflush(buffer_2,".\n");
      }
      tmp=fmt_ldapmessage(buf,messageid,SearchResultEntry,l);
      fmt_ldapsearchresultentry(buf+tmp,&sre);
      write(out,buf,l+tmp);
    }
  }
  free_ldappal(sre.attributes);
}

static void answerwithjournal(struct SearchRequest* sr,long messageid,int out) {
  struct hashnode* hn=root;
  while (hn) {
    if (!hn->overwrite && matchhashnode(hn,sr))
      answerwith_hn(hn,sr,messageid,out);
    hn=hn->linear;
  }
}

#if !defined(NO_SECCOMP) && defined(__linux__) && (defined(__i386__) || defined(__x86_64__)) && !defined(STANDALONE)
#define SECCOMP
#endif
#ifdef SECCOMP

#include <sys/prctl.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
# define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
# define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
# define SECCOMP_RET_ERRNO	0x00050000U /* returns an errno */
# define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */
struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};
#endif
#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#define syscall_nr (offsetof(struct seccomp_data, nr))

#if defined(__i386__)
# define REG_SYSCALL	REG_EAX
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define REG_SYSCALL	REG_RAX
# define ARCH_NR	AUDIT_ARCH_X86_64
#else
# error "Platform does not support seccomp filter yet"
#endif

#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

static int install_syscall_filter(void) {
  /* Linux allows a process to restrict itself (and potential children)
   * in what syscalls can be issued.  The mechanism is called
   * seccomp-filter or "seccomp mode 2".  It works by reusing the
   * Berkeley Packet Filter, which is meant for PCAP-style packet
   * filtering expressions like "only TCP packets, please".  But it is
   * really a bytecode that has to be passed inside an array, and each
   * instruction is constructed using scary looking macros.  The basics
   * are not so bad, however.  We have two registers, one accumulator
   * and one index register (which is not used in this part of the
   * code), and instead of a network packet we are operating on a
   * certain struct with the syscall info, which is called seccomp_data
   * (reproduced above). */
  struct sock_filter filter[] = {
    /* validate architecture to avoid x32-on-x86_64 syscall aliasing shenanigans */

    /* BPF_LD = load, BPF_W = word, BPF_ABS = absolute offset */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    /* BPF_JMP+BPF_JEQ+BPF_K = compare accumulator to constant (in our
     * case, ARCH_NR), and skip the next instruction if equal */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
    /* "return SECCOMP_RET_KILL", tell seccomp to kill the process */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    /* load the syscall number */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* and now a list of allowed syscalls */
    ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
    ALLOW_SYSCALL(sigreturn),
#endif
    ALLOW_SYSCALL(exit_group),
    ALLOW_SYSCALL(exit),

    ALLOW_SYSCALL(read),
    ALLOW_SYSCALL(write),

    /* we need a special case for open.
     * we want open to succeed, but only if it's on the journal */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 10),
    /* it's open(2). Accept if mode == O_RDONLY or mode has O_APPEND */
    /* load mode */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
    /* & O_ACCMODE */
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_ACCMODE),
    /* if (mode & O_ACCMODE) == O_RDONLY */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_RDONLY, 5, 0),
    /* only let write access through with O_APPEND */
    /* load mode again */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
    /* & O_APPEND */
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_APPEND),
    /* if (mode & O_APPEND) == O_APPEND */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_APPEND, 0, 3),
    /* load name */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[0])),
    /* if (name == journalfilename) */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t)journalfilename, 0, 1),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
    /* otherwise kill the process */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

#ifdef __GLIBC__
    /* glibc switched to openat instead of open */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 10),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[2])),
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_ACCMODE),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_RDONLY, 5, 0),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[2])),
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, O_APPEND),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, O_APPEND, 0, 3),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t)journalfilename, 0, 1),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    ALLOW_SYSCALL(newfstatat),
#endif

    ALLOW_SYSCALL(close),

    /* for syslog() */
#ifdef __NR__llseek
    ALLOW_SYSCALL(_llseek),
#else
    ALLOW_SYSCALL(lseek),
#endif
#ifdef __NR_fstat64
    ALLOW_SYSCALL(fstat64),
    ALLOW_SYSCALL(stat64),
#else
    ALLOW_SYSCALL(fstat),
    ALLOW_SYSCALL(stat),
#endif

    /* for reading from the socket */
#ifdef DEBUG
    ALLOW_SYSCALL(poll),
#endif

#ifdef __NR__ftruncate64
    ALLOW_SYSCALL(ftruncate64),
#endif
    ALLOW_SYSCALL(ftruncate),

    /* for malloc / calloc */
#ifdef __dietlibc__
    ALLOW_SYSCALL(mmap),
#else
    ALLOW_SYSCALL(brk),
    ALLOW_SYSCALL(mmap),
#endif
    ALLOW_SYSCALL(mremap),
    ALLOW_SYSCALL(munmap),

#ifdef __NR_socketcall
    ALLOW_SYSCALL(socketcall),
#endif
#ifdef __NR_setsockopt
    ALLOW_SYSCALL(setsockopt),
#endif

    /* if none of these syscalls matched, kill the process */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter
  };

  /* see linux/Documentation/prctl/no_new_privs.txt */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    /* if this fails, we are running on an ancient kernel without
     * seccomp support; nothing we can do about it, really. */
    return -1;
  }

  /* see linux/Documentation/prctl/seccomp_filter.txt */
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    /* if this happens, we are running on a kernel without seccomp
     * filters support; nothing we can do about it, really. */
    return -1;
  }
  return 0;
}
#endif

/*
                 _
 _ __ ___   __ _(_)_ __
| '_ ` _ \ / _` | | '_ \
| | | | | | (_| | | | | |
|_| |_| |_|\__,_|_|_| |_|
*/

int main(int argc,char* argv[]) {
#ifdef STANDALONE
  int sock;
#endif

#if defined(STANDALONE) || defined(DEBUG)
  uid_t u=-1;
  gid_t g=-1;
  {
    const char* user=getenv("UID");
    if (user) {
      const char* group=getenv("GID");
      unsigned long ul;
      if (scan_ulong(user,&ul))
	u=ul;
      if (group) {
	if (scan_ulong(group,&ul))
	  g=ul;
      } else {
	struct passwd* p=getpwuid(u);
	if (p) g=p->pw_gid;
      }
    } else if ((user=getenv("USER"))) {
      struct passwd *p=getpwnam(user);
      if (p) {
	u=p->pw_uid;
	g=p->pw_gid;
      }
    }
  }
#endif

  {
    const char* os=getenv("ONESHOT");
    if (os && isdigit(*os))
      oneshot=*os-'0';
  }

  errmsg_iam("tinyldap");

  signal(SIGPIPE,SIG_IGN);

  map_datafile(argc>1?argv[1]:"data");

#ifdef SECCOMP
  install_syscall_filter();
#endif

  // first opportunity to get exploited by evil input
  // so do this after installing the seccomp filter
  readjournal();

#if 0
  ldif_parse("exp.ldif");
  if (!first) {
    buffer_putsflush(buffer_2,"no data?!");
  }
#endif

#ifdef STANDALONE
  if ((sock=socket_tcp6b())==-1) {
    buffer_putsflush(buffer_2,"socket failed!\n");
    exit(1);
  }
  {
    char ip[16];
    char* IP=(char*)V6any;
    char* x=getenv("IP");
    const char* Port=getenv("PORT");
    unsigned long port=389;
    if (Port && Port[scan_ulong(Port,&port)])
      port=389;
    if (port<1 || port>65535) port=389;
    if (x && !x[scan_ip6(x,ip)])
      IP=ip;
    if (socket_bind6_reuse(sock,IP,port,0)) {
      buffer_putsflush(buffer_2,"bind failed!\n");
      exit(1);
    }
  }

  if (setresgid(g,g,g) || setresuid(u,u,u)) {
    buffer_putsflush(buffer_2,"setresgid/setresuid failed!\n");
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
#ifdef DEBUG
again:
#endif
    asock=socket_accept6(sock,ip,&port,&scope_id);
    if (asock==-1) {
      buffer_putsflush(buffer_2,"accept failed!\n");
      exit(1);
    }
    {
      int one=1;
      setsockopt(asock,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
    }
    update();
#ifdef DEBUG
    {
      struct pollfd p;
      p.fd=0;
      p.events=POLLIN;
      if (poll(&p,1,1)==1) return 0;
    }
    handle(asock,asock);
    goto again;
//    exit(0);
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
  {
    int one=1;
    setsockopt(1,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
  }
  handle(0,1);
#endif
  _exit(0);	// glibc does some bizarre shit after main that trips our seccomp jail, like getpid, gettid, prctl
}

/* vim:tw=90:
 */
