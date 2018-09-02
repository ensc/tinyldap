#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <libowfat/buffer.h>
#include <libowfat/mmap.h>
#include <libowfat/uint32.h>
#include "mstorage.h"
#include <libowfat/errmsg.h>
#include <ctype.h>
#include <stdlib.h>

#include <stdio.h>

mstorage_t idx;
char* map;

int compar(const void* a,const void* b) {
  int i;
  if ((i=strcmp(map+*(uint32*)a,map+*(uint32*)b)))
    return i;
  else
    return *(uint32*)b-*(uint32*)a;
}

int compari(const void* a,const void* b) {
  int i;
  if ((i=strcasecmp(map+*(uint32*)a,map+*(uint32*)b)))
    return i;
  else
    return *(uint32*)b-*(uint32*)a;
}

uint32 hash(const unsigned char* c,unsigned long keylen) {
  unsigned long h=0;
  unsigned long i;
  for (i=0; i<keylen; ++i) {
    /* from djb's cdb */
    h += (h<<5);
    h ^= c[i];
  }
  return (uint32)h;
}

uint32 hash_tolower(const unsigned char* c,unsigned long keylen) {
  unsigned long h=0;
  unsigned long i;
  for (i=0; i<keylen; ++i) {
    /* from djb's cdb */
    h += (h<<5);
    h ^= tolower(c[i]);
  }
  return (uint32)h;
}

uint32 hashmapped(uint32 ofs,int ignorecase) {
  unsigned char* c=(unsigned char*)map+ofs;
  uint32 len;
  if (*c) return ignorecase?hash_tolower(c,strlen((char*)c)):hash(c,strlen((char*)c));
  uint32_unpack((char*)c+1,&len);
  return ignorecase?hash_tolower(c+5,len):hash(c+5,len);
}

int main(int argc,char* argv[]) {
  enum { SORTEDTABLE, HASHTABLE } mode;
  size_t filelen;
  char* filename=argv[1];
  const char* lookfor=argv[2];
  uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;
  uint32 wanted,casesensitive,dn,objectClass;
  int ignorecase,fastindex,onlywithpassword;

  ignorecase=fastindex=onlywithpassword=0;

  errmsg_iam("addindex");
  mstorage_init(&idx);

  if (argc<3) {
    buffer_putsflush(buffer_2,"usage: ./addindex filename attribute [i][f][h]\n"
		     "if i is present, make index case insensitive.\n"
		     "if f is present, make index twice as large, but quicker.\n"
		     "if h is present, make it a hash index (only accelerates direct lookups)\n"
		     "if u is present with h, only hash entries with userPassword\n");
    return 1;
  }

  mode=SORTEDTABLE;
  if (argc>3) {
    if (strchr(argv[3],'i')) ignorecase=1;
    if (strchr(argv[3],'f')) fastindex=1;
    if (strchr(argv[3],'h')) mode=HASHTABLE;
    if (strchr(argv[3],'u')) onlywithpassword=1;
  }

  if (mode!=HASHTABLE && onlywithpassword)
    die(111,"u only implemented with h\n");

  if (onlywithpassword && strcmp(lookfor,"dn"))
    die(111,"u only works if attribute is dn\n");

  if (onlywithpassword)
    lookfor="userPassword";

  map=(char*)mmap_read(filename,&filelen);
  if (!map)
    diesys(111,"Could not open \"",filename,"\"");
  uint32_unpack(map,&magic);
  if (magic!=0xfefe1da9)
    die(111,"File format not recognized (invalid magic)!\n");
  uint32_unpack(map+4,&attribute_count);
  uint32_unpack(map+2*4,&record_count);
  uint32_unpack(map+3*4,&indices_offset);
  uint32_unpack(map+4*4,&size_of_string_table);

  {
    unsigned int i;
    const char* x=map+5*4+size_of_string_table;
    wanted=casesensitive=dn=objectClass=0;
    for (i=0; i<attribute_count; ++i) {
      uint32 j;
      uint32_unpack(x,&j);
//      buffer_puts(buffer_1,map+j); buffer_putsflush(buffer_1,"\n");
      if (!strcasecmp(map+j,"dn")) dn=j;
      if (!strcasecmp(map+j,"objectClass")) objectClass=j;
      if (!strcasecmp(map+j,lookfor)) {
//	buffer_putsflush(buffer_2,"found attribute!\n");
	wanted=j; casesensitive=x+attribute_count*4-map;
	uint32_unpack(map+casesensitive,&j);
	if (j)
	  die(1,"Case sensitivity flag is nonzero!?");
      }
      x+=4;
    }
    if (!wanted)
      die(1,"That attribute is not in the database.");
    if (!dn || !objectClass)
      die(1,"dn or objectClass not found.");
  }

  if (mode==SORTEDTABLE) {
    uint32 i,counted=0;
    const char* x=map+5*4+size_of_string_table+attribute_count*8;
    for (i=0; i<record_count; ++i) {
      uint32 j,k;
      uint32_unpack(x,&j);
      if (wanted==dn) {
	uint32_unpack(x+8,&k);
	mstorage_add(&idx,(char*)&k,4);
	if (fastindex)
	  mstorage_add(&idx,(char*)&i,4);
	++counted;
	x+=j*8;
      } else {
	if (wanted==objectClass) {
	  uint32_unpack(x+12,&k);
	  mstorage_add(&idx,(char*)&k,4);
	  if (fastindex)
	    mstorage_add(&idx,(char*)&i,4);
	  ++counted;
	}
	x+=16;
	for (; j>2; --j) {
	  uint32_unpack(x,&k);
	  if (k==wanted) {
	    uint32_unpack(x+4,&k);
	    mstorage_add(&idx,(char*)&k,4);
	    if (fastindex)
	      mstorage_add(&idx,(char*)&i,4);
	    ++counted;
	  }
	  x+=8;
	}
      }
    }
    buffer_putulong(buffer_1,counted);
    buffer_putsflush(buffer_1," entries to be sorted...");
    if (ignorecase)
      qsort(idx.root,counted,4*(fastindex+1),compari);
    else
      qsort(idx.root,counted,4*(fastindex+1),compar);
    buffer_putsflush(buffer_1," done.\n");
    munmap(map,filelen);
    {
      int fd=open(filename,O_RDWR);
      if (fd<0)
	diesys(111,"Could not re-open database file read-write");
      ftruncate(fd,filelen+3*4+counted*4*(fastindex+1));
      map=mmap(0,filelen+(counted+3)*4*(fastindex+1),PROT_WRITE,MAP_SHARED,fd,0);
      if (map==(char*)-1)
	diesys(111,"Could not mmap database file read-write");
      uint32_pack(map+casesensitive,ignorecase);
      uint32_pack(map+filelen,fastindex);
      uint32_pack(map+filelen+4,filelen+3*4+counted*4*(fastindex+1));
      uint32_pack(map+filelen+8,wanted);
      {
	char* x=map+filelen+12;
	unsigned long i;
	for (i=0; i<counted; ++i) {
	  uint32_pack(x,((uint32*)idx.root)[i<<fastindex]);
	  x+=4;
	}
	if (fastindex) {
	  /* index type 1 also saves the record number for each table
	   * entry.  Since normal searches will bsearch over the offsets
	   * and only then ask for the record number, we try to be cache
	   * friendly and save one table with the offsets and one table
	   * with the record numbers, instead of one table with tuples. */
	  for (i=0; i<counted; ++i) {
	    uint32_pack(x,((uint32*)idx.root)[i*2+1]);
	    x+=4;
	  }
	}
      }
    }
  } else if (mode==HASHTABLE) {
    uint32 i,j,counted,cur;
    char* x;
    struct node {
      uint32 recnum,hashcode;
    }* y;
    struct htentry {
      uint32 count;
      uint32* x;
    }* tab;
    uint32 maxtabsize;
    uint32 maxcoll,mincoll,cmaxcoll,nmaxcoll,nmincoll,cmincoll;
    uint32 indexsize;
    cmaxcoll=cmincoll=0;	/* shut gcc up */
    if (wanted==dn && !onlywithpassword)
      counted=record_count;
    else {
      x=map+5*4+size_of_string_table+attribute_count*8;
      counted=0;
      for (i=0; i<record_count; ++i) {
	uint32 j,k;
	uint32_unpack(x,&j);
	if (wanted==objectClass)
	  ++counted;
	x+=16;
	for (; j>2; --j) {
	  uint32_unpack(x,&k);
	  if (k==wanted)
	    ++counted;
	  x+=8;
	}
      }
    }
    if (!counted) die(111,"attribute does not occur?!");
    y=malloc(counted*sizeof(struct node));
    if (!y) die(111,"out of memory");
    x=map+5*4+size_of_string_table+attribute_count*8;
    for (cur=i=0; i<record_count; ++i) {
      uint32 k;
      uint32_unpack(x,&j);
      if (wanted==dn) {
	uint32_unpack(x+8,&k);
	y[cur].recnum=i;
	y[cur].hashcode=hashmapped(k,ignorecase);
	++cur;
	x+=j*8;
      } else {
	if (wanted==objectClass) {
	  uint32_unpack(x+12,&k);
	  y[cur].recnum=i;
	  y[cur].hashcode=hashmapped(k,ignorecase);
	  ++cur;
	}
	x+=16;
	for (; j>2; --j) {
	  uint32_unpack(x,&k);
	  if (k==wanted) {
	    if (onlywithpassword) {
	      uint32_unpack(x-8,&k);
	      y[cur].recnum=i;
	      y[cur].hashcode=hashmapped(k,ignorecase);
	      ++cur;
	    } else {
	      y[cur].recnum=i;
	      y[cur].hashcode=hashmapped(k,ignorecase);
	      ++cur;
	    }
	  }
	  x+=8;
	}
      }
    }
    buffer_putulong(buffer_1,counted);
    buffer_putsflush(buffer_1," entries hashed; looking for hash table size with least collisions...");
    i=counted;
    if (!(i&1)) ++i;
    maxtabsize=counted+counted/8;
    tab=malloc(maxtabsize*sizeof(struct htentry));
    if (!tab) die(111,"out of memory");
    if (maxtabsize > 100) {
      maxcoll=nmaxcoll=nmincoll=0; mincoll=-1;
      for (; i<maxtabsize; ++i) {
	uint32 j,k,chains;
	if ((i&1)==0 || (i%3)==0 || (i%5)==0 || (i%7)==0) continue;
	memset(tab,0,i*sizeof(struct htentry));
	for (j=k=chains=0; j<counted; ++j) {
	  uint32 l=y[j].hashcode%i;
	  if (++tab[l].count>1) ++k;
	  if (tab[l].count==2) ++chains;
	}
	if (k>maxcoll) {
	  nmaxcoll=i;
	  maxcoll=k;
	  cmaxcoll=chains;
	}
	if (k<mincoll) {
	  nmincoll=i;
	  mincoll=k;
	  cmincoll=chains;
	}
      }
      buffer_puts(buffer_1," done.\nminimum collisions at ");
      buffer_putulong(buffer_1,nmincoll);
      buffer_puts(buffer_1,": ");
      buffer_putulong(buffer_1,mincoll);
      buffer_puts(buffer_1," (");
      buffer_putulong(buffer_1,cmincoll);
      buffer_puts(buffer_1," chains), maximum collisions at ");
      buffer_putulong(buffer_1,nmaxcoll);
      buffer_puts(buffer_1,": ");
      buffer_putulong(buffer_1,maxcoll);
      buffer_puts(buffer_1," (");
      buffer_putulong(buffer_1,cmaxcoll);
      buffer_putsflush(buffer_1," chains).\n");
      if (!nmincoll)
	die(111,"can''t happen error: table size zero!?");
      maxtabsize=nmincoll;
    } else {
      buffer_putsflush(buffer_1," done.\n");
    }

    memset(tab,0,maxtabsize*sizeof(struct htentry));

    for (j=0; j<counted; ++j) {
      uint32 l=y[j].hashcode%maxtabsize;
      tab[l].x=realloc(tab[l].x,(++tab[l].count)*sizeof(tab[l].x[0]));
      if (!tab[l].x) die(111,"out of memory");
      tab[l].x[tab[l].count-1]=y[j].recnum;
    }

    indexsize=4*4+maxtabsize*4;
    for (j=0; j<maxtabsize; ++j)
      if (tab[j].count>1)
	indexsize+=(tab[j].count+1)*4;

    free(y);
    munmap(map,filelen);

    {
      int fd=open(filename,O_RDWR);
      char* dest,* x,* z;
      if (fd<0)
	diesys(111,"Could not re-open database file read-write");
      ftruncate(fd,filelen+indexsize);
      map=mmap(0,filelen+indexsize,PROT_WRITE,MAP_SHARED,fd,0);
      if (map==(char*)-1)
	diesys(111,"Could not mmap database file read-write");
      uint32_pack(map+casesensitive,ignorecase);
      dest=map+filelen;
      uint32_pack(dest,3);			/* index type 3 == hash table */
      uint32_pack(dest+4,filelen+indexsize);	/* offset of next index */
      if (onlywithpassword)
	uint32_pack(dest+2*4,dn);		/* indexed attribute */
      else
	uint32_pack(dest+2*4,wanted);		/* indexed attribute */
      uint32_pack(dest+3*4,maxtabsize);		/* hash table size in uint32s */
      x=dest+4*4;
      z=x+maxtabsize*4;
//      printf("hashtab starts at %lu, has %u entries, ends at %lu\n",x-map,maxtabsize,z-map);
      for (j=0; j<maxtabsize; ++j) {
	if (tab[j].count==0) {
//	  printf("tab[%u] = []\n",j);
	  uint32_pack(x,-1);
	  x+=4;
	} else if (tab[j].count==1) {
//	  printf("tab[%u] = [%u]\n",j,tab[j].x[0]);
	  uint32_pack(x,tab[j].x[0]);
	  x+=4;
	} else if (tab[j].count>1) {
	  uint32 k;
	  uint32_pack(x,filelen+(z-dest));
	  x+=4;
	  uint32_pack(z,tab[j].count);
	  z+=4;
//	  printf("tab[%u] = [",j);
	  for (k=0; k<tab[j].count; ++k) {
//	    printf("%u%s",tab[j].x[k],k+1<tab[j].count ? "," : "");
	    uint32_pack(z,tab[j].x[k]);
	    z+=4;
	  }
//	  printf("]\n");
	}
      }
    }

    for (j=0; j<maxtabsize; ++j)
      free(tab[j].x);
    free(tab);

    munmap(map,filelen);
  } else
    die(1,"invalid index type requested");
  return 0;
}
