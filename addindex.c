#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <string.h>
#include "buffer.h"
#include "mmap.h"
#include "uint32.h"
#include "mstorage.h"

mstorage_t idx;
char* map;

int compar(const void* a,const void* b) {
  return strcmp(map+*(uint32*)a,map+*(uint32*)b);
}

int compari(const void* a,const void* b) {
  return strcasecmp(map+*(uint32*)a,map+*(uint32*)b);
}

int main(int argc,char* argv[]) {
  long filelen;
  char* filename=argv[1];
  uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table;
  uint32 wanted,casesensitive,dn,objectClass;

  if (argc<3) {
    buffer_putsflush(buffer_2,"usage: ./addindex filename attribute [i]\n"
		     "if i is present, make index case insensitive.\n");
    return 1;
  }
  map=mmap_read(filename,&filelen);
  uint32_unpack(map,&magic);
  if (magic!=0xfefe1da9) {
    buffer_putsflush(buffer_2,"file format not recognized!  Invalid magic!\n");
    return 1;
  }
  uint32_unpack(map+4,&attribute_count);
  uint32_unpack(map+2*4,&record_count);
  uint32_unpack(map+3*4,&indices_offset);
  uint32_unpack(map+4*4,&size_of_string_table);

  {
    unsigned int i;
    char* x=map+5*4+size_of_string_table;
    wanted=0;
    for (i=0; i<attribute_count; ++i) {
      uint32 j;
      uint32_unpack(x,&j);
      if (!strcmp(map+j,argv[2])) {
	buffer_putsflush(buffer_2,"found attribute!\n");
	wanted=j; casesensitive=x+attribute_count*4-map;
	uint32_unpack(map+casesensitive,&j);
	if (j) {
	  buffer_putsflush(buffer_2,"case sensitivity flag is nonzero?!\n");
	  return 1;
	}
	break;
      } else if (!strcmp(map+j,"dn"))
	dn=j;
      else if (!strcmp(map+j,"objectClass"))
	objectClass=j;
      x+=4;
    }
    if (!wanted) {
      buffer_putsflush(buffer_2,"that attribute is not in the database!\n");
      return 1;
    }
  }

  {
    unsigned long i,counted=0;
    char* x=map+5*4+size_of_string_table+attribute_count*8;
    for (i=0; i<record_count; ++i) {
      uint32 j,k;
      uint32_unpack(x,&j);
      if (wanted==dn) {
	uint32_unpack(x+8,&k);
	mstorage_add(&idx,(char*)&k,4);
	++counted;
      } else if (wanted==objectClass) {
	uint32_unpack(x+12,&k);
	mstorage_add(&idx,(char*)&k,4);
	++counted;
      } else {
	x+=16;
	for (; j>2; --j) {
	  uint32_unpack(x,&k);
	  if (k==wanted) {
	    uint32_unpack(x+4,&k);
	    mstorage_add(&idx,(char*)&k,4);
	    ++counted;
	  }
	  x+=8;
	}
      }
    }
    buffer_putulong(buffer_1,counted);
    buffer_putsflush(buffer_1," entries to be sorted...");
    if (argc>3)
      qsort(idx.root,counted,4,compari);
    else
      qsort(idx.root,counted,4,compar);
    buffer_putsflush(buffer_1," done.\n");
    munmap(map,filelen);
    {
      int fd=open(filename,O_RDWR);
      if (fd<0) {
	buffer_putsflush(buffer_2,"could not re-open database file read-write\n");
	exit(1);
      }
      ftruncate(fd,filelen+(counted+3)*4);
      map=mmap(0,filelen+(counted+3)*4,PROT_WRITE,MAP_SHARED,fd,0);
      if (map==(char*)-1) {
	buffer_putsflush(buffer_2,"could not mmap database file read-write\n");
	exit(1);
      }
      uint32_pack(map+casesensitive,argc>3?1:0);
      uint32_pack(map+filelen,0);
      uint32_pack(map+filelen+4,filelen+(counted+3)*4);
      uint32_pack(map+filelen+8,wanted);
      {
	char* x=map+filelen+12;
	unsigned long i;
	for (i=0; i<counted; ++i) {
	  uint32_pack(x,((uint32*)idx.root)[i]);
	  x+=4;
	}
      }
    }
  }
  return 0;
}
