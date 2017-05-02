#include <stdlib.h>
#include <assert.h>
#include <libowfat/buffer.h>
#include <libowfat/mmap.h>
#include <libowfat/uint16.h>
#include <libowfat/uint32.h>
#include "ldap.h"
#include <libowfat/byte.h>

int main(int argc,char* argv[]) {
  size_t filelen;
  char* fn=argc<2?"data":argv[1];
  const char* map=mmap_read(fn,&filelen);
  uint32 magic,attribute_count,record_count,indices_offset,size_of_string_table,acl_ofs;
  if (!map) {
    buffer_puts(buffer_2,"could not open `");
    buffer_puts(buffer_2,fn);
    buffer_puts(buffer_2,"': ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
    exit(1);
  }
  uint32_unpack(map,&magic);
  uint32_unpack(map+4,&attribute_count);
  uint32_unpack(map+2*4,&record_count);
  uint32_unpack(map+3*4,&indices_offset);
  uint32_unpack(map+4*4,&size_of_string_table);

  {
    uint32 ofs,next;
    acl_ofs=0;
    for (ofs=indices_offset+record_count*4; ofs<(unsigned long)filelen;) {
      uint32 index_type;
      uint32_unpack(map+ofs,&index_type);
      uint32_unpack(map+ofs+4,&next);
      if (index_type==2) { acl_ofs=ofs; break; }
      if (next<ofs || next>filelen) {
kaputt:
	buffer_putsflush(buffer_1,"broken file!\n");
	return 1;
      }
      ofs=next;
    }
    if (acl_ofs) {
      uint32 i,filters,acls,filtertab,acltab;
      ofs=acl_ofs+8;
      buffer_putulong(buffer_1,filters=uint32_read(map+ofs));
      buffer_puts(buffer_1," Filters:\n\n");
      filtertab=ofs+4;
      ofs=filtertab+filters*4;
      if (ofs<filtertab) goto kaputt;
      for (i=0; i<filters; ++i) {
	struct Filter* f;
	ofs=uint32_read(map+filtertab+i*4);
	if (ofs<filtertab || ofs>filelen) goto kaputt;
	buffer_putulong(buffer_1,i);
	buffer_puts(buffer_1,": ");
	if (byte_equal(map+ofs,4,"self"))
	  buffer_puts(buffer_1,"self");
	else if (byte_equal(map+ofs,2,"*"))
	  buffer_puts(buffer_1,"any");
	else if (scan_ldapsearchfilter(map+ofs,map+filelen,&f)!=0) {
	  unsigned long l=fmt_ldapsearchfilterstring(0,f);
	  unsigned long l2;
	  char* buf=malloc(l+23);
	  if (!buf) goto kaputt;
	  buf[l2=fmt_ldapsearchfilterstring(buf,f)]=0;
	  buffer_puts(buffer_1,buf);
	  free_ldapsearchfilter(f);
	  free(f);
	}
	buffer_putsflush(buffer_1,"\n");
      }
      ofs=uint32_read(map+filtertab+filters*4);
      if (ofs<filtertab || ofs>filelen-4) goto kaputt;
      acls=uint32_read(map+ofs);
      buffer_puts(buffer_1,"\n\n");
      buffer_putulong(buffer_1,acls);
      buffer_putsflush(buffer_1," ACLs:\n\n");
      acltab=ofs+4;
      for (i=0; i<acls; ++i) {
	uint16 may,maynot;
	ofs=uint32_read(map+acltab+i*4);
	if (ofs>filelen-16) goto kaputt;
	buffer_putlong(buffer_1,i);
	buffer_puts(buffer_1,":  acl [");
	buffer_putulong(buffer_1,uint32_read(map+ofs));
	buffer_puts(buffer_1,"] [");
	buffer_putulong(buffer_1,uint32_read(map+ofs+4));
	buffer_puts(buffer_1,"] ");
	may=uint16_read(map+ofs+8);
	maynot=uint16_read(map+ofs+10);
	for (ofs+=12; ofs<filelen; ofs+=4) {
	  uint32 j=uint32_read(map+ofs);
	  if (j>ofs) goto kaputt;
	  if (!j) break;
	  buffer_puts(buffer_1,map+j);
	  buffer_puts(buffer_1,uint32_read(map+ofs+4)?",":" ");
	}
	if (may) {
	  buffer_puts(buffer_1,"+");
	  if (may&1) buffer_puts(buffer_1,"r");
	  if (may&2) buffer_puts(buffer_1,"w");
	  if (may&4) buffer_puts(buffer_1,"a");
	  if (may&8) buffer_puts(buffer_1,"d");
	  if (may&16) buffer_puts(buffer_1,"R");
	}
	if (maynot) {
	  buffer_puts(buffer_1,"-");
	  if (maynot&1) buffer_puts(buffer_1,"r");
	  if (maynot&2) buffer_puts(buffer_1,"w");
	  if (maynot&4) buffer_puts(buffer_1,"a");
	  if (maynot&8) buffer_puts(buffer_1,"d");
	  if (maynot&16) buffer_puts(buffer_1,"R");
	}
	buffer_putsflush(buffer_1,"\n");
      }
    }
  }
  buffer_flush(buffer_1);
  return 0;
}
