#include "ldap.h"

size_t scan_ldapmessage_nolengthcheck(const char* src,const char* max,size_t* len) {
  return scan_asn1SEQUENCE_nolengthcheck(src,max,len);
}
