#include <unistd.h>
#include "ldap.h"

int main() {
  char buf[1024];
  int s=100;
  int len=fmt_ldapbindrequest(buf+s,3,"","");
  int hlen=fmt_ldapmessage(0,1,0,len);
  fmt_ldapmessage(buf+s-hlen,1,0,len);
  write(1,buf+s-hlen,len+hlen);
  return 0;
}
