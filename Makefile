#DEBUG=1

all: t1 t2 parse dumpidx addindex bindrequest tinyldap tinyldap_standalone tinyldap_debug ldapclient ldapclient_str # t

asn1.a: fmt_asn1intpayload.o fmt_asn1length.o fmt_asn1tag.o \
fmt_asn1int.o fmt_asn1string.o fmt_asn1transparent.o scan_asn1tag.o \
scan_asn1length.o scan_asn1int.o scan_asn1string.o scan_asn1INTEGER.o \
scan_asn1STRING.o scan_asn1SEQUENCE.o scan_asn1ENUMERATED.o \
scan_asn1BOOLEAN.o scan_asn1rawint.o scan_asn1SET.o fmt_asn1sint.o \
fmt_asn1sintpayload.o

ldap.a: scan_ldapmessage.o fmt_ldapmessage.o fmt_ldapbindrequest.o \
scan_ldapbindrequest.o scan_ldapbindresponse.o scan_ldapresult.o \
scan_ldapstring.o scan_ldapsearchfilter.o scan_ldapsearchrequest.o \
freefilter.o freeava.o scan_ldapava.o fmt_ldapsearchresultentry.o \
fmt_ldapstring.o freepal.o scan_ldapsearchresultentry.o \
fmt_ldapresult.o fmt_ldappal.o fmt_ldapadl.o fmt_ldapava.o \
fmt_ldapsearchfilter.o fmt_ldapsearchrequest.o matchstring.o

ldif.a: ldif_parse.o ldap_match.o ldap_match_mapped.o

storage.a: strstorage.o strduptab.o mstorage_add.o mduptab_add.o

DIET=/opt/diet/bin/diet -Os
CC=gcc
CFLAGS=-pipe -I. -Wall -W
ifneq ($(DEBUG),)
DIET=/opt/diet/bin/diet
CFLAGS=-pipe -I. -Wall -W -g
endif

%.o: %.c
	$(DIET) $(CC) $(CFLAGS) -c $<

%.a:
	ar cru $@ $^

%: %.c
	$(DIET) $(CC) $(CFLAGS) -o $@ $^ -lowfat

t1 parse: ldif.a storage.a
t2: ldap.a asn1.a
t3 t4 t5 addindex: storage.a
bindrequest tinyldap tinyldap_standalone tinyldap_debug ldapclient ldapclient_str: ldap.a asn1.a

tinyldap tinyldap_standalone tinyldap_debug: ldif.a storage.a

tinyldap_standalone: tinyldap.c
	$(DIET) $(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ -lowfat

tinyldap_debug: tinyldap.c
	$(DIET) $(CC) $(CFLAGS) -DSTANDALONE -DDEBUG -o $@ $^ -lowfat

.PHONY: clean tar
clean:
	rm -f t t[1-9] *.[ao] bindrequest tinyldap ldapclient data \
parse tinyldap_standalone tinyldap_debug ldapclient_str addindex \
dumpidx

tar: clean
	cd ..; tar cvvf ldap.tar.bz2 ldap --use=bzip2 --exclude CVS --exclude exp.ldif --exclude polyp* --exclude rfc*

fmt_asn1int.o: fmt_asn1int.c
fmt_asn1intpayload.o: fmt_asn1intpayload.c
fmt_asn1length.o: fmt_asn1length.c asn1.h
fmt_asn1string.o: fmt_asn1string.c asn1.h
fmt_asn1tag.o: fmt_asn1tag.c asn1.h
fmt_asn1transparent.o: fmt_asn1transparent.c asn1.h
fmt_ldapbindrequest.o: fmt_ldapbindrequest.c asn1.h ldap.h
fmt_ldapbindresponse.o: fmt_ldapbindresponse.c asn1.h ldap.h
fmt_ldapmessage.o: fmt_ldapmessage.c asn1.h ldap.h

scan_asn1BOOLEAN.o: scan_asn1BOOLEAN.c asn1.h
scan_asn1ENUMERATED.o: scan_asn1ENUMERATED.c asn1.h
scan_asn1INTEGER.o: scan_asn1INTEGER.c asn1.h
scan_asn1SEQUENCE.o: scan_asn1SEQUENCE.c asn1.h
scan_asn1STRING.o: scan_asn1STRING.c asn1.h
scan_asn1int.o: scan_asn1int.c asn1.h
scan_asn1length.o: scan_asn1length.c asn1.h
scan_asn1string.o: scan_asn1string.c asn1.h
scan_asn1tag.o: scan_asn1tag.c asn1.h
scan_ldapava.o: scan_ldapava.c asn1.h ldap.h
scan_ldapbindrequest.o: scan_ldapbindrequest.c asn1.h ldap.h
scan_ldapbindresponse.o: scan_ldapbindresponse.c asn1.h ldap.h
scan_ldapmessage.o: scan_ldapmessage.c asn1.h ldap.h
scan_ldapsearchfilter.o: scan_ldapsearchfilter.c asn1.h ldap.h
scan_ldapsearchrequest.o: scan_ldapsearchrequest.c asn1.h ldap.h
scan_ldapstring.o: scan_ldapstring.c

ldif_parse.o: ldif_parse.c strduptab.h strstorage.h ldif.h

tinyldap.o: tinyldap.c ldap.h ldif.h
ldapclient.o: ldapclient.c ldap.h
ldapclient_str.o: ldapclient_str.c ldap.h
bindrequest.o: bindrequest.c ldap.h

strduptab.o: strduptab.c strduptab.h strstorage.h
strstorage.o: strstorage.c strstorage.h
freeava.o: freeava.c ldap.h
freefilter.o: freefilter.c ldap.h
