#DEBUG=1
#COVERAGE=1

all: t1 t2 parse dumpidx idx2ldif addindex bindrequest tinyldap \
tinyldap_standalone tinyldap_debug ldapclient ldapclient_str \
md5password mysql2ldif acl dumpacls ldapdelete # t6 # t

asn1.a: fmt_asn1intpayload.o fmt_asn1length.o fmt_asn1tag.o \
fmt_asn1int.o fmt_asn1string.o fmt_asn1transparent.o scan_asn1tag.o \
scan_asn1length.o scan_asn1int.o scan_asn1string.o scan_asn1INTEGER.o \
scan_asn1STRING.o scan_asn1SEQUENCE.o scan_asn1ENUMERATED.o \
scan_asn1BOOLEAN.o scan_asn1rawint.o scan_asn1SET.o fmt_asn1sint.o \
fmt_asn1sintpayload.o scan_asn1oid.o scan_asn1BITSTRING.o \
scan_asn1tagint.o fmt_asn1tagint.o fmt_asn1OID.o scan_asn1generic.o \
fmt_asn1generic.o

ldap.a: scan_ldapmessage.o fmt_ldapmessage.o fmt_ldapbindrequest.o \
scan_ldapbindrequest.o scan_ldapbindresponse.o scan_ldapresult.o \
scan_ldapstring.o scan_ldapsearchfilter.o scan_ldapsearchrequest.o \
freefilter.o freeava.o scan_ldapava.o fmt_ldapsearchresultentry.o \
fmt_ldapstring.o freepal.o scan_ldapsearchresultentry.o \
fmt_ldapresult.o fmt_ldappal.o fmt_ldapadl.o fmt_ldapava.o \
fmt_ldapsearchfilter.o fmt_ldapsearchrequest.o matchstring.o \
matchprefix.o matchcasestring.o matchcaseprefix.o \
scan_ldapmodifyrequest.o scan_ldapaddrequest.o bstrlen.o bstrfirst.o \
bstrstart.o free_ldapadl.o free_ldappal.o free_ldapsearchfilter.o \
scan_ldapsearchfilterstring.o free_ldapsearchresultentry.o \
fmt_ldapsearchfilterstring.o ldap_match_sre.o \
fmt_ldapdeleterequest.o scan_ldapdeleterequest.o normalize_dn.o

ldif.a: ldif_parse.o ldap_match_mapped.o

storage.a: strstorage.o strduptab.o mstorage_add.o mduptab_add.o \
bstr_diff.o mduptab_adds.o bstr_diff2.o mstorage_add_bin.o \
mstorage_init.o mstorage_init_persistent.o mstorage_unmap.o \
mduptab_init.o mduptab_init_reuse.o mduptab_reset.o

auth.a: auth.o

DIET=/opt/diet/bin/diet -Os
CC=gcc
CFLAGS=-pipe -I. -Wall -W -Wextra
ifneq ($(DEBUG),)
DIET=/opt/diet/bin/diet
CFLAGS=-pipe -I. -Wall -W -g -fstack-protector
endif
ifeq ($(COVERAGE),1)
DIET=
CFLAGS=-pipe -I. -g -fprofile-arcs -ftest-coverage
endif

ifneq ($(DIET),)
LIBS+=-llatin1
else
LIBS+=-lcrypto -lcrypt
endif

%.o: %.c
	$(DIET) $(CC) $(CFLAGS) -c $<

%.a:
	ar cru $@ $^

%: %.c
	$(DIET) $(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lowfat ${LIBS}

t1 parse: ldif.a storage.a
t2: ldap.a asn1.a
t3 t4 t5 addindex: storage.a
t6: storage.a
tinyldap tinyldap_standalone tinyldap_debug: ldif.a storage.a auth.a
bindrequest tinyldap tinyldap_standalone tinyldap_debug ldapclient ldapclient_str ldapdelete: ldap.a asn1.a
idx2ldif: ldap.a
dumpacls: ldap.a asn1.a
parse: normalize_dn.o

tinyldap_standalone: tinyldap.c
	$(DIET) $(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ $(LDFLAGS) -lowfat $(LIBS)

tinyldap_debug: tinyldap.c
	$(DIET) $(CC) $(CFLAGS) -DSTANDALONE -DDEBUG -o $@ $^ $(LDFLAGS) -lowfat $(LIBS)

acl: acl.c ldap.a asn1.a
	$(DIET) $(CC) $(CFLAGS) -o acl acl.c -I. ldap.a asn1.a -lowfat $(LIBS)


.PHONY: clean tar
clean:
	rm -f t t[1-9] *.[ao] bindrequest tinyldap ldapclient \
parse tinyldap_standalone tinyldap_debug ldapclient_str addindex \
dumpidx idx2ldif md5password *.da *.bbg *.bb *.gcov gmon.out *.gcda \
*.gcno

tar: clean
	cd ..; tar cvvf tinyldap.tar.bz2 tinyldap --use=bzip2 --exclude capture --exclude CVS --exclude exp.ldif --exclude polyp* --exclude rfc*

ldif_parse.o: ldif_parse.c strduptab.h strstorage.h ldif.h

tinyldap.o: tinyldap.c ldap.h ldif.h
ldapclient.o: ldapclient.c ldap.h
ldapclient_str.o: ldapclient_str.c ldap.h
bindrequest.o: bindrequest.c ldap.h

strduptab.o: strduptab.c strduptab.h strstorage.h
strstorage.o: strstorage.c strstorage.h
freeava.o: freeava.c ldap.h
freefilter.o: freefilter.c ldap.h

fmt_asn1int.o: fmt_asn1int.c asn1.h
fmt_asn1intpayload.o: fmt_asn1intpayload.c asn1.h
fmt_asn1length.o: fmt_asn1length.c asn1.h
fmt_asn1sint.o: fmt_asn1sint.c asn1.h
fmt_asn1sintpayload.o: fmt_asn1sintpayload.c asn1.h
fmt_asn1string.o: fmt_asn1string.c asn1.h
fmt_asn1tag.o: fmt_asn1tag.c asn1.h
fmt_asn1tagint.o: fmt_asn1tagint.c asn1.h
fmt_asn1transparent.o: fmt_asn1transparent.c asn1.h
fmt_ldapadl.o: fmt_ldapadl.c asn1.h ldap.h
fmt_ldapava.o: fmt_ldapava.c asn1.h ldap.h
fmt_ldapbindrequest.o: fmt_ldapbindrequest.c asn1.h ldap.h
fmt_ldapmessage.o: fmt_ldapmessage.c asn1.h ldap.h
fmt_ldappal.o: fmt_ldappal.c asn1.h ldap.h
fmt_ldapresult.o: fmt_ldapresult.c asn1.h ldap.h
fmt_ldapsearchfilter.o: fmt_ldapsearchfilter.c asn1.h ldap.h
fmt_ldapsearchfilterstring.o: fmt_ldapsearchfilterstring.c ldap.h
fmt_ldapsearchrequest.o: fmt_ldapsearchrequest.c asn1.h ldap.h
fmt_ldapsearchresultentry.o: fmt_ldapsearchresultentry.c asn1.h ldap.h
fmt_ldapstring.o: fmt_ldapstring.c asn1.h ldap.h
fmt_asn1OID.o: fmt_asn1OID.c asn1.h
fmt_asn1generic.o: fmt_asn1generic.c asn1.h

scan_asn1BOOLEAN.o: scan_asn1BOOLEAN.c asn1.h
scan_asn1ENUMERATED.o: scan_asn1ENUMERATED.c asn1.h
scan_asn1INTEGER.o: scan_asn1INTEGER.c asn1.h
scan_asn1SEQUENCE.o: scan_asn1SEQUENCE.c asn1.h
scan_asn1SET.o: scan_asn1SET.c asn1.h
scan_asn1STRING.o: scan_asn1STRING.c asn1.h
scan_asn1BITSTRING.o: scan_asn1BITSTRING.c asn1.h
scan_asn1int.o: scan_asn1int.c asn1.h
scan_asn1length.o: scan_asn1length.c asn1.h
scan_asn1oid.o: scan_asn1oid.c asn1.h
scan_asn1rawint.o: scan_asn1rawint.c asn1.h
scan_asn1string.o: scan_asn1string.c asn1.h
scan_asn1tag.o: scan_asn1tag.c asn1.h
scan_asn1tagint.o: scan_asn1tagint.c asn1.h
scan_ldapaddrequest.o: scan_ldapaddrequest.c asn1.h ldap.h
scan_ldapava.o: scan_ldapava.c asn1.h ldap.h
scan_ldapbindrequest.o: scan_ldapbindrequest.c asn1.h ldap.h
scan_ldapbindresponse.o: scan_ldapbindresponse.c asn1.h ldap.h
scan_ldapmessage.o: scan_ldapmessage.c asn1.h ldap.h
scan_ldapmodifyrequest.o: scan_ldapmodifyrequest.c asn1.h ldap.h
scan_ldapresult.o: scan_ldapresult.c asn1.h ldap.h
scan_ldapsearchfilter.o: scan_ldapsearchfilter.c asn1.h ldap.h
scan_ldapsearchfilterstring.o: scan_ldapsearchfilterstring.c ldap.h
scan_ldapsearchrequest.o: scan_ldapsearchrequest.c asn1.h ldap.h
scan_ldapsearchresultentry.o: scan_ldapsearchresultentry.c asn1.h ldap.h
scan_ldapstring.o: scan_ldapstring.c asn1.h ldap.h
scan_asn1generic.o: scan_asn1generic.c asn1.h

ldap_match_sre.o: ldap_match_sre.c ldap.h
