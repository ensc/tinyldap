#ifndef _AUTH_H
#define _AUTH_H

/* return non-zero if the password matches */
int check_password(const char* fromdb,struct string* plaintext);

#endif
