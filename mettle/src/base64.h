#ifndef _BASE64_H
#define _BASE64_H

int base64decode(char *dest, const char *src, int l);

int base64encode(char *dest, const char *src, int l);

#endif
