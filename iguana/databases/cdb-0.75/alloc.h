#ifndef ALLOC_H
#define ALLOC_H
#include <stdlib.h>

extern /*@null@*//*@out@*/char *alloc();
extern void alloc_free();
extern int alloc_re();

#endif
