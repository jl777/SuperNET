#ifndef READWRITE_H
#define READWRITE_H
#include <sys/types.h>

ssize_t read(int, void *, size_t);
ssize_t write(int, const void *, size_t);

#endif
