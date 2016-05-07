#include "str.h"

uint32_t str_len(char *s)
{
  register char *t;

  t = s;
  for (;;) {
    if (!*t) return (uint32_t)(t - s); ++t;
    if (!*t) return (uint32_t)(t - s); ++t;
    if (!*t) return (uint32_t)(t - s); ++t;
    if (!*t) return (uint32_t)(t - s); ++t;
  }
}
