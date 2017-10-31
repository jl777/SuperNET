#include <stdio.h>
#include <memory.h>
#include <string.h>

char *barterDEX(char *jsonstr)
{
char *str = "{\"result\":\"success\"}";
printf("barterDEX.(%s)\n",jsonstr);
retstr = malloc(strlen(str)+1);
strcpy(retstr,str);
return(retstr);
}

