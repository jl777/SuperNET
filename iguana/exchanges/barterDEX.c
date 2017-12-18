#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

char *barterDEX(char *jsonstr)
{
char *retstr,*str = "{\"result\":\"success\"}";
printf("barterDEX.(%s)\n",jsonstr);
retstr = malloc(strlen(str)+1);
strcpy(retstr,str);
return(retstr);
}

