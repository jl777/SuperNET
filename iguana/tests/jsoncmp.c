#include <stdio.h>
#include <stdint.h>
#include "../../includes/cJSON.h"
#include "../../crypto777/OS_portable.h"

int32_t main(int32_t argc,char **argv)
{
    cJSON *argjson,*array,*filejson,*obj,*fobj; char *fname,*filestr,*fstr,*str,*field; int32_t i,n; long filesize;
    if ( argc > 2 && (argjson= cJSON_Parse(argv[2])) != 0 )
    {
        fname = argv[1];
printf("fname.%s\n",argv[1]);
	if ( (filestr= OS_filestr(&filesize,fname)) != 0 )
        {
            if ( (filejson= cJSON_Parse(filestr)) != 0 )
            {
                if ( (array= jarray(&n,argjson,"fields")) == 0 )
                    obj = jobj(argjson,"field"), n = 1;
                else obj = jitem(array,0);
                for (i=0; i<n; i++)
                {
                    if ( (field= jfieldname(obj)) != 0 )
                    {
                        if ( (fobj= jobj(filejson,field)) != 0 )
                        {
                            fstr = jprint(fobj,0);
                            str = jprint(obj,0);
                            if ( strcmp(fstr,str) != 0 )
                                printf("field.(%s) in (%s) mismatch (%s) != (%s)\n",field,fname,fstr,str);
                            free(str);
                            free(fstr);
                        } else printf("cant find field.(%s) in (%s)\n",field,fname);
                    }
                    if ( i < n-1 )
                        obj = jitem(array,i+1);
                }
                free_json(filejson);
            }
            free(filestr);
        }
    } else printf("argc.%d fname.(%s) error\n",argc,argv[1]);
}

