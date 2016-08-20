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
        if ( (filestr= OS_filestr(&filesize,fname)) != 0 )
        {
            if ( (filejson= cJSON_Parse(filestr)) != 0 )
            {
                if ( (array= jarray(&n,argjson,"fields")) != 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        obj = jitem(array,i);
                        if ( (field= jfieldname(obj)) != 0 && (obj= obj->child) != 0 )
                        {
                            if ( (fobj= jobj(filejson,field)) != 0 )
                            {
                                fstr = jprint(fobj,0);
                                str = jprint(obj,0);
                                if ( strcmp(fstr,str) != 0 )
                                {
                                    printf("{\"error\":\"field.(%s) in (%s) i.%d of n.%d mismatch (%s) != (%s)\"}\n",field,fname,i,n,fstr,str);
                                    fprintf(stderr,"{\"error\":\"field.(%s) in (%s) i.%d of n.%d mismatch (%s) != (%s)\"}\n",field,fname,i,n,fstr,str);
                                }
                                else printf("{\"result\":\"MATCHED.[%s] (%s).(%s)\"}\n",fname,field,fstr);
                                free(str);
                                free(fstr);
                            } else fprintf(stderr,"cant find field.(%s) in (%s)\n",field,fname);
                        } else fprintf(stderr,"no fieldname array[%d]\n",i);
                    }
                } else fprintf(stderr,"no fields array\n");
                free_json(filejson);
            } else fprintf(stderr,"cant parse.(%s)\n",filestr);
            free(filestr);
        } else fprintf(stderr,"cant load (%s)\n",fname);
    } else fprintf(stderr,"argc.%d fname.(%s) error\n",argc,argv[1]);
}

