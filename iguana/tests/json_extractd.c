#include <stdio.h>
#include <stdint.h>
#include "../../includes/cJSON.h"
#include "../../crypto777/OS_portable.h"

int32_t main(int32_t argc,char **argv)
{
    cJSON *filejson; char *fname,*filestr,*field; long filesize;
    if ( argc > 2 )
    {
        fname = argv[1];
	field = argv[2];
        if ( (filestr= OS_filestr(&filesize,fname)) != 0 )
        {
            if ( (filejson= cJSON_Parse(filestr)) != 0 )
            {
		if ( jobj(filejson,field) != 0 )
		    printf("%.8f\n",jdouble(filejson,field));
		free_json(filejson);
            } else fprintf(stderr,"cant parse.(%s)\n",filestr);
            free(filestr);
        } else fprintf(stderr,"cant load (%s)\n",fname);
    } else fprintf(stderr,"argc.%d fname.(%s) error\n",argc,argv[1]);
}

