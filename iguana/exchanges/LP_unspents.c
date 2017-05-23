//
//  LP_unspents.c
//  marketmaker
//
//  Created by Mac on 5/23/17.
//  Copyright © 2017 SuperNET. All rights reserved.
//

#include <stdio.h>

void LPinit()
{
    char *retstr;
    retstr = iguana_listunspent("KMD","RRyBxbrAPRUBCUpiJgJZYrkxqrh8x5ta9Z");
    if ( retstr != 0 )
    {
        printf("listunspent.(%s)\n",retstr);
        free(retstr);
    } else printf("null retstr\n");
    getchar();
}
