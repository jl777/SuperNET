
/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
//
//  LP_mpnet.c
//  marketmaker
//

int32_t LP_tradecommand(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen);
int32_t LP_quoteparse(struct LP_quoteinfo *qp,cJSON *argjson);

int32_t LP_mpnet_addorder(struct LP_quoteinfo *qp)
{
    uint64_t destvalue,destvalue2;
    if ( LP_iseligible(&destvalue,&destvalue2,0,qp->destcoin,qp->desttxid,qp->destvout,qp->destsatoshis,qp->feetxid,qp->feevout) > 0 )
    {
        LP_gtc_addorder(qp);
        return(0);
    }
    return(-1);
}

void LP_mpnet_init()
{
    char fname[1024],line[8192]; FILE *fp; struct LP_quoteinfo Q;
    sprintf(fname,"%s/GTC/orders",GLOBAL_DBDIR), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        while ( fgets(line,sizeof(line),fp) > 0 )
        {
            if ( (argjson= cJSON_Parse(line)) != 0 )
            {
                if ( LP_quoteparse(&Q,argjson) == 0 )
                {
                    if ( LP_mpnet_addorder(&Q) == 0 )
                        printf("GTC %s",line);
                }
                free_json(argjson);
            }
        }
        fclose(fp);
    }
}

void LP_mpnet_send(int32_t localcopy,char *msg,int32_t sendflag)
{
    char fname[1024]; FILE *fp;
    if ( localcopy != 0 )
    {
        sprintf(fname,"%s/GTC/orders",GLOBAL_DBDIR), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"rb+")) == 0 )
            fp = fopen(fname,"wb+");
        else fseek(fp,0,SEEK_END);
        fprintf(fp,"%s\n",msg);
        fclose(fp);
    }
    if ( G.mpnet != 0 && sendflag != 0 )
    {
        
    }
}

cJSON *LP_mpnet_get()
{
    return(0);
}

void LP_mpnet_check(void *ctx,char *myipaddr,int32_t pubsock)
{
    cJSON *argjson;
    while ( (argjson= LP_mpnet_get()) != 0 )
    {
        LP_tradecommand(ctx,myipaddr,pubsock,argjson,0,0);
        free_json(argjson);
    }
}
