
/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
//  LP_network.c
//  marketmaker
//

char *nanomsg_tcpname(char *str,char *ipaddr,uint16_t port)
{
    sprintf(str,"tcp://%s:%u",ipaddr,port);
    return(str);
}

int32_t LP_send(int32_t sock,char *msg,int32_t freeflag)
{
    int32_t sentbytes,len,i; struct nn_pollfd pfd;
    if ( sock < 0 )
    {
        printf("LP_send.(%s) to illegal socket\n",msg);
        if ( freeflag != 0 )
            free(msg);
        return(-1);
    }
    len = (int32_t)strlen(msg) + 1;
    for (i=0; i<1000; i++)
    {
        pfd.fd = sock;
        pfd.events = NN_POLLOUT;
        if ( nn_poll(&pfd,1,1) > 0 )
        {
            if ( (sentbytes= nn_send(sock,msg,len,0)) != len )
                printf("LP_send sent %d instead of %d\n",sentbytes,len);
            //else printf("SENT.(%s)\n",msg);
            if ( freeflag != 0 )
                free(msg);
            return(sentbytes);
        }
        usleep(1000);
    }
    printf("error LP_send sock.%d, pipeline timeout.(%s)\n",sock,msg);
    //if ( (sentbytes= nn_send(sock,msg,len,0)) != len )
    //   printf("LP_send sent %d instead of %d\n",sentbytes,len);
    if ( freeflag != 0 )
        free(msg);
    return(-1);
}

uint32_t LP_swapsend(int32_t pairsock,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t nextbits,uint32_t crcs[2])
{
    uint8_t *buf; int32_t sentbytes,offset=0,i;
    buf = malloc(datalen + sizeof(msgbits) + sizeof(swap->I.req.quoteid) + sizeof(bits256)*2);
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.myhash.bytes[i];
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.otherhash.bytes[i];
    offset += iguana_rwnum(1,&buf[offset],sizeof(swap->I.req.quoteid),&swap->I.req.quoteid);
    offset += iguana_rwnum(1,&buf[offset],sizeof(msgbits),&msgbits);
    if ( datalen > 0 )
        memcpy(&buf[offset],data,datalen), offset += datalen;
    if ( (sentbytes= nn_send(pairsock,buf,offset,0)) != offset )
    {
        printf("sentbytes.%d vs offset.%d\n",sentbytes,offset);
        if ( sentbytes < 0 )
        {
        }
    }
    //printf("sent %d bytes\n",sentbytes);
    //else printf("send.[%d] %x offset.%d datalen.%d [%llx]\n",sentbytes,msgbits,offset,datalen,*(long long *)data);
    free(buf);
    return(nextbits);
}
