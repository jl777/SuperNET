/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
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

#include "iguana777.h"

int32_t iguana_rwaddr(int32_t rwflag,uint8_t *serialized,struct iguana_msgaddress *addr,int32_t protover)
{
    int32_t len = 0;
	if ( protover >= CADDR_TIME_VERSION )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->nTime),&addr->nTime);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->nServices),&addr->nServices);
    len += iguana_rwmem(rwflag,&serialized[len],sizeof(addr->ip),&addr->ip);
    if ( rwflag != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->port),&addr->port);
    else
    {
        addr->port = (uint16_t)serialized[len++] << 8;
        addr->port += (uint16_t)serialized[len++];
    }
    return(len);
}

int32_t iguana_rwversion(int32_t rwflag,uint8_t *serialized,struct iguana_msgversion *msg,char *ipaddr,int32_t readsize)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nVersion),&msg->nVersion);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nServices),&msg->nServices);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nTime),&msg->nTime);
    len += iguana_rwaddr(rwflag,&serialized[len],&msg->addrTo,MIN_PROTO_VERSION);
    len += iguana_rwaddr(rwflag,&serialized[len],&msg->addrFrom,MIN_PROTO_VERSION);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nonce),&msg->nonce);
    len += iguana_rwstr(rwflag,&serialized[len],sizeof(msg->strSubVer),msg->strSubVer);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nStartingHeight),&msg->nStartingHeight);
    if ( readsize == 117 )
    {
        uint32_t iVer = 1132,v_Network_id=1; uint16_t wPort=1920,wCtPort=0,wPrPort=0; uint8_t bIsGui=0;
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(iVer),&iVer);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(v_Network_id),&v_Network_id);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(wPort),&wPort);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(bIsGui),&bIsGui);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(wCtPort),&wCtPort);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(wPrPort),&wPrPort);
        /*int iVer = BitNet_Version;
         unsigned short wPort = GetListenPort();
         unsigned char bIsGui = 0;	// 2014.12.18 add
         unsigned short wCtPort = 0;
         unsigned short wPrPort = 0;
         vRecv >> iVer;
         pfrom->vBitNet.v_iVersion = iVer;
         vRecv >> pfrom->vBitNet.;
         if (!vRecv.empty()){ vRecv >> pfrom->vBitNet.v_ListenPort; }
         if (!vRecv.empty()){ vRecv >> pfrom->vBitNet.v_IsGuiNode; }	//-- 2014.12.18 add
         if (!vRecv.empty()){ vRecv >> pfrom->vBitNet.v_iVpnServiceCtrlPort; }	//-- 2014.12.28 add
         if (!vRecv.empty()){ vRecv >> pfrom->vBitNet.v_P2P_proxy_port; }	    //-- 2014.12.28 add
         */
        printf("iVer.%d v_Network_id.%d wPort.%u bIsGui.%d wCtPort.%u wPrPort.%u\n",iVer,v_Network_id,wPort,bIsGui,wCtPort,wPrPort);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->relayflag),&msg->relayflag);
    }
    else if ( msg->nVersion > 70000 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->relayflag),&msg->relayflag);
    //if ( rwflag == 0 )
    //printf("readsize.%d %-15s v.%llu srv.%llx %u ht.%llu [%s].R%d nonce.%llx\n",readsize,ipaddr,(long long)msg->nVersion,(long long)msg->nServices,(uint32_t)msg->nTime,(long long)msg->nStartingHeight,msg->strSubVer,msg->relayflag,(long long)msg->nonce);
    // 6e ea 00 00 01 00 00 00 00 00 00 00 86 5f a8 56 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff b5 2f b7 bc c6 83 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 67 e5 7e c2 07 80 00 00 00 00 00 00 00 00 10 2f 42 69 74 4e 65 74 3a 31 2e 31 2e 33 2e 32 2f 92 d0 09 00 6c 04 00 00 01 00 00 00 80 07 01 9a 03 9b 03 01
    return(len);
}

// 06000000996da490f6151ad9d05d9defc99bda58441d2b833c0da69d11e764d7c70a00003378a650b506a66b41097a0b513f2fee899788711bc6643ff976ce6dbb0b620c5f800854ffff0f1e0004de0301010000005e800854010000000000000000000000000000000000000000000000000000000000000000ffffffff03510102ffffffff0100008a5d784563011976a9145166e6e52de58dfacb18670c0030aedcf295233988ac000000000000

int32_t iguana_rwblock(char *symbol,int32_t (*hashalgo)(uint8_t *blockhashp,uint8_t *serialized,int32_t len),int32_t rwflag,bits256 *hash2p,uint8_t *serialized,struct iguana_msgblock *msg)
{
    int32_t len = 0; uint64_t x;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.version),&msg->H.version);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->H.prev_block),msg->H.prev_block.bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->H.merkle_root),msg->H.merkle_root.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.timestamp),&msg->H.timestamp);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.bits),&msg->H.bits);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.nonce),&msg->H.nonce);
    *hash2p = iguana_calcblockhash(symbol,hashalgo,serialized,len);
    //char str[65]; printf("len.%d: block version.%d timestamp.%u bits.%x nonce.%u prev.(%s) %llx blockhash.(%s) %llx\n",len,msg->H.version,msg->H.timestamp,msg->H.bits,msg->H.nonce,bits256_str(str,msg->H.prev_block),(long long)msg->H.merkle_root.txid,blockhash,(long long)hash2p->txid);
    if ( rwflag != 0 )
        x = msg->txn_count;
    len += iguana_rwvarint(rwflag,&serialized[len],&x);
    if ( rwflag == 0 )
    {
        char str[65];
        bits256_str(str,*hash2p);
        if ( x < 65536 )
            msg->txn_count = (uint16_t)x;
        else printf("txn_count overflow.%lld for %s\n",(long long)x,str);
    }
    //  ? 	txns 	tx[] 	Block transactions, in format of "tx" command
    return(len);
}

int32_t iguana_serialize_block(struct iguana_chain *chain,bits256 *hash2p,uint8_t serialized[sizeof(struct iguana_msgblock)],struct iguana_block *block)
{
    struct iguana_msgblock msg; int32_t len;
    memset(&msg,0,sizeof(msg));
    msg.H.version = block->RO.version;
    msg.H.prev_block = block->RO.prev_block;
    msg.H.merkle_root = block->RO.merkle_root;
    msg.H.timestamp = block->RO.timestamp;
    msg.H.bits = block->RO.bits;
    msg.H.nonce = block->RO.nonce;
    msg.txn_count = block->RO.txn_count;
    len = iguana_rwblock(chain->symbol,chain->hashalgo,1,hash2p,serialized,&msg);
    return(len);
}

int32_t iguana_rwblockhash(int32_t rwflag,uint8_t *serialized,uint32_t *nVersionp,uint32_t *varintp,bits256 *hashes,bits256 *stophash)
{
    int32_t i,len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(*nVersionp),nVersionp);
    len += iguana_rwvarint32(rwflag,&serialized[len],varintp);
    if ( *varintp < IGUANA_MAXBUNDLESIZE+1 )
    {
        for (i=0; i<*varintp; i++)
            len += iguana_rwbignum(rwflag,&serialized[len],sizeof(hashes[i]),hashes[i].bytes);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(*stophash),stophash->bytes);
        //for (i=0; i<len; i++)
        //    printf("%02x ",serialized[i]);
        //printf("rwblockhash len.%d\n",len);
    } else printf("iguana_rwblockhash: illegal varint.%d\n",*varintp);
    return(len);
}

/*int32_t iguana_request_data(struct iguana_info *coin,struct iguana_peer *addr,bits256 *hashes,int32_t n,uint32_t type,int32_t forceflag)
 {
 uint32_t len,i; uint8_t serialized[sizeof(struct iguana_msghdr) + (sizeof(uint32_t) + sizeof(bits256))*32 + sizeof(uint64_t)];
 if ( addr == 0 )
 return(-1);
 len = iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr)],(uint32_t *)&n);
 for (i=0; i<n; i++)
 {
 len += iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(uint32_t),&type);
 len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hashes[i].bytes);
 }
 //printf("iguana_request_data.%d %s ht.%d\n",n,bits256_str(hashes[0]),iguana_height(coin,hashes[0]));
 addr->getdatamillis = milliseconds();
 len = iguana_queue_send(addr,0,serialized,"getdata",len,iguana_height(coin,hashes[n-1]),forceflag);
 return(len);
 }*/

void iguana_gotversion(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgversion *vers)
{
    uint8_t serialized[sizeof(struct iguana_msghdr)];
    //printf("gotversion from %s: starting height.%d services.%llx proto.%d\n",addr->ipaddr,vers->nStartingHeight,(long long)vers->nServices,vers->nVersion);
    if ( (vers->nServices & NODE_NETWORK) != 0 )//&& vers->nonce != coin->instance_nonce )
    {
        addr->protover = (vers->nVersion < PROTOCOL_VERSION) ? vers->nVersion : PROTOCOL_VERSION;
        //printf("(%s) proto.%d -> %d\n",addr->ipaddr,vers->nVersion,addr->protover);
        addr->relayflag = vers->relayflag;
        addr->height = vers->nStartingHeight;
        addr->relayflag = 1;
        iguana_gotdata(coin,addr,addr->height);
        iguana_queue_send(addr,0,serialized,"verack",0,0,0);
        //iguana_send_ping(coin,addr);
    }
    else if ( (vers->nServices & (1<<7)) == 0 )
        addr->dead = (uint32_t)time(NULL);
    if ( (vers->nServices & (1<<7)) == (1<<7) )
        addr->supernet = 1;
    if ( addr->supernet != 0 )
        printf("height.%d nServices.%lld nonce.%llu %srelay node.(%s) supernet.%d\n",vers->nStartingHeight,(long long)vers->nServices,(long long)vers->nonce,addr->relayflag==0?"non-":"",addr->ipaddr,addr->supernet);
    if ( (int32_t)vers->nStartingHeight > coin->longestchain )
    {
        if ( coin->badlongestchain != 0 && (int32_t)vers->nStartingHeight >= coin->badlongestchain )
        {
            printf("peer.(%s) gives badlongestchain.%d\n",addr->ipaddr,vers->nStartingHeight);
            addr->dead = 1;
        } else coin->longestchain = vers->nStartingHeight;
    }
    iguana_queue_send(addr,0,serialized,"getaddr",0,0,0);
}

int32_t iguana_send_version(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices)
{
  	int32_t len; struct iguana_msgversion msg; uint8_t serialized[sizeof(struct iguana_msghdr)+sizeof(msg)];
    memset(&msg,0,sizeof(msg));
	msg.nVersion = PROTOCOL_VERSION;
	msg.nServices = myservices;
	msg.nTime = (int64_t)time(NULL);
	msg.nonce = coin->instance_nonce;
	sprintf(msg.strSubVer,"/Satoshi:0.10.0/");
	msg.nStartingHeight = coin->blocks.hwmchain.height;
    iguana_gotdata(coin,addr,msg.nStartingHeight);
    len = iguana_rwversion(1,&serialized[sizeof(struct iguana_msghdr)],&msg,addr->ipaddr,0);
    return(iguana_queue_send(addr,0,serialized,"version",len,0,1));
}

int32_t iguana_send_VPNversion(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices)
{
  	int32_t len; struct iguana_VPNversion msg; uint8_t serialized[sizeof(struct iguana_msghdr)+sizeof(msg)];
    memset(&msg,0,sizeof(msg));
	msg.nVersion = PROTOCOL_VERSION;
	msg.nServices = myservices;
	msg.nTime = (int64_t)time(NULL);
	msg.nonce = 0;//coin->instance_nonce;
	sprintf(msg.strSubVer,"/Satoshi:0.11.99/");
	msg.nStartingHeight = coin->blocks.hwmchain.height;
    len = iguana_rwversion(1,&serialized[sizeof(struct iguana_msghdr)],(void *)&msg,addr->ipaddr,117);
    return(iguana_queue_send(addr,0,serialized,"version",len,0,1));
}

void iguana_gotverack(struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr)];
    if ( addr != 0 )
    {
        //printf("gotverack from %s\n",addr->ipaddr);
        addr->A.nTime = (uint32_t)time(NULL);
        iguana_queue_send(addr,0,serialized,"getaddr",0,0,0);
        if ( addr->supernet != 0 )
        {
            //printf("send getpeers to %s\n",addr->ipaddr);
            iguana_send_supernet(addr,SUPERNET_GETPEERSTR,0);
        }
    }
}

void iguana_gotaddr(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgaddress *A)
{
    char ipaddr[64],ipport[64]; uint32_t ipbits; uint16_t port;
    iguana_rwnum(0,&A->ip[12],sizeof(uint32_t),&ipbits);
    iguana_rwnum(0,(void *)&A->port,sizeof(uint16_t),&port);
    expand_ipbits(ipaddr,ipbits);
    if ( port != 0 )
        sprintf(ipport,"%s:%d",ipaddr,port);
    if ( 0 )
    {
        int32_t i;
        printf("{{");
        for (i=0; i<16; i++)
            printf("0x%02x%s",A->ip[i],i<15?",":"");
        printf("}, 14631},\n");
    }
    iguana_possible_peer(coin,ipport);
    //printf("gotaddr.(%s:%d) from (%s)\n",ipaddr,port,addr->ipaddr);
}

void iguana_gotping(struct iguana_info *coin,struct iguana_peer *addr,uint64_t nonce,uint8_t *data)
{
    int32_t len; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(nonce)];
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint64_t),&nonce);
    if ( memcmp(data,&serialized[sizeof(struct iguana_msghdr)],sizeof(nonce)) != 0 )
        printf("ping ser error %llx != %llx\n",(long long)nonce,*(long long *)data);
    iguana_queue_send(addr,0,serialized,"pong",len,0,0);
    if ( addr->supernet != 0 )
    {
        iguana_send_supernet(addr,SUPERNET_GETPEERSTR,0);
    }
}

int32_t iguana_send_ping(struct iguana_info *coin,struct iguana_peer *addr)
{
  	int32_t len; uint64_t nonce; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(nonce)];
    if ( (nonce= addr->pingnonce) == 0 )
    {
        OS_randombytes((uint8_t *)&nonce,sizeof(nonce));
        addr->pingnonce = ((nonce & 0xffffffff) << 32) | ((uint32_t)addr->ipbits & 0xffffffff);
        addr->pingtime = (uint32_t)time(NULL);
    }
    //printf("pingnonce.%llx from (%s)\n",(long long)nonce,addr->ipaddr);
    iguana_queue_send(addr,0,serialized,"getaddr",0,0,0);
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint64_t),&nonce);
    if ( addr->supernet != 0 )
        iguana_send_supernet(addr,SUPERNET_GETPEERSTR,0);
    return(iguana_queue_send(addr,0,serialized,"ping",len,0,0));
}

int32_t iguana_send_ConnectTo(struct iguana_info *coin,struct iguana_peer *addr)
{
  	int32_t len; uint32_t r; uint16_t port = 1920; uint8_t serialized[sizeof(struct iguana_msghdr) + 6];
    r = rand();
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint32_t),&r);
    len += iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)+len],sizeof(port),&port);
    return(iguana_queue_send(addr,0,serialized,"ConnectTo",len,0,0));
}

void iguana_gotpong(struct iguana_info *coin,struct iguana_peer *addr,uint64_t nonce)
{
    if ( addr->sendmillis != 0 )
    {
        addr->pingtime = (OS_milliseconds() - addr->sendmillis) + 1;
        addr->pingsum += addr->pingtime, addr->numpings++;
        //printf("%s pingtime %.0f numpings.%d [%.3f] ",addr->ipaddr,addr->pingtime,addr->numpings,addr->pingsum/addr->numpings);
    }
    if ( nonce != addr->pingnonce )
    {
        // printf("pong received invalid pingnonce (%s) %llx vs %llx\n",addr->ipaddr,(long long)addr->pingnonce,(long long)nonce);
    } else printf("(%s) pong verified with pingnonce.%llx\n",addr->ipaddr,(long long)addr->pingnonce);
    addr->pingnonce = 0;
    addr->sendmillis = 0;
}

int32_t iguana_gethdrs(struct iguana_info *coin,uint8_t *serialized,char *cmd,char *hashstr)
{
    uint32_t len,n; bits256 hash2; bits256 zero;
    decode_hex(hash2.bytes,sizeof(hash2),hashstr);
    memset(zero.bytes,0,sizeof(zero));
    n = 0;
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint32_t),&n);
    n++;
    len += iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr) + len],(uint32_t *)&n);
    len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hash2.bytes);
    len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),(uint8_t *)zero.bytes);
    return(iguana_sethdr((void *)serialized,coin->chain->netmagic,cmd,&serialized[sizeof(struct iguana_msghdr)],len));
}

int32_t iguana_getdata(struct iguana_info *coin,uint8_t *serialized,int32_t type,bits256 *hashes,int32_t n)
{
    uint32_t len,i; //bits256 hash2;
    len = iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr)],(uint32_t *)&n);
    for (i=0; i<n; i++)
    {
        len += iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(uint32_t),&type);
        len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hashes[i].bytes);
    }
    return(iguana_sethdr((void *)serialized,coin->chain->netmagic,"getdata",&serialized[sizeof(struct iguana_msghdr)],len));
}

int32_t iguana_rwvin(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0; uint32_t tmp;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    if ( rwflag == 1 )
        tmp = msg->scriptlen;
    len += iguana_rwvarint32(rwflag,&serialized[len],&tmp);
    if ( rwflag == 0 )
    {
        msg->scriptlen = tmp;
        msg->vinscript = iguana_memalloc(mem,msg->scriptlen,1);
    }
    len += iguana_rwmem(rwflag,&serialized[len],msg->scriptlen,msg->vinscript);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    //char str[65]; printf("MSGvin.(%s/v%d) script[%d]\n",bits256_str(str,msg->prev_hash),msg->prev_vout,msg->scriptlen);
    //int i; for (i=0; i<msg->scriptlen; i++)
    // printf("%02x ",msg->script[i]);
    //printf(" inscriptlen.%d, prevhash.%llx prev_vout.%d | ",msg->scriptlen,(long long)msg->prev_hash.txid,msg->prev_vout);
    return(len);
}

int32_t debugtest;
int32_t iguana_rwvout(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( rwflag == 0 )
        msg->pk_script = iguana_memalloc(mem,msg->pk_scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->pk_scriptlen,msg->pk_script);
    if ( debugtest != 0 )
    {
        printf("(%.8f scriptlen.%d) ",dstr(msg->value),msg->pk_scriptlen);
        int i; for (i=0; i<msg->pk_scriptlen; i++)
            printf("%02x",msg->pk_script[i]);
        printf("\n");
    }
    return(len);
}

int32_t iguana_rwtx(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t hastimestamp,int32_t isvpncoin)
{
    int32_t i,len = 0; uint8_t *txstart = serialized; char txidstr[65];
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    //printf("version.%d ",msg->version);
    if ( rwflag == 0 )
        msg->vins = iguana_memalloc(mem,msg->tx_in * sizeof(*msg->vins),1);
    for (i=0; i<msg->tx_in; i++)
    {
        len += iguana_rwvin(rwflag,mem,&serialized[len],&msg->vins[i]);
        if ( len > maxsize )
        {
            printf("invalid tx_in.%d len.%d vs maxsize.%d\n",msg->tx_in,len,maxsize);
            return(-1);
        }
    }
    //printf("numvins.%d\n",msg->tx_in);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    //printf("numvouts.%d ",msg->tx_out);
    if ( rwflag == 0 )
        msg->vouts = iguana_memalloc(mem,msg->tx_out * sizeof(*msg->vouts),1);
    for (i=0; i<msg->tx_out; i++)
    {
        len += iguana_rwvout(rwflag,mem,&serialized[len],&msg->vouts[i]);
        if ( len > maxsize )
        {
            printf("invalid tx_out.%d len.%d vs maxsize.%d\n",msg->tx_out,len,maxsize);
            return(-1);
        }
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    if ( isvpncoin != 0 )
    {
        uint16_t ddosflag=0;
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(ddosflag),&ddosflag);
        for (; serialized[len]!=0&&len<maxsize; len++) // eat null terminated string
            ;
    }
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    msg->allocsize = len;
    return(len);
}

char *iguana_txscan(struct iguana_info *coin,cJSON *json,uint8_t *data,int32_t recvlen,bits256 txid)
{
    struct iguana_msgtx tx; bits256 hash2; struct iguana_block block; struct iguana_msgblock msg;
    int32_t i,n,len,extralen = 65356; char *txbytes,vpnstr[64]; uint8_t *extraspace;
    memset(&msg,0,sizeof(msg));
    vpnstr[0] = 0;
    extraspace = calloc(1,extralen);
    len = iguana_rwblock(coin->symbol,coin->chain->hashalgo,0,&hash2,data,&msg);
    iguana_blockconv(&block,&msg,hash2,-1);
    for (i=0; i<msg.txn_count; i++)
    {
        if ( (n= iguana_rwmsgtx(coin,0,0,&data[len],recvlen - len,&tx,&tx.txid,vpnstr,extraspace,extralen)) < 0 )
            break;
        //char str[65]; printf("%d of %d: %s\n",i,msg.txn_count,bits256_str(str,tx.txid));
        if ( bits256_cmp(txid,tx.txid) == 0 )
        {
            if ( (n= iguana_rwmsgtx(coin,0,json,&data[len],recvlen - len,&tx,&tx.txid,vpnstr,extraspace,extralen)) > 0 )
            {
                txbytes = malloc(n*2+1);
                init_hexbytes_noT(txbytes,&data[len],n);
                free(extraspace);
                return(txbytes);
            }
        }
        len += n;
    }
    return(0);
}

int32_t iguana_gentxarray(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_txblock *txdata,int32_t *lenp,uint8_t *data,int32_t recvlen)
{
    struct iguana_msgtx *tx; bits256 hash2; struct iguana_msgblock msg; int32_t i,n,len,numvouts,numvins;
    memset(&msg,0,sizeof(msg));
    len = iguana_rwblock(coin->symbol,coin->chain->hashalgo,0,&hash2,data,&msg);
    iguana_blockconv(&txdata->block,&msg,hash2,-1);
    tx = iguana_memalloc(mem,msg.txn_count*sizeof(*tx),1);
    for (i=numvins=numvouts=0; i<msg.txn_count; i++)
    {
        if ( (n= iguana_rwtx(0,mem,&data[len],&tx[i],recvlen - len,&tx[i].txid,coin->chain->hastimestamp,strcmp(coin->symbol,"VPN")==0)) < 0 )
            break;
        numvouts += tx[i].tx_out;
        numvins += tx[i].tx_in;
        len += n;
    }
    if ( coin->chain->hastimestamp != 0 && len != recvlen && data[len] == (recvlen - len - 1) )
    {
        //printf("\n>>>>>>>>>>> len.%d vs recvlen.%d [%d]\n",len,recvlen,data[len]);
        memcpy(txdata->space,&data[len],recvlen-len);
        len += (recvlen-len);
        txdata->extralen = (recvlen - len);
    } else txdata->extralen = 0;
    txdata->recvlen = len;
    txdata->numtxids = msg.txn_count;
    txdata->numunspents = numvouts;
    txdata->numspends = numvins;
    return(len);
}

int32_t iguana_send_hashes(struct iguana_info *coin,char *command,struct iguana_peer *addr,bits256 stophash,bits256 *hashes,int32_t n)
{
  	uint32_t len,nVersion,varint; int32_t retval = -1; uint8_t *serialized; long size;
    size = sizeof(struct iguana_msghdr) + sizeof(uint64_t) + 1 + sizeof(bits256)*(n+1);
    if ( (varint= n) <= IGUANA_MAXINV )
    {
        serialized = mycalloc('h',1,size);
        nVersion = 0;
        len = iguana_rwblockhash(1,&serialized[sizeof(struct iguana_msghdr)],&nVersion,&varint,hashes,&stophash);
        //printf("%s send_hashes.%d %s height.%d\n",addr->ipaddr,n,bits256_str(hashes[0]),iguana_height(coin,hashes[0]));
        retval = iguana_queue_send(addr,0,serialized,command,len,0,0);
        myfree(serialized,size);
    } else printf("iguana_send_hashes: unexpected n.%d\n",n);
    return(retval);
}

int32_t iguana_intvectors(struct iguana_info *coin,struct iguana_peer *addr,int32_t processflag,uint8_t *data,int32_t datalen) // other side needs to be a bit smart about what hashes are sents in
{
    uint32_t type; bits256 *txids=0,*quotes=0,*blockhashes=0,hash; int32_t i,n,q,m,len; uint64_t x;
    len = n = m = q = 0;
    len += iguana_rwvarint(0,&data[len],&x);
    for (i=0; i<x; i++)
    {
        len += iguana_rwnum(0,&data[len],sizeof(uint32_t),&type);
        len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash.bytes);
        if ( type == MSG_TX )
        {
            if ( txids == 0 )
                txids = mycalloc('t',(int32_t)x+1,sizeof(*txids));
            txids[m++] = hash;
            if ( (rand() % 1000) == 0 && i == x-1 )
                printf("%s %d of %d: tx.%llx len.%d\n",addr->ipaddr,i,(int32_t)x,(long long)hash.txid,len);
        }
        else if ( type == MSG_BLOCK )
        {
            if ( blockhashes == 0 )
            {
                blockhashes = mycalloc('f',(int32_t)x+1,sizeof(*blockhashes));
                n = 1;
            }
            blockhashes[n++] = hash;
        }
        else if ( type == MSG_QUOTE )
        {
            if ( quotes == 0 )
            {
                quotes = mycalloc('q',(int32_t)x+1,sizeof(*quotes));
                q = 1;
            }
            quotes[q++] = hash;
        }
        else if ( type == MSG_FILTERED_BLOCK )
            printf(" %d of %d: merkle.%llx\n",i,(int32_t)x,(long long)hash.txid);
        else printf("what type is %d\n",type);
    }
    if ( n > 0 )
    {
        if ( n != x+1 )
        {
            printf("n.%d != x.%d -> realloc blockhashes\n",n,(int32_t)x+1);
            blockhashes = myrealloc('f',blockhashes,(int32_t)((x+1)*sizeof(*blockhashes)),n*sizeof(*blockhashes));
        } // else printf("n.%d == x.%d\n",n,(int32_t)x);
        if ( processflag != 0 )
            iguana_gotblockhashesM(coin,addr,blockhashes,n), blockhashes = 0;
    }
    if ( m > 0 )
    {
        if ( m != x )
            txids = myrealloc('t',txids,(int32_t)((x+1)*sizeof(*txids)),(m+1)*sizeof(*txids));
        if ( processflag != 0 )
            iguana_gottxidsM(coin,addr,txids,m), txids = 0;
    }
    if ( q > 0 )
    {
        if ( q != x )
            quotes = myrealloc('q',quotes,(int32_t)((x+1)*sizeof(*quotes)),(q+1)*sizeof(*quotes));
        if ( processflag != 0 )
            iguana_gotquotesM(coin,addr,quotes,q), quotes = 0;
    }
    if ( txids != 0 )
        myfree(txids,sizeof(*txids) * (x+1));
    if ( blockhashes != 0 )
        myfree(blockhashes,sizeof(*blockhashes) * (x+1));
    return(len);
    //printf("intvectors.%c recvlen.%d\n",intvectors,recvlen);
}

int32_t iguana_msgparser(struct iguana_info *coin,struct iguana_peer *addr,struct OS_memspace *rawmem,struct OS_memspace *txmem,struct OS_memspace *hashmem,struct iguana_msghdr *H,uint8_t *data,int32_t recvlen)
{
    uint8_t serialized[16384]; char *retstr; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    int32_t i,n,retval,ishost,delay,srvmsg,bloom,sendlen=0,intvectors,len= -100; uint64_t nonce,x;  bits256 hash2;
    bloom = intvectors = srvmsg = -1;
    if ( addr != 0 )
    {
        //printf("iguana_msgparser from (%s) parse.(%s) len.%d\n",addr->ipaddr,H->command,recvlen);
        //iguana_peerblockrequest(coin,addr->blockspace,IGUANA_MAXPACKETSIZE,addr,iguana_blockhash(coin,100),0);
        addr->lastcontact = (uint32_t)time(NULL);
        strcpy(addr->lastcommand,H->command);
        if ( strncmp(H->command,"SuperNET",strlen("SuperNET")) == 0 )
        {
            addr->supernet = 1;
            addr->msgcounts.verack++;
            len = recvlen;
            if ( (retstr= SuperNET_p2p(coin,addr,&delay,addr->ipaddr,data,recvlen,H->command[strlen("SuperNET")]=='b')) != 0 )
            {
                cJSON *rawtxjson;
                if ( (rawtxjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( jstr(rawtxjson,"method") != 0 && strcmp(jstr(rawtxjson,"method"),"rawtx_return") == 0 )
                    {
                        ;
                    }
                }
                iguana_send_supernet(addr,retstr,delay);
                free(retstr);
            }
            //printf("GOT.(%s) len.%d from %s -> ret.(%s)\n",H->command,recvlen,addr->ipaddr,retstr==0?"null":retstr);
            return(0);
        }
        else if ( strcmp(H->command,"InstantDEX") == 0 )
        {
            char *str;
            printf("peer InstantDEX message datalen.%d\n",recvlen);
            if ( (str= InstantDEX_hexmsg(myinfo,category_find(myinfo->instantdex_category,GENESIS_PUBKEY),data,recvlen,addr->ipaddr)) != 0 )
                free(str);
            //SuperNET_hexmsgadd(myinfo,myinfo->instantdex_category,GENESIS_PUBKEY,(char *)serialized,tai_now(),addr->ipaddr);
            return(0);
        }
        else if ( strcmp(H->command,"pangea") == 0 )
        {
            //init_hexbytes_noT(0,data,recvlen);
            printf("skip pangea InstantDEX message\n");
            //SuperNET_hexmsgadd(myinfo,myinfo->pangea_category,GENESIS_PUBKEY,0,tai_now(),addr->ipaddr);
            return(0);
        }
        else if ( strcmp(H->command,"quote") == 0 )
        {
            printf("got full quote from %s\n",addr->ipaddr);
            instantdex_quotep2p(myinfo,coin,addr,data,recvlen);
            return(0);
        }
    }
    retval = 0;
    if ( (ishost= (strcmp(H->command,"getblocks") == 0)) || strcmp(H->command,"block") == 0 )
    {
        if ( addr != 0 )
        {
            struct iguana_txblock txdata;
            iguana_memreset(rawmem), iguana_memreset(txmem);
            memset(&txdata,0,sizeof(txdata));
            if ( ishost == 0 )
            {
                addr->msgcounts.block++;
                if ( (n= iguana_gentxarray(coin,rawmem,&txdata,&len,data,recvlen)) == recvlen )
                {
                    len = n;
                    iguana_gotblockM(coin,addr,&txdata,rawmem->ptr,H,data,recvlen);
                }
                else
                {
                    //for (i=0; i<recvlen; i++)
                    //    printf("%02x",data[i]);
                    printf(" parse error block txn_count.%d, n.%d len.%d vs recvlen.%d from.(%s)\n",txdata.block.RO.txn_count,n,len,recvlen,addr->ipaddr);
                }
            }
            else
            {
                len = iguana_peergetrequest(coin,addr,data,recvlen,1);
            }
        }
    }
    else if ( (ishost= (strncmp(H->command,"inv",3) == 0)) || strncmp(H->command,"getdata",7) == 0 )
    {
        if ( addr != 0 )
        {
            if ( ishost == 0 )
            {
                addr->msgcounts.getdata++;
                len = iguana_peerdatarequest(coin,addr,data,recvlen);
            }
            else
            {
                intvectors = 'I', addr->msgcounts.inv++;
                if ( 0 && strcmp(H->command,"inv2") == 0 )
                    printf("GOT INV2.%d\n",recvlen);
                len = iguana_intvectors(coin,addr,1,data,recvlen); // indirectly issues getdata
            }
        }
    }
    else if ( (ishost= (strcmp(H->command,"getheaders") == 0)) || strcmp(H->command,"headers") == 0 )
    {
        struct iguana_msgblock msg; struct iguana_block *blocks; uint32_t n=0;
        len = 0;
        if ( addr != 0 )
        {
            if ( ishost == 0 )
            {
                len = iguana_rwvarint32(0,data,&n);
                if ( n <= IGUANA_MAXINV )
                {
                    blocks = mycalloc('i',1,sizeof(*blocks) * n);
                    for (i=0; i<n; i++)
                    {
                        len += iguana_rwblock(coin->symbol,coin->chain->hashalgo,0,&hash2,&data[len],&msg);
                        iguana_blockconv(&blocks[i],&msg,hash2,-1);
                    }
                    iguana_gotheadersM(coin,addr,blocks,n);
                    //myfree(blocks,sizeof(*blocks) * n);
                    if ( len == recvlen && addr != 0 )
                        addr->msgcounts.headers++;
                } else printf("got unexpected n.%d for headers\n",n);
            }
            else if ( addr->headerserror == 0 )
                len = iguana_peergetrequest(coin,addr,data,recvlen,0);
        }
    }
    else if ( (ishost= (strcmp(H->command,"version") == 0)) || strcmp(H->command,"verack") == 0 )
    {
        if ( addr != 0 )
        {
            if ( ishost != 0 )
            {
                struct iguana_msgversion recvmv;
                len = iguana_rwversion(0,data,&recvmv,addr->ipaddr,recvlen);
                if ( len <= recvlen )
                    iguana_gotversion(coin,addr,&recvmv);
                addr->msgcounts.version++;
            }
            else
            {
                iguana_gotverack(coin,addr);
                addr->msgcounts.verack++;
                len = 0;
            }
        }
    }
    else if ( (ishost= (strcmp(H->command,"ping") == 0)) || strcmp(H->command,"pong") == 0 )
    {
        len = 0;
        if ( recvlen == sizeof(uint64_t) && addr != 0 )
        {
            len = iguana_rwnum(0,data,sizeof(uint64_t),&nonce);
            if ( addr != 0 )
            {
                //printf("%u got nonce.%llx from %s\n",(uint32_t)time(NULL),(long long)nonce,addr->ipaddr);
                if ( ishost != 0 )
                {
                    iguana_gotping(coin,addr,nonce,data);
                    addr->msgcounts.ping++;
                }
                else
                {
                    iguana_gotpong(coin,addr,nonce);
                    addr->msgcounts.pong++;
                }
                iguana_queue_send(addr,0,serialized,"getaddr",0,0,0);
            }
        }
    }
    else if ( (ishost= (strcmp(H->command,"getaddr") == 0)) || strcmp(H->command,"addr") == 0 )
    {
        struct iguana_msgaddress A;
        if ( addr != 0 )
        {
            if ( ishost == 0 )
            {
                len = iguana_rwvarint(0,data,&x);
                for (i=0; i<x; i++)
                {
                    memset(&A,0,sizeof(A));
                    len += iguana_rwaddr(0,&data[len],&A,(int32_t)addr->protover);
                    iguana_gotaddr(coin,addr,&A);
                }
                if ( len == recvlen )
                {
                    addr->lastgotaddr = (uint32_t)time(NULL);
                    addr->msgcounts.addr++;
                }
            }
            else
            {
                len = 0;
                if ( (sendlen= iguana_peeraddrrequest(coin,addr,&addr->blockspace[sizeof(H)],IGUANA_MAXPACKETSIZE)) > 0 )
                {
                    if ( 0 )
                    {
                        int32_t checklen; uint32_t checkbits; uint16_t checkport; char checkaddr[64];
                        checklen = iguana_rwvarint(0,&addr->blockspace[sizeof(H)],&x);
                        for (i=0; i<sendlen; i++)
                            printf("%02x",addr->blockspace[sizeof(H)+i]);
                        printf(" %p addr sendlen.%d\n",&addr->blockspace[sizeof(H)],sendlen);
                        for (i=0; i<x; i++)
                        {
                            memset(&A,0,sizeof(A));
                            checklen += iguana_rwaddr(0,&addr->blockspace[sizeof(H) + checklen],&A,(int32_t)addr->protover);
                            iguana_rwnum(0,&A.ip[12],sizeof(uint32_t),&checkbits);
                            iguana_rwnum(0,(void *)&A.port,sizeof(uint16_t),&checkport);
                            expand_ipbits(checkaddr,checkbits);
                            printf("checkaddr.(%s:%u) ",checkaddr,checkport);
                        }
                        printf("x.%d\n",(int32_t)x);
                    }
                    retval = iguana_queue_send(addr,0,addr->blockspace,"addr",sendlen,0,0);
                }
                addr->msgcounts.getaddr++;
            }
        }
        //printf("%s -> addr recvlen.%d num.%d\n",addr->ipaddr,recvlen,(int32_t)x);
    }
    else if ( strcmp(H->command,"notfound") == 0 )
    {
        if ( addr != 0 )
        {
            printf("%s SERVER notfound\n",addr->ipaddr);
            intvectors = 'N', addr->msgcounts.notfound++;
            len = iguana_intvectors(coin,addr,1,data,recvlen);
        }
    }
    else if ( strcmp(H->command,"mempool") == 0 )
    {
        if ( addr != 0 )
        {
            printf("%s SERVER mempool\n",addr->ipaddr);
            srvmsg = 'M', addr->msgcounts.mempool++;
        }
    }
    else if ( strcmp(H->command,"tx") == 0 )
    {
        struct iguana_msgtx *tx;
        iguana_memreset(rawmem);
        tx = iguana_memalloc(rawmem,sizeof(*tx),1);//mycalloc('u',1,sizeof(*tx));
        len = iguana_rwtx(0,rawmem,data,tx,recvlen,&tx->txid,coin->chain->hastimestamp,strcmp(coin->symbol,"VPN")==0);
        if ( addr != 0 )
        {
            iguana_gotunconfirmedM(coin,addr,tx,data,recvlen);
            printf("tx recvlen.%d vs len.%d\n",recvlen,len);
            addr->msgcounts.tx++;
        }
    }
    else if ( addr != 0 && strcmp(H->command,"ConnectTo") == 0 )
    {
        iguana_queue_send(addr,0,serialized,"getaddr",0,0,0);
        len = 6;
    }
    else if ( strcmp(H->command,"reject") == 0 )
    {
        if ( addr != 0 )
        {
            if ( strncmp((char *)data+1,"headers",7) == 0 )
                addr->headerserror++;
            else
            {
                for (i=0; i<recvlen; i++)
                    printf("%02x ",data[i]);
                printf("reject.(%s) recvlen.%d %s proto.%d\n",data+1,recvlen,addr->ipaddr,addr->protover);
                addr->msgcounts.reject++;
            }
        }
        len = recvlen;
    }
    else if ( strcmp(H->command,"alert") == 0 )
    {
        for (i=0; i<recvlen; i++)
            printf("%02x ",data[i]);
        printf("alert.(%s)\n",data+1);
        len = recvlen;
        if ( len == recvlen && addr != 0 )
            addr->msgcounts.alert++;
    }
    else if ( addr != 0 )
    {
        if ( strcmp(H->command,"filterload") == 0 ) // for bloom
            bloom = 'L', addr->msgcounts.filterload++;
        else if ( strcmp(H->command,"filteradd") == 0 ) // for bloom
            bloom = 'A', addr->msgcounts.filteradd++;
        else if ( strcmp(H->command,"filterclear") == 0 ) // for bloom
            bloom = 'C', addr->msgcounts.filterclear++;
        else if ( strcmp(H->command,"merkleblock") == 0 ) // for bloom
            bloom = 'M', addr->msgcounts.merkleblock++;
    }
    if ( bloom >= 0 || srvmsg >= 0 )
        len = recvlen; // just mark as valid
    if ( len != recvlen && len != recvlen-1 && len != recvlen-2 )
    {
        //printf("error.(%s) (%s): len.%d != recvlen.%d\n",H->command,addr->ipaddr,len,recvlen);
        //for (i=0; i<len; i++)
        //    printf("%02x",data[i]);
        if ( strcmp(H->command,"addr") != 0 )
            printf("%s %s.%s len mismatch %d != %d\n",coin->symbol,addr!=0?addr->ipaddr:"local",H->command,len,recvlen);
    }
    else if ( len != recvlen )
    {
        printf("%s extra byte.[%02x] command.%s len.%d recvlen.%d\n",addr->ipaddr,data[recvlen-1],H->command,len,recvlen);
        //retval = -1;
    }
    return(retval);
}

