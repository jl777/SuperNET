
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
//  LP_etomic.c
//  marketmaker
//

//
// Created by artem on 24.01.18.
//
#ifdef __cplusplus
extern "C" {
#endif
    typedef struct {
        char* from;
        char* to;
        char* amount;
        int nonce;
        char* secretKey;
    } BasicTxData;
    
    typedef struct {
        char* dealId;
        char* bobAddress;
        char* aliceHash;
        char* bobHash;
    } AliceInitEthInput;
    
    typedef struct {
        char* dealId;
        char* amount;
        char* tokenAddress;
        char* bobAddress;
        char* aliceHash;
        char* bobHash;
    } AliceInitErc20Input;
    
    typedef struct {
        char* dealId;
        char* amount;
        char* tokenAddress;
        char* bobAddress;
        char* aliceHash;
        char* bobSecret;
    } AliceReclaimsAlicePaymentInput;
    
    typedef struct {
        char* dealId;
        char* amount;
        char* tokenAddress;
        char* aliceAddress;
        char* aliceSecret;
        char* bobHash;
    } BobSpendsAlicePaymentInput;
    
    typedef struct {
        char* depositId;
        char* aliceAddress;
        char* bobHash;
    } BobMakesEthDepositInput;
    
    typedef struct {
        char* depositId;
        char* amount;
        char* tokenAddress;
        char* aliceAddress;
        char* bobHash;
    } BobMakesErc20DepositInput;
    
    typedef struct {
        char* depositId;
        char* amount;
        char* tokenAddress;
        char* aliceAddress;
        char* bobSecret;
        char* aliceCanClaimAfter;
    } BobRefundsDepositInput;
    
    typedef struct {
        char* depositId;
        char* amount;
        char* tokenAddress;
        char* bobAddress;
        char* bobHash;
        char* aliceCanClaimAfter;
    } AliceClaimsBobDepositInput;
    
    typedef struct {
        char* paymentId;
        char* aliceAddress;
        char* aliceHash;
    } BobMakesEthPaymentInput;
    
    typedef struct {
        char* paymentId;
        char* amount;
        char* tokenAddress;
        char* aliceAddress;
        char* aliceHash;
    } BobMakesErc20PaymentInput;
    
    typedef struct {
        char* paymentId;
        char* amount;
        char* tokenAddress;
        char* aliceAddress;
        char* aliceHash;
        char* bobCanClaimAfter;
    } BobReclaimsBobPaymentInput;
    
    typedef struct {
        char* paymentId;
        char* amount;
        char* tokenAddress;
        char* aliceSecret;
        char* bobAddress;
        char* bobCanClaimAfter;
    } AliceSpendsBobPaymentInput;
    
    // Your prototype or Definition
#ifdef __cplusplus
}
#endif

#define ETOMIC_ALICECONTRACT "0xe1D4236C5774D35Dc47dcc2E5E0CcFc463A3289c"
#define ETOMIC_BOBCONTRACT "0x9387Fd3a016bB0205e4e131Dde886B9d2BC000A2"
#define ETOMIC_SATOSHICAT "0000000000"

char *aliceInitsEthDeal(AliceInitEthInput input,BasicTxData txData);
char *aliceInitsErc20Deal(AliceInitErc20Input input,BasicTxData txData);
//char *aliceMakesEthPayment(AliceMakesEthPaymentInput input,BasicTxData txData);
//char *aliceMakesErc20Payment(AliceMakesErc20PaymentInput input,BasicTxData txData);
char *aliceSpendsBobPayment(AliceSpendsBobPaymentInput input,BasicTxData txData);
char *aliceReclaimsAlicePayment(AliceReclaimsAlicePaymentInput input,BasicTxData txData);
char *aliceClaimsBobDeposit(AliceClaimsBobDepositInput input,BasicTxData txData);

char *bobMakesEthDeposit(BobMakesEthDepositInput input,BasicTxData txData);
char *bobMakesErc20Deposit(BobMakesErc20DepositInput input,BasicTxData txData);
char *bobMakesEthPayment(BobMakesEthPaymentInput input,BasicTxData txData);
char *bobMakesErc20Payment(BobMakesErc20PaymentInput input,BasicTxData txData);
char *bobSpendsAlicePayment(BobSpendsAlicePaymentInput input,BasicTxData txData);
char *bobReclaimsBobPayment(BobReclaimsBobPaymentInput input,BasicTxData txData);
char *bobRefundsDeposit(BobRefundsDepositInput input,BasicTxData txData);

char *approveErc20(char *amount,char *from,char *secret,char *buffer,int32_t nonce);

int32_t LP_etomicsymbol(char *etomic,char *symbol)
{
    struct iguana_info *coin;
    etomic[0] = 0;
    if ( (coin= LP_coinfind(symbol)) != 0 )
        strcpy(etomic,coin->etomic);
    return(etomic[0] != 0);
}

char *LP_etomicalice_start(struct basilisk_swap *swap)
{
    AliceInitEthInput input; AliceInitErc20Input input20; BasicTxData txData;
    // set input and txData fields from the swap data structure
    memset(&txData,0,sizeof(txData));
    if ( strcmp(swap->I.alicestr,"ETH") == 0 )
    {
        memset(&input,0,sizeof(input));
        //return(aliceInitsEthDeal(input,txData));
    }
    else
    {
        memset(&input20,0,sizeof(input20));
        //return(aliceInitsErc20Deal(input20,txData));
    }
    return(0);
}
