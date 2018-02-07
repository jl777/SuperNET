//
// Created by artem on 24.01.18.
//
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    char* from;
    char* to;
    char* amount;
    char* secretKey;
} BasicTxData;

typedef struct {
    char* dealId;
    char* bobAddress;
    char* aliceHash;
    char* bobHash;
} AliceSendsEthPaymentInput;

typedef struct {
    char* dealId;
    char* amount;
    char* tokenAddress;
    char* bobAddress;
    char* aliceHash;
    char* bobHash;
} AliceSendsErc20PaymentInput;

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
} BobSendsEthDepositInput;

typedef struct {
    char* depositId;
    char* amount;
    char* tokenAddress;
    char* aliceAddress;
    char* bobHash;
} BobSendsErc20DepositInput;

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
} BobSendsEthPaymentInput;

typedef struct {
    char* paymentId;
    char* amount;
    char* tokenAddress;
    char* aliceAddress;
    char* aliceHash;
} BobSendsErc20PaymentInput;

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

char* approveErc20(char* amount, char* from, char* secret);
char* aliceSendsEthPayment(AliceSendsEthPaymentInput input, BasicTxData txData);
char* aliceSendsErc20Payment(AliceSendsErc20PaymentInput input, BasicTxData txData);
char* aliceReclaimsAlicePayment(AliceReclaimsAlicePaymentInput input, BasicTxData txData);
char* bobSpendsAlicePayment(BobSpendsAlicePaymentInput input, BasicTxData txData);
char* bobSendsEthDeposit(BobSendsEthDepositInput input, BasicTxData txData);
char* bobSendsErc20Deposit(BobSendsErc20DepositInput input, BasicTxData txData);
char* bobRefundsDeposit(BobRefundsDepositInput input, BasicTxData txData);
char* aliceClaimsBobDeposit(AliceClaimsBobDepositInput input, BasicTxData txData);
char* bobSendsEthPayment(BobSendsEthPaymentInput input, BasicTxData txData);
char* bobSendsErc20Payment(BobSendsErc20PaymentInput input, BasicTxData txData);
char* bobReclaimsBobPayment(BobReclaimsBobPaymentInput input, BasicTxData txData);
char* aliceSpendsBobPayment(AliceSpendsBobPaymentInput input, BasicTxData txData);
char* privKey2Addr(char* privKey);
char* pubKey2Addr(char* pubKey);
char* getPubKeyFromPriv(char* privKey);
uint64_t getEthBalance(char* address);
uint64_t getErc20Balance(char* address, char* tokenAddress);
// Your prototype or Definition
#ifdef __cplusplus
}
#endif
