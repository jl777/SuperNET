//
// Created by artem on 24.01.18.
//
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ETOMIC_TESTNET
#define ETOMIC_ALICECONTRACT "0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c"
#define ETOMIC_BOBCONTRACT "0x2a8e4f9ae69c86e277602c6802085febc4bd5986"
#else
#define ETOMIC_ALICECONTRACT "0x9bc5418ceded51db08467fc4b62f32c5d9ebda55"
#define ETOMIC_BOBCONTRACT "0xfef736cfa3b884669a4e0efd6a081250cce228e7"
#endif

#define EMPTY_ETH_TX_ID "0x0000000000000000000000000000000000000000000000000000000000000000"

typedef struct {
    char from[65];
    char to[65];
    char amount[100];
    char secretKey[70];
} BasicTxData;

typedef struct {
    char dealId[70];
    char bobAddress[65];
    char aliceHash[65];
    char bobHash[65];
} AliceSendsEthPaymentInput;

typedef struct {
    char dealId[70];
    char amount[100];
    char tokenAddress[65];
    char bobAddress[65];
    char aliceHash[65];
    char bobHash[65];
    uint8_t decimals;
} AliceSendsErc20PaymentInput;

typedef struct {
    char dealId[70];
    char amount[100];
    char tokenAddress[65];
    char bobAddress[65];
    char aliceHash[65];
    char bobSecret[70];
    uint8_t decimals;
} AliceReclaimsAlicePaymentInput;

typedef struct {
    char dealId[70];
    char amount[100];
    char tokenAddress[65];
    char aliceAddress[65];
    char aliceSecret[70];
    char bobHash[65];
    uint8_t decimals;
} BobSpendsAlicePaymentInput;

typedef struct {
    char depositId[70];
    char aliceAddress[65];
    char bobHash[65];
    uint64_t lockTime;
} BobSendsEthDepositInput;

typedef struct {
    char depositId[70];
    char amount[100];
    char tokenAddress[65];
    char aliceAddress[65];
    char bobHash[65];
    uint64_t lockTime;
    uint8_t decimals;
} BobSendsErc20DepositInput;

typedef struct {
    char depositId[70];
    char amount[100];
    char tokenAddress[65];
    char aliceAddress[65];
    char bobSecret[70];
    uint8_t decimals;
} BobRefundsDepositInput;

typedef struct {
    char depositId[70];
    char amount[100];
    char tokenAddress[65];
    char bobAddress[65];
    char bobHash[65];
    uint8_t decimals;
} AliceClaimsBobDepositInput;

typedef struct {
    char paymentId[70];
    char aliceAddress[65];
    char aliceHash[65];
    uint64_t lockTime;
} BobSendsEthPaymentInput;

typedef struct {
    char paymentId[70];
    char amount[100];
    char tokenAddress[65];
    char aliceAddress[65];
    char aliceHash[65];
    uint64_t lockTime;
    uint8_t decimals;
} BobSendsErc20PaymentInput;

typedef struct {
    char paymentId[70];
    char amount[100];
    char tokenAddress[65];
    char aliceAddress[65];
    char aliceHash[65];
    uint8_t decimals;
} BobReclaimsBobPaymentInput;

typedef struct {
    char paymentId[70];
    char amount[100];
    char tokenAddress[65];
    char aliceSecret[70];
    char bobAddress[65];
    uint8_t decimals;
} AliceSpendsBobPaymentInput;

typedef struct {
    char tokenAddress[65];
    char owner[65];
    char spender[65];
    char amount[100];
    char secret[70];
} ApproveErc20Input;

char *approveErc20(ApproveErc20Input input);

char* aliceSendsEthPayment(AliceSendsEthPaymentInput input, BasicTxData txData);
uint8_t verifyAliceEthPaymentData(AliceSendsEthPaymentInput input, char *data);

char* aliceSendsErc20Payment(AliceSendsErc20PaymentInput input, BasicTxData txData);
uint8_t verifyAliceErc20PaymentData(AliceSendsErc20PaymentInput input, char *data);

char* aliceReclaimsAlicePayment(AliceReclaimsAlicePaymentInput input, BasicTxData txData);
char* bobSpendsAlicePayment(BobSpendsAlicePaymentInput input, BasicTxData txData);

char* bobSendsEthDeposit(BobSendsEthDepositInput input, BasicTxData txData);
uint8_t verifyBobEthDepositData(BobSendsEthDepositInput input, char *data);

char* bobSendsErc20Deposit(BobSendsErc20DepositInput input, BasicTxData txData);
uint8_t verifyBobErc20DepositData(BobSendsErc20DepositInput input, char *data);

char* bobRefundsDeposit(BobRefundsDepositInput input, BasicTxData txData);
char* aliceClaimsBobDeposit(AliceClaimsBobDepositInput input, BasicTxData txData);

char* bobSendsEthPayment(BobSendsEthPaymentInput input, BasicTxData txData);
uint8_t verifyBobEthPaymentData(BobSendsEthPaymentInput input, char *data);

char* bobSendsErc20Payment(BobSendsErc20PaymentInput input, BasicTxData txData);
uint8_t verifyBobErc20PaymentData(BobSendsErc20PaymentInput input, char *data);

char* bobReclaimsBobPayment(BobReclaimsBobPaymentInput input, BasicTxData txData);
char* aliceSpendsBobPayment(AliceSpendsBobPaymentInput input, BasicTxData txData);

char* privKey2Addr(char* privKey);
char* pubKey2Addr(char* pubKey);
char* getPubKeyFromPriv(char* privKey);

// returns satoshis, not wei!
uint64_t getEthBalance(char* address, int *error);
uint64_t getErc20BalanceSatoshi(char *address, char *tokenAddress, uint8_t setDecimals, int *error);
char *getErc20BalanceHexWei(char* address, char tokenAddress[65]);

uint8_t getErc20Decimals(char *tokenAddress);

// returns satoshis, not wei!
uint64_t getErc20Allowance(char *owner, char *spender, char *tokenAddress, uint8_t set_decimals);

void uint8arrayToHex(char *dest, uint8_t *input, int len);
void satoshisToWei(char *dest, uint64_t input);
uint64_t weiToSatoshi(char *wei);

char *sendEth(char *to, char *amount, char *privKey, uint8_t waitConfirm, int64_t gas, int64_t gasPrice, uint8_t defaultGasOnErr);
char *sendErc20(
        char *tokenAddress,
        char *to,
        char *amount,
        char *privKey,
        uint8_t waitConfirm,
        int64_t gas,
        int64_t gasPrice,
        uint8_t defaultGasOnErr,
        uint8_t decimals
);

uint8_t verifyAliceErc20FeeData(char* tokenAddress, char *to, char *amount, char *data, uint8_t decimals);

uint8_t alicePaymentStatus(char *paymentId);
uint8_t bobDepositStatus(char *depositId);
uint8_t bobPaymentStatus(char *paymentId);

uint64_t estimate_erc20_gas(
        char *tokenAddress,
        char *to,
        char *amount,
        char *privKey,
        uint8_t decimals
);

uint8_t compareAddresses(char *address1, char *address2);
uint8_t isValidAddress(char *address);
uint8_t getErc20DecimalsZeroOnError(char *tokenAddress);

#ifdef __cplusplus
}
#endif
