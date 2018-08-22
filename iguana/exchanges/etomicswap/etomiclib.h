//
// Created by artem on 24.01.18.
//
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETOMIC_ALICECONTRACT "0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c"
#define ETOMIC_BOBCONTRACT "0x2a8e4f9ae69c86e277602c6802085febc4bd5986"

#define EMPTY_ETH_TX_ID "0x0000000000000000000000000000000000000000000000000000000000000000"

typedef struct {
    char from[65];
    char to[65];
    char amount[100];
    char secretKey[70];
} BasicTxData;

typedef struct {
    char deal_id[70];
    char bob_address[65];
    char alice_hash[65];
    char bob_hash[65];
    uint64_t amount;
} AliceSendsEthPaymentInput;

typedef struct {
    char deal_id[70];
    uint64_t amount;
    char token_address[65];
    char bob_address[65];
    char alice_hash[65];
    char bob_hash[65];
    uint8_t decimals;
} AliceSendsErc20PaymentInput;

typedef struct {
    char deal_id[70];
    uint64_t amount;
    char token_address[65];
    char bob_address[65];
    char alice_hash[65];
    char bob_secret[70];
    uint8_t decimals;
} AliceReclaimsPaymentInput;

typedef struct {
    char deal_id[70];
    uint64_t amount;
    char token_address[65];
    char alice_address[65];
    char alice_secret[70];
    char bob_hash[65];
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
    char token_address[65];
    char spender[65];
    uint64_t amount;
    uint8_t decimals;
} ApproveErc20Input;

extern char *approve_erc20(ApproveErc20Input input, void *eth_client);

extern char *alice_sends_eth_payment(AliceSendsEthPaymentInput input, void *eth_client);
extern uint8_t verify_alice_eth_payment_data(AliceSendsEthPaymentInput input, char *data);

extern char *alice_sends_erc20_payment(AliceSendsErc20PaymentInput input, void *eth_client);
extern uint8_t verify_alice_erc20_payment_data(AliceSendsErc20PaymentInput input, char *data);

extern char* alice_reclaims_payment(AliceReclaimsPaymentInput input, void *eth_client);
extern char* bob_spends_alice_payment(BobSpendsAlicePaymentInput input, void *eth_client);

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

extern char *priv_key_2_addr(char* privKey);
extern char *pub_key_2_addr(char* pubKey);
extern char *priv_key_2_pub_key(char* privKey);

// returns satoshis, not wei!
extern uint64_t get_eth_balance(char* address, int *error, void *eth_client);
// returns satoshis, not wei!
extern uint64_t get_erc20_balance(char *address, char *token_address, uint8_t set_decimals, int *error, void *eth_client);

extern uint8_t get_erc20_decimals(char *token_address, void *eth_client);

// returns satoshis, not wei!
extern uint64_t get_erc20_allowance(char *owner, char *spender, char *token_address, uint8_t set_decimals, void *eth_client);

void uint8arrayToHex(char *dest, uint8_t *input, int len);
void satoshisToWei(char *dest, uint64_t input);
extern uint64_t wei_to_satoshi(char *wei);

extern char *send_eth(char *to, uint64_t amount, uint64_t gas, uint64_t gas_price, uint8_t default_gas_on_err, void *eth_client);
extern char *send_erc20(
        char *token_address,
        char *to,
        uint64_t amount,
        int64_t gas,
        int64_t gas_price,
        uint8_t default_gas_on_err,
        uint8_t decimals,
        void *eth_client
);

extern uint8_t verify_alice_erc20_fee_data(char *to, uint64_t amount, char *data, uint8_t decimals);

extern uint64_t alice_payment_status(char *paymentId, void *eth_client);
extern uint64_t bob_payment_status(char *payment_tx_id, void *eth_client);
extern uint64_t bob_deposit_status(char *deposit_tx_id, void *eth_client);

extern uint64_t estimate_erc20_gas(char *token_address, char *to, uint64_t amount, uint8_t decimals, void *eth_client);

extern uint8_t compare_addresses(char *address1, char *address2);
extern uint8_t is_valid_address(char *address);

extern void *eth_client(char *private_key);
extern void eth_client_destruct(void *eth_client);

#ifdef __cplusplus
}
#endif
