//
// Created by artem on 24.01.18.
//
#ifndef ETOMIC_LIB_HEADER
#define ETOMIC_LIB_HEADER

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EMPTY_ETH_TX_ID "0x0000000000000000000000000000000000000000000000000000000000000000"

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
    char deposit_id[70];
    char alice_address[65];
    char bob_hash[65];
    char alice_hash[65];
    uint64_t lock_time;
    uint64_t amount;
} BobSendsEthDepositInput;

typedef struct {
    char deposit_id[70];
    uint64_t amount;
    char token_address[65];
    char alice_address[65];
    char bob_hash[65];
    char alice_hash[65];
    uint64_t lock_time;
    uint8_t decimals;
} BobSendsErc20DepositInput;

typedef struct {
    char deposit_id[70];
    uint64_t amount;
    char token_address[65];
    char alice_address[65];
    char bob_secret[70];
    char alice_hash[70];
    uint8_t decimals;
} BobRefundsDepositInput;

typedef struct {
    char deposit_id[70];
    uint64_t amount;
    char alice_secret[70];
    char token_address[65];
    char bob_address[65];
    char bob_hash[65];
    uint8_t decimals;
} AliceClaimsBobDepositInput;

typedef struct {
    char payment_id[70];
    char alice_address[65];
    char alice_hash[65];
    uint64_t lock_time;
    uint64_t amount;
} BobSendsEthPaymentInput;

typedef struct {
    char payment_id[70];
    uint64_t amount;
    char token_address[65];
    char alice_address[65];
    char alice_hash[65];
    uint64_t lock_time;
    uint8_t decimals;
} BobSendsErc20PaymentInput;

typedef struct {
    char payment_id[70];
    uint64_t amount;
    char token_address[65];
    char alice_address[65];
    char alice_hash[65];
    uint8_t decimals;
} BobReclaimsBobPaymentInput;

typedef struct {
    char payment_id[70];
    uint64_t amount;
    char token_address[65];
    char alice_secret[70];
    char bob_address[65];
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

extern char *alice_reclaims_payment(AliceReclaimsPaymentInput input, void *eth_client);
extern char *bob_spends_alice_payment(BobSpendsAlicePaymentInput input, void *eth_client);

extern char *bob_sends_eth_deposit(BobSendsEthDepositInput input, void *eth_client);
extern uint8_t verify_bob_eth_deposit_data(BobSendsEthDepositInput input, char *data);

extern char *bob_sends_erc20_deposit(BobSendsErc20DepositInput input, void *eth_client);
extern uint8_t verify_bob_erc20_deposit_data(BobSendsErc20DepositInput input, char *data);

extern char *bob_refunds_deposit(BobRefundsDepositInput input, void *eth_client);
extern char *alice_claims_bob_deposit(AliceClaimsBobDepositInput input, void *eth_client);

extern char *bob_sends_eth_payment(BobSendsEthPaymentInput input, void *eth_client);
extern uint8_t verify_bob_eth_payment_data(BobSendsEthPaymentInput input, char *data);

extern char *bob_sends_erc20_payment(BobSendsErc20PaymentInput input, void *eth_client);
extern uint8_t verify_bob_erc20_payment_data(BobSendsErc20PaymentInput input, char *data);

extern char *bob_reclaims_bob_payment(BobReclaimsBobPaymentInput input, void *eth_client);
extern char *alice_spends_bob_payment(AliceSpendsBobPaymentInput input, void *eth_client);

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

extern void *eth_client(char *private_key, char *node_url, char *alice_contract, char *bob_contract, uint32_t mm_ctx_id);
extern void eth_client_destruct(void *eth_client);

#ifdef __cplusplus
}
#endif

#endif
