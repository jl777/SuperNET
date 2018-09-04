#ifndef ETOMIC_CURL_HEADER
#define ETOMIC_CURL_HEADER

#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

typedef struct
{
    uint64_t block_number;
    uint64_t confirmations;
    uint64_t status;
} EthTxReceipt;

typedef struct
{
    char from[50];
    char to[50];
    char input[1000];
    uint64_t value;
    uint8_t exists;
} EthTxData;

extern EthTxReceipt get_eth_tx_receipt(char *tx_id, void *eth_client);
extern EthTxData get_eth_tx_data(char *txId, void *eth_client);
extern uint64_t get_gas_price_from_station(uint8_t default_on_err);
int32_t wait_for_confirmation(char *tx_id, void *eth_client);
extern uint8_t get_etomic_from_faucet(char *etomic_addr);

#ifdef __cplusplus
}
#endif

#endif