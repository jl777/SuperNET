#ifndef ETOMIC_CURL_HEADER
#define ETOMIC_CURL_HEADER

#include <stdint.h>
#include <includes/cJSON.h>
#ifdef _WIN32
#include "../../../OSlibs/win/pthread.h"
#endif

#ifdef __cplusplus
extern "C"{
#endif

#ifdef ETOMIC_TESTNET
#define ETOMIC_URL "http://195.201.0.6:8545"
#define DEFAULT_GAS_PRICE 100
#else
#define ETOMIC_URL "http://195.201.0.6:8555"
#define DEFAULT_GAS_PRICE 10
#endif

#define FAUCET_URL "http://195.201.116.176:8000/getEtomic"

typedef struct
{
    uint64_t blockNumber;
    uint64_t confirmations;
    char blockHash[75];
    char status[10];
} EthTxReceipt;

typedef struct
{
    char from[50];
    char to[50];
    char input[1000];
    char valueHex[70];
    uint8_t exists;
} EthTxData;

char* sendRawTx(char* rawTx);
char* sendRawTxWaitConfirm(char* rawTx);
char* ethCall(char* to, const char* data);
uint64_t estimateGas(char *from, char *to, const char *data);
int64_t getNonce(char* address);
char* getEthBalanceRequest(char* address);
EthTxReceipt getEthTxReceipt(char *txId);
EthTxData getEthTxData(char *txId);
uint64_t getEthBlockNumber();
uint64_t getGasPriceFromStation(uint8_t defaultOnErr);
int32_t waitForConfirmation(char *txId);
void unlock_send_tx_mutex();
uint8_t get_etomic_from_faucet(char *etomic_addr);

#ifdef __cplusplus
}
#endif

#endif