#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif
    
#define ETOMIC_TESTNET
#ifdef ETOMIC_TESTNET
#define ETOMIC_URL "https://ropsten.infura.io/y07GHxUyTgeN2mdfOonu"
#else
#define ETOMIC_URL "https://mainnet.infura.io/y07GHxUyTgeN2mdfOonu"
#endif
    
typedef struct
{
    uint64_t blockNumber;
    char blockHash[75];
} EthTxReceipt;

char* sendRawTx(char* rawTx);
char* ethCall(char* to, const char* data);
int getNonce(char* address);
char* getEthBalanceRequest(char* address);
EthTxReceipt getEthTxReceipt(char *txId);

#ifdef __cplusplus
}
#endif
