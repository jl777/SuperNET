#ifdef __cplusplus
extern "C"{
#endif

char* sendRawTx(char* rawTx);
char* ethCall(char* to, const char* data);
int getNonce(char* address);
char* getEthBalanceRequest(char* address);

#ifdef __cplusplus
}
#endif