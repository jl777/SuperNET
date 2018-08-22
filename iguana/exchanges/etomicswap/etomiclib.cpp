//
// Created by artem on 24.01.18.
//
#include "etomiclib.h"
#include "etomiccurl.h"
#include <inttypes.h>

extern void *LP_eth_client;

char* bobSendsEthDeposit(BobSendsEthDepositInput input, BasicTxData txData)
{
    /*
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = bobSendsEthDepositData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
    */
    return NULL;
}

uint8_t verifyBobEthDepositData(BobSendsEthDepositInput input, char *data)
{
    /*
    std::stringstream ss = bobSendsEthDepositData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Bob deposit data %s != expected %s\n", data, ss.str().c_str());
        return 0;
    }
     */
    return 0;
}

char* bobSendsErc20Deposit(BobSendsErc20DepositInput input, BasicTxData txData)
{
    /*
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = bobSendsErc20DepositData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTxWaitConfirm(rawTx);
    free(rawTx);
    return result;
    */
    return NULL;
}

uint8_t verifyBobErc20DepositData(BobSendsErc20DepositInput input, char *data)
{
    /*
    std::stringstream ss = bobSendsErc20DepositData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Bob deposit data %s != expected %s\n", data, ss.str().c_str());
        return 0;
    }
     */
    return 0;
}

char* bobRefundsDeposit(BobRefundsDepositInput input, BasicTxData txData)
{
    /*
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals;
        if (input.decimals > 0) {
            decimals = input.decimals;
        } else {
            decimals = get_erc20_decimals(input.tokenAddress, LP_eth_client);
        }

        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0x1f7a72f7"
       << toHex(jsToBytes(input.depositId))
       << toHex(toBigEndian(amount))
       << toHex(jsToBytes(input.bobSecret))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << "000000000000000000000000"
       << toHex(tokenAddress);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTxWaitConfirm(rawTx);
    free(rawTx);
    return result;
    */
    return NULL;
}

char* aliceClaimsBobDeposit(AliceClaimsBobDepositInput input, BasicTxData txData)
{
    /*
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals;
        if (input.decimals > 0) {
            decimals = input.decimals;
        } else {
            decimals = get_erc20_decimals(input.tokenAddress, LP_eth_client);
        }

        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0x4b915a68"
       << toHex(jsToBytes(input.depositId))
       << toHex(toBigEndian(amount))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.bobAddress))
       << "000000000000000000000000"
       << toHex(tokenAddress)
       << toHex(jsToBytes(input.bobHash))
       << "000000000000000000000000";
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTxWaitConfirm(rawTx);
    free(rawTx);
    return result;
    */
    return NULL;
}

char* bobSendsEthPayment(BobSendsEthPaymentInput input, BasicTxData txData)
{
    /*
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = bobSendsEthPaymentData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTxWaitConfirm(rawTx);
    free(rawTx);
    return result;
    */
    return NULL;
}

uint8_t verifyBobEthPaymentData(BobSendsEthPaymentInput input, char *data)
{
    /*
    std::stringstream ss = bobSendsEthPaymentData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Bob payment data %s != expected %s\n", data, ss.str().c_str());
        return 0;
    }
     */
    return 0;
}

char* bobSendsErc20Payment(BobSendsErc20PaymentInput input, BasicTxData txData)
{
    /*
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = bobSendsErc20PaymentData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTxWaitConfirm(rawTx);
    free(rawTx);
    return result;
    */
    return NULL;
}

uint8_t verifyBobErc20PaymentData(BobSendsErc20PaymentInput input, char *data)
{
    /*
    std::stringstream ss = bobSendsErc20PaymentData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Bob payment data %s != expected %s\n", data, ss.str().c_str());
        return 0;
    }
     */
    return 0;
}

char* bobReclaimsBobPayment(BobReclaimsBobPaymentInput input, BasicTxData txData)
{
    /*
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals;
        if (input.decimals > 0) {
            decimals = input.decimals;
        } else {
            decimals = get_erc20_decimals(input.tokenAddress, LP_eth_client);
        }

        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0xe45ef4ad"
       << toHex(jsToBytes(input.paymentId))
       << toHex(toBigEndian(amount))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << "000000000000000000000000"
       << toHex(tokenAddress)
       << toHex(jsToBytes(input.aliceHash))
       << "000000000000000000000000";
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTxWaitConfirm(rawTx);
    free(rawTx);
    return result;
    */
    return NULL;
}

char* aliceSpendsBobPayment(AliceSpendsBobPaymentInput input, BasicTxData txData)
{
    /*
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals;
        if (input.decimals > 0) {
            decimals = input.decimals;
        } else {
            decimals = get_erc20_decimals(input.tokenAddress, LP_eth_client);
        }

        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0x113ee583"
       << toHex(jsToBytes(input.paymentId))
       << toHex(toBigEndian(amount))
       << toHex(jsToBytes(input.aliceSecret))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.bobAddress))
       << "000000000000000000000000"
       << toHex(tokenAddress);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTxWaitConfirm(rawTx);
    free(rawTx);
    return result;
     */
    return NULL;
}

void uint8arrayToHex(char *dest, uint8_t *input, int len)
{
    strcpy(dest, "0x");
    for (int i = 0; i < len; i++)
    {
        sprintf(dest + (i + 1) * 2, "%02x", input[i]);
    }
    dest[(len + 1) * 2] = '\0';
}

void satoshisToWei(char *dest, uint64_t input)
{
    sprintf(dest, "%" PRIu64, input);
    strcat(dest, "0000000000");
}
