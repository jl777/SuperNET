//
// Created by artem on 24.01.18.
//
#include "etomiclib.h"
#include "etomiccurl.h"
#include <iostream>
#include <cpp-ethereum/libethcore/Common.h>
#include <cpp-ethereum/libethcore/CommonJS.h>
#include <cpp-ethereum/libethcore/TransactionBase.h>
#include <inttypes.h>

using namespace dev;
using namespace dev::eth;

char *stringStreamToChar(std::stringstream& ss)
{
    const std::string tmp = ss.str();
    auto result = (char*)malloc(strlen(tmp.c_str()) + 1);
    strcpy(result, tmp.c_str());
    return result;
}

TransactionSkeleton txDataToSkeleton(BasicTxData txData)
{
    TransactionSkeleton tx;
    tx.from = jsToAddress(txData.from);
    tx.to = jsToAddress(txData.to);
    tx.value = jsToU256(txData.amount);
    tx.gas = 100000;
    tx.gasPrice = getGasPriceFromStation() * boost::multiprecision::pow(u256(10), 9);
    tx.nonce = getNonce(txData.from);
    return tx;
}

char *signTx(TransactionSkeleton& tx, char* secret)
{
    Secret& secretKey = *(new Secret(secret));
    auto baseTx = new TransactionBase(tx, secretKey);
    RLPStream& rlpStream = *(new RLPStream());
    baseTx->streamRLP(rlpStream);
    std::stringstream& ss = *(new std::stringstream);
    ss << rlpStream.out();
    return stringStreamToChar(ss);
}

char *approveErc20(ApproveErc20Input input)
{
    TransactionSkeleton tx;
    tx.from = jsToAddress(input.owner);
    tx.to = jsToAddress(input.tokenAddress);
    tx.value = 0;
    tx.gas = 300000;
    tx.gasPrice = getGasPriceFromStation() * boost::multiprecision::pow(u256(10), 9);
    tx.nonce = getNonce(input.owner);
    uint8_t decimals = getErc20Decimals(input.tokenAddress);
    std::stringstream ss;
    ss << "0x095ea7b3"
       << "000000000000000000000000"
       << toHex(jsToAddress(input.spender))
       << toHex(toBigEndian(jsToU256(input.amount)));
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, input.secret);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

std::stringstream aliceSendsEthPaymentData(AliceSendsEthPaymentInput input)
{
    std::stringstream ss;
    ss << "0x47c7b6e2"
       << toHex(jsToBytes(input.dealId))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.bobAddress))
       << toHex(jsToBytes(input.aliceHash))
       << "000000000000000000000000"
       << toHex(jsToBytes(input.bobHash))
       << "000000000000000000000000";
    return ss;
}

char* aliceSendsEthPayment(AliceSendsEthPaymentInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = aliceSendsEthPaymentData(input);
    tx.data = jsToBytes(ss.str());
    char *rawTx = signTx(tx, txData.secretKey);
    char *result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

uint8_t verifyAliceEthPaymentData(AliceSendsEthPaymentInput input, char *data)
{
    std::stringstream ss = aliceSendsEthPaymentData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Alice ETH payment data %s does not match expected %s\n", data, ss.str().c_str());
        return 0;
    }
    return 1;
}

std::stringstream aliceSendsErc20PaymentData(AliceSendsErc20PaymentInput input)
{
    uint8_t decimals = getErc20Decimals(input.tokenAddress);
    u256 amount = jsToU256(input.amount);
    if (decimals < 18) {
        amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
    }
    std::stringstream ss;
    ss << "0x184db3bf"
       << toHex(jsToBytes(input.dealId))
       << toHex(toBigEndian(amount))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.bobAddress))
       << toHex(jsToBytes(input.aliceHash))
       << "000000000000000000000000"
       << toHex(jsToBytes(input.bobHash))
       << "000000000000000000000000"
       << "000000000000000000000000"
       << toHex(jsToAddress(input.tokenAddress));
    return ss;
}

char* aliceSendsErc20Payment(AliceSendsErc20PaymentInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = aliceSendsErc20PaymentData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

uint8_t verifyAliceErc20PaymentData(AliceSendsErc20PaymentInput input, char *data)
{
    std::stringstream ss = aliceSendsErc20PaymentData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Alice ERC20 payment data %s is not equal to expected %s\n", data, ss.str().c_str());
        return 0;
    }
    return 1;
}

char* aliceReclaimsAlicePayment(AliceReclaimsAlicePaymentInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals = getErc20Decimals(input.tokenAddress);
        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0x8b9a167a"
       << toHex(jsToBytes(input.dealId))
       << toHex(toBigEndian(amount))
       << "000000000000000000000000"
       << toHex(tokenAddress)
       << "000000000000000000000000"
       << toHex(jsToAddress(input.bobAddress))
       << toHex(jsToBytes(input.aliceHash))
       << "000000000000000000000000"
       << "00000000000000000000000000000000000000000000000000000000000000c0"
       << "0000000000000000000000000000000000000000000000000000000000000020"
       << toHex(jsToBytes(input.bobSecret));
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

char* bobSpendsAlicePayment(BobSpendsAlicePaymentInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals = getErc20Decimals(input.tokenAddress);
        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0x392ec66b"
       << toHex(jsToBytes(input.dealId))
       << toHex(toBigEndian(amount))
       << "000000000000000000000000"
       << toHex(tokenAddress)
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << toHex(jsToBytes(input.bobHash))
       << "000000000000000000000000"
       << "00000000000000000000000000000000000000000000000000000000000000c0"
       << "0000000000000000000000000000000000000000000000000000000000000020"
       << toHex(jsToBytes(input.aliceSecret));
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

std::stringstream bobSendsEthDepositData(BobSendsEthDepositInput input)
{
    std::stringstream ss;
    ss << "0xc2c5143f"
       << toHex(jsToBytes(input.depositId))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << toHex(jsToBytes(input.bobHash))
       << "000000000000000000000000";
    return ss;
}

char* bobSendsEthDeposit(BobSendsEthDepositInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = bobSendsEthDepositData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

uint8_t verifyBobEthDepositData(BobSendsEthDepositInput input, char *data)
{
    std::stringstream ss = bobSendsEthDepositData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Bob deposit data %s != expected %s\n", data, ss.str().c_str());
        return 0;
    }
    return 1;
}

std::stringstream bobSendsErc20DepositData(BobSendsErc20DepositInput input)
{
    uint8_t decimals = getErc20Decimals(input.tokenAddress);
    u256 amount = jsToU256(input.amount);
    if (decimals < 18) {
        amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
    }
    std::stringstream ss;
    ss << "0xce8bbe4b"
       << toHex(jsToBytes(input.depositId))
       << toHex(toBigEndian(amount))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << toHex(jsToBytes(input.bobHash))
       << "000000000000000000000000"
       << "000000000000000000000000"
       << toHex(jsToAddress(input.tokenAddress));
    return ss;
}

char* bobSendsErc20Deposit(BobSendsErc20DepositInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = bobSendsErc20DepositData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

uint8_t verifyBobErc20DepositData(BobSendsErc20DepositInput input, char *data)
{
    std::stringstream ss = bobSendsErc20DepositData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Bob deposit data %s != expected %s\n", data, ss.str().c_str());
        return 0;
    }
    return 1;
}

char* bobRefundsDeposit(BobRefundsDepositInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals = getErc20Decimals(input.tokenAddress);
        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0x1dbe6508"
       << toHex(jsToBytes(input.depositId))
       << toHex(toBigEndian(amount))
       << toHex(toBigEndian(jsToU256(input.aliceCanClaimAfter)))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << "000000000000000000000000"
       << toHex(tokenAddress)
       << "00000000000000000000000000000000000000000000000000000000000000c0"
       << "0000000000000000000000000000000000000000000000000000000000000020"
       << toHex(jsToBytes(input.bobSecret));
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

char* aliceClaimsBobDeposit(AliceClaimsBobDepositInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals = getErc20Decimals(input.tokenAddress);
        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0x960173b5"
       << toHex(jsToBytes(input.depositId))
       << toHex(toBigEndian(amount))
       << toHex(toBigEndian(jsToU256(input.aliceCanClaimAfter)))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.bobAddress))
       << "000000000000000000000000"
       << toHex(tokenAddress)
       << toHex(jsToBytes(input.bobHash))
       << "000000000000000000000000";
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

std::stringstream bobSendsEthPaymentData(BobSendsEthPaymentInput input)
{
    std::stringstream ss;
    ss << "0xcf36fe8e"
       << toHex(jsToBytes(input.paymentId))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << toHex(jsToBytes(input.aliceHash))
       << "000000000000000000000000";
    return ss;
}

char* bobSendsEthPayment(BobSendsEthPaymentInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = bobSendsEthPaymentData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

uint8_t verifyBobEthPaymentData(BobSendsEthPaymentInput input, char *data)
{
    std::stringstream ss = bobSendsEthPaymentData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Bob payment data %s != expected %s\n", data, ss.str().c_str());
        return 0;
    }
    return 1;
}

std::stringstream bobSendsErc20PaymentData(BobSendsErc20PaymentInput input)
{
    uint8_t decimals = getErc20Decimals(input.tokenAddress);
    u256 amount = jsToU256(input.amount);
    if (decimals < 18) {
        amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
    }
    std::stringstream ss;
    ss << "0x34f64dfd"
       << toHex(jsToBytes(input.paymentId))
       << toHex(toBigEndian(amount))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << toHex(jsToBytes(input.aliceHash))
       << "000000000000000000000000"
       << "000000000000000000000000"
       << toHex(jsToAddress(input.tokenAddress));
    return ss;
}

char* bobSendsErc20Payment(BobSendsErc20PaymentInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss = bobSendsErc20PaymentData(input);
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

uint8_t verifyBobErc20PaymentData(BobSendsErc20PaymentInput input, char *data)
{
    std::stringstream ss = bobSendsErc20PaymentData(input);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Bob payment data %s != expected %s\n", data, ss.str().c_str());
        return 0;
    }
    return 1;
}

char* bobReclaimsBobPayment(BobReclaimsBobPaymentInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals = getErc20Decimals(input.tokenAddress);
        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0xb7cc2312"
       << toHex(jsToBytes(input.paymentId))
       << toHex(toBigEndian(amount))
       << toHex(toBigEndian(jsToU256(input.bobCanClaimAfter)))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.aliceAddress))
       << "000000000000000000000000"
       << toHex(tokenAddress)
       << toHex(jsToBytes(input.aliceHash))
       << "000000000000000000000000";
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

char* aliceSpendsBobPayment(AliceSpendsBobPaymentInput input, BasicTxData txData)
{
    TransactionSkeleton tx = txDataToSkeleton(txData);
    std::stringstream ss;
    u256 amount = jsToU256(input.amount);
    dev::Address tokenAddress = jsToAddress(input.tokenAddress);
    if (tokenAddress != ZeroAddress) {
        uint8_t decimals = getErc20Decimals(input.tokenAddress);
        if (decimals < 18) {
            amount /= boost::multiprecision::pow(u256(10), 18 - decimals);
        }
    }
    ss << "0x97004255"
       << toHex(jsToBytes(input.paymentId))
       << toHex(toBigEndian(amount))
       << toHex(toBigEndian(jsToU256(input.bobCanClaimAfter)))
       << "000000000000000000000000"
       << toHex(jsToAddress(input.bobAddress))
       << "000000000000000000000000"
       << toHex(tokenAddress)
       << "00000000000000000000000000000000000000000000000000000000000000c0"
       << "0000000000000000000000000000000000000000000000000000000000000020"
       << toHex(jsToBytes(input.aliceSecret));
    tx.data = jsToBytes(ss.str());
    char* rawTx = signTx(tx, txData.secretKey);
    char* result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

char* privKey2Addr(char* privKey)
{
    Secret& secretKey = *(new Secret(privKey));
    std::stringstream& ss = *(new std::stringstream);
    ss << "0x" << toAddress(secretKey);
    return stringStreamToChar(ss);
};

char* pubKey2Addr(char* pubKey)
{
    Public& publicKey = *(new Public(pubKey));
    std::stringstream& ss = *(new std::stringstream);
    ss << "0x" << toAddress(publicKey);
    return stringStreamToChar(ss);
};

char* getPubKeyFromPriv(char* privKey)
{
    Public publicKey = toPublic(*(new Secret(privKey)));
    std::stringstream& ss = *(new std::stringstream);
    ss << "0x" << publicKey;
    return stringStreamToChar(ss);
}

uint64_t getEthBalance(char* address)
{
    char* hexBalance = getEthBalanceRequest(address);
    // convert wei to satoshi
    u256 balance = jsToU256(hexBalance) / boost::multiprecision::pow(u256(10), 10);
    free(hexBalance);
    return static_cast<uint64_t>(balance);
}

uint64_t getErc20BalanceSatoshi(char *address, char *tokenAddress)
{
    std::stringstream ss;
    ss << "0x70a08231"
       << "000000000000000000000000"
       << toHex(jsToAddress(address));
    std::stringstream& resultStream = *(new std::stringstream);
    char* hexBalance = ethCall(tokenAddress, ss.str().c_str());
    // convert wei to satoshi
    uint8_t decimals = getErc20Decimals(tokenAddress);
    u256 balance = jsToU256(hexBalance);
    if (decimals < 18) {
        balance *= boost::multiprecision::pow(u256(10), 18 - decimals);
    }
    balance /= boost::multiprecision::pow(u256(10), 10);
    free(hexBalance);
    return static_cast<uint64_t>(balance);
}

char *getErc20BalanceHexWei(char *address, char *tokenAddress)
{
    std::stringstream ss;
    ss << "0x70a08231"
       << "000000000000000000000000"
       << toHex(jsToAddress(address));
    char *hexBalance = ethCall(tokenAddress, ss.str().c_str());
    return hexBalance;
}

uint64_t getErc20Allowance(char *owner, char *spender, char *tokenAddress)
{
    std::stringstream ss;
    ss << "0xdd62ed3e"
       << "000000000000000000000000"
       << toHex(jsToAddress(owner))
       << "000000000000000000000000"
       << toHex(jsToAddress(spender));
    char* hexAllowance = ethCall(tokenAddress, ss.str().c_str());
    uint8_t decimals = getErc20Decimals(tokenAddress);
    u256 allowance = jsToU256(hexAllowance);
    if (decimals < 18) {
        allowance *= boost::multiprecision::pow(u256(10), 18 - decimals);
    }
    // convert wei to satoshi
    allowance /= boost::multiprecision::pow(u256(10), 10);
    free(hexAllowance);
    return static_cast<uint64_t>(allowance);
}

uint8_t getErc20Decimals(char *tokenAddress)
{
    char* hexDecimals = ethCall(tokenAddress, "0x313ce567");
    auto decimals = (uint8_t) strtol(hexDecimals, NULL, 0);
    free(hexDecimals);
    return decimals;
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

uint64_t weiToSatoshi(char *wei)
{
    u256 satoshi = jsToU256(wei) / boost::multiprecision::pow(u256(10), 10);
    return static_cast<uint64_t>(satoshi);
}

char *sendEth(char *to, char *amount, char *privKey)
{
    TransactionSkeleton tx;
    char *from = privKey2Addr(privKey);
    tx.from = jsToAddress(from);
    tx.to = jsToAddress(to);
    tx.value = jsToU256(amount);
    tx.gas = 21000;
    tx.gasPrice = getGasPriceFromStation() * boost::multiprecision::pow(u256(10), 9);
    tx.nonce = getNonce(from);
    free(from);

    char *rawTx = signTx(tx, privKey);
    char *result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

std::stringstream getErc20TransferData(char *tokenAddress, char *to, char *amount)
{
    u256 amountWei = jsToU256(amount);
    uint8_t decimals = getErc20Decimals(tokenAddress);
    if (decimals < 18) {
        amountWei /= boost::multiprecision::pow(u256(10), 18 - decimals);
    }
    // convert wei to satoshi
    std::stringstream ss;
    ss << "0xa9059cbb"
       << "000000000000000000000000"
       << toHex(jsToAddress(to))
       << toHex(toBigEndian(amountWei));
    return ss;
}

char *sendErc20(char *tokenAddress, char *to, char *amount, char *privKey)
{
    TransactionSkeleton tx;
    char *from = privKey2Addr(privKey);
    tx.from = jsToAddress(from);
    tx.to = jsToAddress(tokenAddress);
    tx.value = 0;
    tx.gas = 60000;
    tx.gasPrice = getGasPriceFromStation() * boost::multiprecision::pow(u256(10), 9);
    tx.nonce = getNonce(from);
    free(from);

    std::stringstream ss = getErc20TransferData(tokenAddress, to, amount);
    tx.data = jsToBytes(ss.str());

    char *rawTx = signTx(tx, privKey);
    char *result = sendRawTx(rawTx);
    free(rawTx);
    return result;
}

uint8_t verifyAliceErc20FeeData(char* tokenAddress, char *to, char *amount, char *data)
{
    std::stringstream ss = getErc20TransferData(tokenAddress, to, amount);
    if (strcmp(ss.str().c_str(), data) != 0) {
        printf("Alice ERC20 fee data %s is not equal to expected %s\n", data, ss.str().c_str());
        return 0;
    }
    return 1;
}
