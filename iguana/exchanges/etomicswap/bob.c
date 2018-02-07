//
// Created by artem on 24.01.18.
//
#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include "etomiclib.h"
#include <cjson/cJSON.h>

char* bobContractAddress = "0x9387Fd3a016bB0205e4e131Dde886B9d2BC000A2";
char* aliceAddress = "0x485d2cc2d13a9e12E4b53D606DB1c8adc884fB8a";
char* bobAddress = "0xA7EF3f65714AE266414C9E58bB4bAa4E6FB82B41";
char* tokenAddress = "0xc0eb7AeD740E1796992A08962c15661bDEB58003";

int main(int argc, char** argv)
{
    enum {
        BOB_ETH_DEPOSIT,
        BOB_ERC20_DEPOSIT,
        BOB_CLAIMS_DEPOSIT,
        ALICE_CLAIMS_DEPOSIT,
        BOB_ETH_PAYMENT,
        BOB_ERC20_PAYMENT,
        BOB_CLAIMS_PAYMENT,
        ALICE_CLAIMS_PAYMENT,
        BOB_APPROVES_ERC20
    };
    if (argc < 3) {
        return 1;
    }
    int action = atoi(argv[1]);
    BasicTxData txData;
    char* result;
    switch (action)
    {
        case BOB_ETH_DEPOSIT:
            txData.amount = "1000000000000000000";
            txData.from = bobAddress;
            txData.to = bobContractAddress;
            txData.secretKey = getenv("BOB_PK");

            BobSendsEthDepositInput input = {
                .aliceAddress = aliceAddress,
                .depositId = argv[2],
                .bobHash = argv[3]
            };

            result = bobSendsEthDeposit(input, txData);
            break;
        case BOB_ERC20_DEPOSIT:
            txData.amount = "0";
            txData.from = bobAddress;
            txData.to = bobContractAddress;
            txData.secretKey = getenv("BOB_PK");

            BobSendsErc20DepositInput input1 = {
                .depositId = argv[2],
                .amount = "1000000000000000000",
                .aliceAddress = aliceAddress,
                .bobHash = argv[3],
                .tokenAddress = tokenAddress
            };

            result = bobSendsErc20Deposit(input1, txData);
            break;
        case BOB_CLAIMS_DEPOSIT:
            txData.amount = "0";
            txData.from = bobAddress;
            txData.to = bobContractAddress;
            txData.secretKey = getenv("BOB_PK");

            BobRefundsDepositInput input2 = {
                .depositId = argv[2],
                .amount = "1000000000000000000",
                .aliceAddress = aliceAddress,
                .tokenAddress = argv[3],
                .aliceCanClaimAfter = argv[4],
                .bobSecret = argv[5]
            };

            result = bobRefundsDeposit(input2, txData);
            break;
        case ALICE_CLAIMS_DEPOSIT:
            txData.amount = "0";
            txData.from = aliceAddress;
            txData.to = bobContractAddress;
            txData.secretKey = getenv("ALICE_PK");

            AliceClaimsBobDepositInput input3 = {
                .depositId = argv[2],
                .amount = "1000000000000000000",
                .bobAddress = bobAddress,
                .tokenAddress = argv[3],
                .aliceCanClaimAfter = argv[4],
                .bobHash = argv[5]
            };

            result = aliceClaimsBobDeposit(input3, txData);
            break;
        case BOB_ETH_PAYMENT:
            txData.amount = "1000000000000000000";
            txData.from = bobAddress;
            txData.to = bobContractAddress;
            txData.secretKey = getenv("BOB_PK");

            BobSendsEthPaymentInput input4 = {
                .paymentId = argv[2],
                .aliceHash = argv[3],
                .aliceAddress = aliceAddress
            };

            result = bobSendsEthPayment(input4, txData);
            break;
        case BOB_ERC20_PAYMENT:
            txData.amount = "0";
            txData.from = bobAddress;
            txData.to = bobContractAddress;
            txData.secretKey = getenv("BOB_PK");

            BobSendsErc20PaymentInput input5 = {
                .paymentId = argv[2],
                .amount = "1000000000000000000",
                .tokenAddress = tokenAddress,
                .aliceAddress = aliceAddress,
                .aliceHash = argv[3]
            };

            result = bobSendsErc20Payment(input5, txData);
            break;
        case BOB_CLAIMS_PAYMENT:
            txData.amount = "0";
            txData.from = bobAddress;
            txData.to = bobContractAddress;
            txData.secretKey = getenv("BOB_PK");

            BobReclaimsBobPaymentInput input6 = {
                .paymentId = argv[2],
                .aliceAddress = aliceAddress,
                .amount = "1000000000000000000",
                .tokenAddress = argv[3],
                .bobCanClaimAfter = argv[4],
                .aliceHash = argv[5]
            };

            result = bobReclaimsBobPayment(input6, txData);
            break;
        case ALICE_CLAIMS_PAYMENT:
            txData.amount = "0";
            txData.from = aliceAddress;
            txData.to = bobContractAddress;
            txData.secretKey = getenv("ALICE_PK");

            AliceSpendsBobPaymentInput input7 = {
                .paymentId = argv[2],
                .bobAddress = bobAddress,
                .amount = "1000000000000000000",
                .tokenAddress = argv[3],
                .bobCanClaimAfter = argv[4],
                .aliceSecret = argv[5]
            };

            result = aliceSpendsBobPayment(input7, txData);
            break;
        case BOB_APPROVES_ERC20:
            result = approveErc20(
                    "10000000000000000000",
                    "0xA7EF3f65714AE266414C9E58bB4bAa4E6FB82B41",
                    getenv("BOB_PK")
            );
            break;
        default:
            return 1;
    }
    printf("%s\n", result);
    free(result);
    return 0;
}
