/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifndef INCLUDE_NOTARIES_H
#define INCLUDE_NOTARIES_H

char *Notaries[][2] =
{
    { "jl777_testA", "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" },
    { "jl777_testB", "02ebfc784a4ba768aad88d44d1045d240d47b26e248cafaf1c5169a42d7a61d344" },
    //{ "jl777_testC", "020e0f6fe6e0fcdcac541eb728d6fe538a12adff20412b3c8a7fa892b223a47c2f" },
    /*{ "badass_EU", "034ca7bf1b9f084643960525a01d96949f36fdca35fe27f88ae9b167d496a75aa2" },
    { "crackers_NA", "03d40a9123a081c1513e5900f8bf47590952fd0d5587f64715b4b65af8d6be4985" },
    { "movecrypto_EU", "025b1e33dba14a0d4645e88f14992137e5c185708c7a2c219caffdf32dd6405e6e" },
    { "proto_EU", "03681ffdf17c8f4f0008cefb7fa0779c5e888339cdf932f0974483787a4d6747c1" },
    { "pondsea_SH", "027ee1eebfe2bd62239c3e4a859c2e19861fc44b8d77fa569d6527f6f3cdf5925d" },
    { "locomb_EU", "0252c7a960606f53ea562207561b2be1a62bd2801944bb5ac41b5591fe03c7f0e5" },
    { "jeezy_EU", "035e05eca2eb3aab88a6e10c368b9f039cd6f5e02e4e6dc554eb7f552991915280" },
    { "farl4web_EU", "035caa40684ace968677dca3f09098aa02b70e533da32390a7654c626e0cf908e1" },
    { "nxtswe_EU", "0393b7d10b7d723a1e26452a02755f229150e6626423859e1ae69771f1f374d09e" },
    { "crackers_EU", "024612bc1b43cf67692f243b5acbeb90e1f5704cd2f19c0741207ccc5fb218251e" },
     { "traderbill_EU", "03267254424fb00792b9d5cac7124849b70520e125dc0107946c44aecb9aab50fa" },
     { "vanbreuk_EU", "024f3cad7601d2399c131fd070e797d9cd8533868685ddbe515daa53c2e26004c3" },
    { "Server1","0221876c8259764224dc1a7b70ec956f3fbe9a768cd77f13082cfa60eb6aa2d068"},
    { "Server2","03c7c14e6b1f94585bb571cf3ee5eb9b9ab54bd23d0acb8cf13edad1c515842b66"},
    { "Server3","02d28f8992ff0cd68c5d558cf55ec5b3ada25151519a6cea8cef1bac04c40023b6"},
    { "Server4","02adc84814fee5864e67fd1b76f97fbe74d6bd07c62335e2f1da918f46d08d84ba"},
    { "Server5","033dcf1c8308a00533fd3206c2db4f38ace0e08ae089a93efd873c8a2f80c4a620"},
    { "Server6","030f9f354cc8e2eaead1d978cc4db7009715083220fe48252fb0b0680d3a63d5a4"},
    { "Server7","0235d73cf8bc250e7a7032898423f24e240f1267a3c809a557daa3c17108d7585e"},
    { "Server8","03feea6d8ce239043baa9f3c9a1f15213dd4ac73df2bae5da71034f803dc005587"},
    { "Server9","02bfe32e6ce78c3795f0a2aa7e0dd47c51c674742f99ba9a0aec6d0d82d3d476b0"},
    { "Server10","037b46bdc3933fda6f47d14c8931fb8fffc4db85e0981ec4857fd56ee43300a29a"},
    { "Server11","03e6e375c5d36ebfbef9bd97c8cacb2d7a8f54bf89926ebde77fe7cc8cfb3c8e89"},
    { "Server12","032eff141519c1c4b111b1e51e9c4306c9dcfab9357fd27291daa5c6b3736c59d7"},
    { "Server13","03ae5eb57512a756031f7fd516d0f46e984632f73855fdf53fd4a08fbdef284af0"},
    { "Server14","03755d02c5aab06def772438d2a3b3d98d316091747e12b4e85b3a253cf757a730"},
    { "Server15","0260348f92cde87639ba9afc9f02b2c71ab52dc5faa00d175d0e331f71c05a521c"},
    { "Server16","02714f1922b72cce03633720402783de4962432adb3d3e38c95da754d43926e6f5"},
    { "Server17","028a2957cd7b428c3ba7ee2974e8dbbed0ee836721d00db6ea66db8f65c163a582"},
    { "Server18","033b24621b85b0593a7dae5867d112d8b80406369b8b07dde8be6ec6eb123de5aa"},
    { "Server19","0334556377815054bc39eb67186b02bd44ffe5acc9547516de0a639bcb947e2afb"},
    { "Server20","02564d75bed700f431eaabd087d1fbf59a566775ec146a65ad5137cd6ca0ff9c6d"},
    { "Server21","02345e3f2d281b0109cdcae6c70728027801060f231fc740b258c48aa43d75de0d"},
    { "Server22","0224991d534b187e9636d47253b2769fba299a0649c39615f2f31997052345c37c"},
    { "Server23","021a5deb5336e7d914f84616243c12e45268941449f7f0eb6e9d6772e0a605a9af"},
    { "Server24","036f5ae3b01b030acf6d6bc987feec5de5c340ff43887834af18fb0dee3961967c"},
    { "Server25","0377e432331fcca2e39324fdb815ab91171f26d7b838de04b39e4a5787966bf10c"},
    { "Server26","02ac499362e35c2d47b83c3c985abced6f3cb8b3f5c872a1b5806e2abba175a497"},
    { "Server27","0269611d0a1eedc67c323b2e17d332731e267c4c25716f1fa956ce027f7bae787f"},
    { "Server28","0203835a4c208a2a7ae5bafea393f04aaf6e863c93a3bd61f3a59a2383b1f7af31"},
    { "Server29","02ffc70831ca50e4d44f67462405fba12df7b01477e55c12ef6e696e4b1522ce3b"},
    { "Server30","022ab58e8ee541952f9f992890335097fa18479b5f66ad5f1f4a0e8f60959f3d19"},*/
};

#endif
