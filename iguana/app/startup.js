$(function () {
    console.log('jquery loaded');
    $.material.init();
    $(".select ").dropdown({ "autoinit ": ".select " });

    startCoinManagement();
    startBlockExplorer();
    //startPeerManagement();
    
    // Event Handlers
    
    // $('.coinMgmtActionButton').click equivelant w/o jQuery
    document.body.onclick = function (e) {
        e = window.event ? event.srcElement : e.target;
        if (e.className && e.className.indexOf('coinMgmtStartActionButton') != -1) {
            startCoin(e.getAttribute('data-id'));
        } else if (e.className && e.className.indexOf('coinMgmtAddActionButton') != -1) {
            addExistingCoin(e.getAttribute('data-id'));
        } else if (e.className && e.className.indexOf('coinMgmtStopActionButton') != -1) {
            pauseCoin(e.getAttribute('data-id'));
        }
        else if (e.className && e.className.indexOf('addPeerToFav') != -1) {
            update_favourite(e.getAttribute('data-coin'),e.getAttribute('data-ip'),e.getAttribute('data-id'),true);
        }
        else if (e.className && e.className.indexOf('removePeerFromFav') != -1) {
            update_favourite(e.getAttribute('data-coin'),e.getAttribute('data-ip'),e.getAttribute('data-id'),false);
        }else if(e.className && e.className.indexOf('disconnectPeer') != -1){
            disconnectPeer(e.getAttribute('data-ip'),e.getAttribute('data-coin'),e.getAttribute('data-id'));
            
        }else if(e.className && e.className.indexOf('connectPeer') != -1){
            connectPeer(e.getAttribute('data-ip'),e.getAttribute('data-coin'),e.getAttribute('data-id'));
           
        }else if(e.className && e.className.indexOf('coinRPCactive') != -1){
            callBlockEXPRPC(e.getAttribute('data-value'));
        }else if(e.className && e.className.indexOf('getBlockHashActionButton') != -1){
            getBlockhash(e.getAttribute('data-height'));
        }else if(e.className && e.className.indexOf('getBlockActionButton') != -1){
            getBlock(e.getAttribute('data-hash'));
        }else if(e.className && e.className.indexOf('getTrancationActionButton') != -1){
            getRawTransaction(e.getAttribute('data-hash'));
        }
        else if(e.className && e.className.indexOf('host_pangea_request') != -1){
            hostPangea();
        }
        else if(e.className && e.className.indexOf('list_pangea_request') != -1){
            lobbyPangea();
        }
        else if(e.className && e.className.indexOf('join_pangea_game') != -1){
            joinPangea(e.getAttribute("data-tablehash"));
        }
        else if(e.className && e.className.indexOf('instantdex_set_keypair') != -1){
            setUeseridandAPIkeyPair();
        }
        else if(e.className && e.className.indexOf('instantdex_orderbook') != -1){
            orderbook();
        }
        else if(e.className && e.className.indexOf('instantdex_set_method_table') != -1){
            instantdex_set_method_table(e.getAttribute("data-method"));
        }
        else if(e.className && e.className.indexOf('instantdex_sell') != -1){
            InstantDEXSell();
        }
        else if(e.className && e.className.indexOf('instantdex_buy') != -1){
            InstantDEXBuy();
        }
        else if(e.className && e.className.indexOf('instantdex_balance') != -1){
            InstantDEX_balance();
        }
        else if(e.className && e.className.indexOf('instantdex_support') != -1){
            InstantDEX_supports();
        }
        else if(e.className && e.className.indexOf('instantdex_withdraw') != -1){
            InstantDEXWithdaw();
        }
        else if(e.className && e.className.indexOf('instantdex_order_status') != -1){
            InstantDEX_orderstatus();
        }
        else if(e.className && e.className.indexOf('instantdex_open_orders') != -1){
            InstantDEX_openorders();
        }
        else if(e.className && e.className.indexOf('instantdex_trade_history') != -1){
            InstantDEX_tradehistory();
        }
        else if(e.className && e.className.indexOf('instantdex_order_cancel') != -1){
            InstantDEX_cancelorder();
        }
        else if(e.className && e.className.indexOf('instantdex_pollgap') != -1){
            InstantDEX_pollgap();
        }
        else if(e.className && e.className.indexOf('submit_new_coin_test') != -1){
            add_new_coin_test();
        }
        
        else if(e.className && e.className.indexOf('clear-response-coin') != -1){
            $(".coin_result").text("JSON response");
        }
        else if(e.className && e.className.indexOf('instantdex_set_userid') != -1){
            InstantDEX_setuserid();
        }
        else if(e.className && e.className.indexOf('Tradebot_set_method_table') != -1){
            tradebot_set_method_table(e.getAttribute("data-method"));
        }
        else if(e.className && e.className.indexOf('Tradebot_monitorall') != -1){
            Tradebot_monitorall_api();
        }
        else if(e.className && e.className.indexOf('Tradebot_monitor') != -1){
            Tradebot_monitor_api();
        }
        else if(e.className && e.className.indexOf('Tradebot_unmonitor_api') != -1){
            Tradebot_unmonitor_api();
        }
        else if(e.className && e.className.indexOf('Tradebot_accumulate') != -1){
            Tradebot_accumulate_api();
        }
        else if(e.className && e.className.indexOf('Tradebot_divest') != -1){
            Tradebot_divest_api();
        }
        
        else if(e.className && e.className.indexOf('Tradebot_activebots') != -1){
            Tradebot_activebots_api();
        }
        else if(e.className && e.className.indexOf('Tradebot_status') != -1){
            Tradebot_status_api();
        }
        
        else if(e.className && e.className.indexOf('Tradebot_pause') != -1){
            Tradebot_pause_api();
        }
        
        else if(e.className && e.className.indexOf('Tradebot_stop') != -1){
            Tradebot_stop_api();
        }
        else if(e.className && e.className.indexOf('Tradebot_resume') != -1){
            Tradebot_resume_api();
            }
        else if(e.className && e.className.indexOf('instantdex_allpairs') != -1){
            InstantDEX_allpairs();
                        
        }
        
        else if(e.className && e.className.indexOf('saveConfFiles_onclick') != -1){
            reset_conf_files();
                        
        }
        else if(e.className && e.className.indexOf('connect_to_peers_from_conf') != -1){
            load_peers_from_conf();
                        
        }
        else if(e.className && e.className.indexOf('update_allpeer_status') != -1){
            update_allpeer_status();
                        
        }
        else if(e.className && e.className.indexOf('save_peersdata_to_conf') != -1){
            save_peersdata_to_conf();
                        
        }
        
    };
    
    $("div .btn-primary").on("click",function(){
        $("div .btn-primary").each(function(){
             $(this).removeClass('btn-raised');
         });
         if(! $(this).hasClass( "_not_pressed" )){
            $(this).addClass("btn-raised");}
    });
    
});