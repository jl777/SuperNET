$(function () {
    console.log('jquery loaded');
    $.material.init();
    $(".select ").dropdown({ "autoinit ": ".select " });

    startCoinManagement();
    startPeerManagement();
    
    // Event Handlers
    
    // $('.coinMgmtActionButton').click equivelant w/o jQuery
    document.body.onclick = function (e) {
        e = window.event ? event.srcElement : e.target;
        if (e.className && e.className.indexOf('coinMgmtActionButton') != -1) {
            deleteCoin(e.getAttribute('data-id'));
        }
        else if (e.className && e.className.indexOf('addPeerToFav') != -1) {
            addPeerToFav(e.getAttribute('data-id'));
        }
        else if (e.className && e.className.indexOf('removePeerFromFav') != -1) {
            removePeerFromFav(e.getAttribute('data-id'));
        }
    };
});