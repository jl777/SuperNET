var coinManagement = {};
// Classes

coinManagement.Coin = function (_id, _symbol, _description, _statusId) {
    this.Id = _id;
    this.Symbol = _symbol;
    this.Description = _description;
    this.StatusId = _statusId;
};

coinManagement.CoinStatus = function (_id, _name) {
    this.Id = _id;
    this.Name = _name;
};


// Initialization

coinManagement.loggingEnabled = true;
coinManagement.Coins = [];

coinManagement.CoinStatuses = [
    new coinManagement.CoinStatus(1, 'Dormant'),
    new coinManagement.CoinStatus(2, 'Launched'),
    new coinManagement.CoinStatus(3, 'Started'),
    new coinManagement.CoinStatus(4, 'Paused')
];

coinManagement.Initialize = function () {
    coinManagement.Coins = [
        new coinManagement.Coin(1, 'BTC', 'Bitcoin', 1),
        new coinManagement.Coin(2, 'BTCD', 'Bitcoin Dark', 1),
        //new coinManagement.Coin(3, 'GBP', 'British Pound', 3),
        //new coinManagement.Coin(4, 'INR', 'Indian Rupee', 4),
        //new coinManagement.Coin(5, 'YEN', 'Japanese Yen', 3)
    ];
};

coinManagement.getCoinSymbols=function(){
    var coins=[];
   
    if (coinManagement.Coins === null || coinManagement.Coins === undefined) {
        return [];
    }
    for (var index = 0; index < coinManagement.Coins.length; index++) {
         coins.push(coinManagement.Coins[index].Symbol);
    }
    return coins;
};

coinManagement.GetCoinIndex = function (id) {

    if (coinManagement.Coins == null || coinManagement.Coins == undefined) {
        return -1;
    }

    for (var index = 0; index < coinManagement.Coins.length; index++) {
        if (coinManagement.Coins[index].Id == id) {
            console.log('# coin ID:' + id.toString() + 'is @' + index);
            return index;
        }
    }
};

coinManagement.GetCoinIndexBySymbol = function (id) {

    if (coinManagement.Coins == null || coinManagement.Coins == undefined) {
        return -1;
    }

    for (var index = 0; index < coinManagement.Coins.length; index++) {
        if (coinManagement.Coins[index].Symbol == id) {
            console.log('# coin symbol:' + id.toString() + 'is @' + index);
            return index;
        }
    }
};

coinManagement.Post = function (coin) {

    if (coin === null || coin === undefined) {
        console.log('# can not add coin, invalid record');
        return false;
    }

    console.log('# posting coin', coin);
    coinManagement.Coins.push(coin);
};

coinManagement.Get = function () {
    console.log('# getting coins');
    return coinManagement.Coins;
};

coinManagement.Delete = function (id) {

    if (id == null || id == undefined) {
        console.log('# invalid Coin Id');
        return false;
    }

    var index = coinManagement.GetCoinIndex(id);
    if (index == null || index == undefined || index < 0) {
        console.log('# the coin index is invalid');
    }

    console.log('# coin deleted with id:', id, '@ index', index);
    coinManagement.Coins.splice(index, 1);
};

coinManagement.getNewCoinId = function () {

    console.log('# getting new id');

    var newId = -1;

    // Get an array of ids
    var ids = coinManagement.Coins.map(function (elem, index) {
        return elem.Id;
    });

    // sort ids
    ids.sort(function (x, y) {
        return (x - y);
    });

    // get the next id
    for (var i = 0; i < ids.length; i++) {
        if (ids.indexOf(i) == -1) {
            newId = i;
            break;
        }
    };

    // worst case scenario
    if (newId == -1) {
        newId = ids.length;
    }

    console.log('# new id: ', newId);
    return newId;
};

// Helper functions

// Genric Functions to read a key from local storage : for Chrome Browser and Chrome Extension App
var readCache = function (key) {

    // Check if this is a chrome extension App
    if (chrome != null && chrome != undefined && chrome.storage != null && chrome.storage != undefined) {

    }

    // Else it should be a browser, which supports HTML 5 localStorage API
    else {

    }
};

// Genric Functions to add/update key value pair in lcoal storage : for Chrome Browser and Chrome Extension App
var updateCache = function (key, value) {
    // Check if this is a chrome extension App
    if (chrome != null && chrome != undefined && chrome.storage != null && chrome.storage != undefined) {

    }

    // Else it should be a browser, which supports HTML 5 localStorage API
    else {

    }
};

var populateCoinStatusDropDown = function () {
    console.log('# populating coin status dropdown');
    var select = document.getElementById('ddStatus');
    for (var i = 0; i < coinManagement.CoinStatuses.length; i++) {
        var option = document.createElement('option');
        option.value = coinManagement.CoinStatuses[i].Id
        option.textContent = coinManagement.CoinStatuses[i].Name;
        select.appendChild(option);
    };
    console.log('# populated coin status dropdown');
};

var coinEditFormIsValid = function () {

    var txt_symbol = document.getElementById('txtSymbol').value;
    var txt_description = document.getElementById('txtDescription').value;
    var dd_Status = document.getElementById('ddStatus').value;

    var symbol_group = document.getElementById('txtSymbolGroup');
    var description_group = document.getElementById('txtDescriptionGroup');
    var status_group = document.getElementById('ddCoinStatus');

    symbol_group.removeAttribute('class');
    symbol_group.setAttribute('class', 'form-group');

    description_group.removeAttribute('class');
    description_group.setAttribute('class', 'form-group');

    status_group.removeAttribute('class');
    status_group.setAttribute('class', 'form-group');

    if (txt_symbol == null || txt_symbol == undefined || txt_symbol.length == 0) {
        symbol_group.removeAttribute('class');
        symbol_group.setAttribute('class', 'has-error form-group');
        return false;
    } else if (txt_description == null || txt_description == undefined || txt_description.length == 0) {
        description_group.removeAttribute('class');
        description_group.setAttribute('class', 'has-error form-group');
        return false;
    } else if (dd_Status == null || dd_Status == undefined || dd_Status.length == 0) {
        status_group.removeAttribute('class');
        status_group.setAttribute('class', 'has-error form-group');
        return false;
    }
};

var GetStatusName = function (id) {
    for (var index = 0; index < coinManagement.CoinStatuses.length; index++) {
        if (coinManagement.CoinStatuses[index].Id == id) {
            return coinManagement.CoinStatuses[index].Name;
        }
    }
};

var GetStatusNameHtml = function (id) {
    var result = GetStatusName(id);

    switch (parseInt(id)) {
        case 1:
            return '<span class="label label-info">' + result + '</span>';
            break;

        case 2:
            return '<span class="label label-primary">' + result + '</span>';
            break;

        case 3:
            return '<span class="label label-success">' + result + '</span>';
            break;

        case 4:
            return '<span class="label label-danger">' + result + '</span>';
            break;

        default:
            coinManagement.log('Invalid Status ID : ' + id);
            return '<span class="label label-default">#Invalid</span>';
            break;
    }

};

var getActionButton = function (objCoin) {
    if(objCoin.StatusId===3){
        return getStopActionButton(objCoin.Id);
    }else if(objCoin.StatusId===2 || objCoin.StatusId===4){
        return getStartActionButton(objCoin.Id);
    }else if(objCoin.StatusId===1){
       return  getAddActionButton(objCoin.Id);
    }
};

var getAddActionButton = function (id) {
    return '<button class="btn btn-raised btn-success btn-xs coinMgmtAddActionButton" data-id=' + id + '>Add Coin</button>';
};

var getStopActionButton = function (id) {
//    return '<button class="btn btn-raised btn-success btn-xs coinMgmtStartActionButton" data-id=' + id + '>Start Coin</button>';
     return '<button class="btn btn-raised btn-danger btn-xs coinMgmtStopActionButton" data-id=' + id + '>Pause Coin</button>';
};

var getStartActionButton = function (id) {
//    return '<button class="btn btn-raised btn-success btn-xs coinMgmtStartActionButton" data-id=' + id + '>Start Coin</button>';
     return '<button class="btn btn-raised btn-success btn-xs coinMgmtStartActionButton" data-id=' + id + '>Start Coin</button>';
};

var objToHtml = function (objCoin) {
    if (objCoin == null || objCoin == undefined) {
        return '';
    }
    return '<tr><td>' + objCoin.Symbol + '</td><td>' + objCoin.Description + '</td><td>' + GetStatusNameHtml(objCoin.StatusId) + '</td><td>' + getActionButton(objCoin) + '</td></tr>';
};

var addCoin = function (e) {

    console.log('# add coin called');
    e.target.removeAttribute('data-dismiss');

    if (coinEditFormIsValid() === false) {
        console.log('# add coin form is invalid');
        return;
    }

    e.target.setAttribute('data-dismiss', 'modal');

    var id = coinManagement.getNewCoinId();
    var txt_symbol = document.getElementById('txtSymbol').value;
    var txt_description = document.getElementById('txtDescription').value;
    var dd_Status = document.getElementById('ddStatus').value;

    var objNewCoin = new coinManagement.Coin(id, txt_symbol, txt_description, dd_Status);
    coinManagement.Post(objNewCoin);

    console.log('# coin added');
    renderGrid();
    coinEditFormReset();
};

var renderGrid = function () {

    console.log('# refreshing coin grid');

    var coinsTableBody = document.getElementById('Coins_table').getElementsByTagName('tbody')[0];
    coinsTableBody.innerHTML = '';

    coinManagement.Coins.forEach(function (element) {
        var htmlCoin = objToHtml(element);
        coinsTableBody.innerHTML += htmlCoin;
    });
};

var deleteCoin = function (id) {
    console.log('# coin delete called');
    coinManagement.Delete(id);
    renderGrid();
};

var pauseCoin = function (id) {
    console.log('# coin pause called');
    var index = coinManagement.GetCoinIndex(id);
     var coin=coinManagement.Coins[index].Symbol;
     console.log("clicked on coin "+coin); 
     var request="{\"agent\":\"iguana\",\"method\":\"pausecoin\",\"coin\":\""+coin+"\"}";
     
     SPNAPI.makeRequest(request, function(request,response){
            response=JSON.parse(response);
            if(response.result && response.result ==="coin paused"){
                var indx=coinManagement.GetCoinIndexBySymbol(request.coin);
                coinManagement.Coins[indx].StatusId=4;
                console.log("coins status changed "+coinManagement.Coins[indx].StatusId);
                renderGrid();
            }
        });
    
};

var startCoin = function (id) {
    console.log('# coin start called');
    //coinManagement.Delete(id);
     var index = coinManagement.GetCoinIndex(id);
     var coin=coinManagement.Coins[index].Symbol;
     console.log("clicked on coin "+coin); 
     var request="{\"agent\":\"iguana\",\"method\":\"startcoin\",\"coin\":\""+coin+"\"}";
     
     SPNAPI.makeRequest(request, function(request,response){
            response=JSON.parse(response);
            if(response.result && response.result ==="coin started"){
                var indx=coinManagement.GetCoinIndexBySymbol(request.coin);
                coinManagement.Coins[indx].StatusId=3;
                console.log("coins status changed "+coinManagement.Coins[indx].StatusId);
                renderGrid();
            }
        });
    
};

var addExistingCoin = function (id) {
    
    var isactive=0;
    var maxpeers=SPNAPI.settings.maxpeers;
    var services=128;
     var index = coinManagement.GetCoinIndex(id);
     console.log('# coin add called '+index);
     var coin=coinManagement.Coins[index].Symbol;
     console.log("clicked on coin "+coin); 
     var request="{\"agent\":\"iguana\",\"method\":\"addcoin\",\"newcoin\":\""+coin+"\",\"active\":"+isactive+",\"maxpeers\":"+maxpeers+",\"services\":"+services+"}";
     
     SPNAPI.makeRequest(request, function(request,response){
            response=JSON.parse(response);
            if(response.result && (response.result ==="coin added" || response.result ==="coin already there")){
                var indx=coinManagement.GetCoinIndexBySymbol(request.newcoin);
                coinManagement.Coins[indx].StatusId=2;
                console.log("coins status changed "+coinManagement.Coins[indx].StatusId);
                renderGrid();
            }
        });
    
};

var initCoinsAdded=false;

var addInitCoins= function(){
    
    if(!initCoinsAdded){
        for (var index = 0; index < coinManagement.Coins.length; index++) {
        addExistingCoin(coinManagement.Coins[index].Id);
        }
        initCoinsAdded=true;
    }
};

var coinEditFormReset = function () {
    document.getElementById('txtSymbol').value = '';
    document.getElementById('txtDescription').value = '';
    document.getElementById('ddStatus').value = 1;
};
// Event Handlers

var startCoinManagement = function () {

    coinManagement.Initialize();

    document.getElementById('btnSaveCoinForm').onclick = addCoin;
    document.getElementById('btnClearCoinForm').onclick = coinEditFormReset;
    document.getElementById('Coins_refresh').onclick = renderGrid;
    document.getElementById('Coins_reset').addEventListener('click', coinManagement.Initialize);
    document.getElementById('Coins_reset').addEventListener('click', renderGrid);

    renderGrid();
    populateCoinStatusDropDown();
};

var add_new_coin_test=function(){
    var request =  IsJsonString($('textarea#json_src_coin').val());
    
    if(request!==false){
        SPNAPI.makeRequest(JSON.stringify(request), function(request,response){
            //response=JSON.parse(response);
             $(".coin_result").text(response);
        });
        
    }else{
        console.log("Invalid JSON");
    }
    
};