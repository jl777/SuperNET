var dJson = {};

dJson.ENCRYPTED = false;

dJson.request = {};

dJson._init = function(credentials) {
	for(var attr in this.request) {
		if(this.request.hasOwnProperty(attr)) {
			this.request[attr] = null;
		};
	};

	this.request.passphrase = credentials.passphrase;
	this.request.permanentfile = credentials.permanentfile;
	this.request.agent = "SuperNET";
};

dJson._checkJson = function(json) {
	try {
		var obj = JSON.parse(json);	
	} catch(e) {
		return false;
	};

	return ogj;
};

//{"agent":"SuperNET","method":"encryptjson","passphrase":"<passphrase>","permanentfile":"<filename>","fromform":"valuefromform","fromform2":"valuefromform2",...rest of form at top level}
dJson.encrypt = function(credentials, json, cb) {
	this._init(credentials);

	var jsonObj;

	if(jsonObj = this._checkJson) {
		this.ENCRYPTED = true;
		this.request.method = "encryptjson";

		for(var attr in jsonObj) {
			if(jsonObj.hasOwnProperty(attr)) {
				this.request[attr] = jsonObj[attr];
			};
		};

		var request = JSON.stringify(this.request);

		SPNAPI.makeRequest(
			JSON.stringify(this.request),
			function(request,response){
	        	cb(response);    
	    	}
		);		
		} else 
			cb(null);
};

//{"agent":"SuperNET","method":"encryptjson","passphrase":"<passphrase>","permanentfile":"<filename>"}
dJson.decrypt = function(credentials, cb) {
	this._init(credentials);
	
	this.ENCRYPTED = false;
	this.request.method = "decryptjson";

	SPNAPI.makeRequest(
		JSON.stringify(this.request),
		function(request,response){
    		cb(response);
		}
	);
};

$(document).ready(function() {

	var encryptBtn = $('#debug_json_encrypt'),
		decryptBtn = $('#debug_json_decrypt'),
		debugJsonResult = $('#debug_json_result'),
		pass = $('#debug_passphrase'),
		permFile = $('#debug_permanentfile'),
		jsonSrc = $('#debug_json_src');


	$(encryptBtn).click(function(e) {
		e.preventDefault();
		debugJsonResult.text('');
		
		dJson.encrypt({
				passphrase: pass.val(),
				permanentfile: permFile.val()
			},
			jsonSrc.val(), 
			function(response) {
				debugJsonResult.text(response || 'wrong json');
			}
		);
	});
		
	$(decryptBtn).click(function(e) {
		e.preventDefault();

		if( !dJson.ENCRYPTED) {
			debugJsonResult.text('Please call encryptjson first');
			return;
		};

		dJson.decrypt({
			passphrase: pass.val(),
			permanentfile: permFile.val()
		}, function(response) {
			debugJsonResult.text(response);
		});
	});	
});



