var dJson = {};

dJson.ENCRYPTED = false;

dJson.request = {};

dJson._init = function(credentials) {
	this.request={};
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

	return obj;
};

//{"agent":"SuperNET","method":"encryptjson","passphrase":"<passphrase>","permanentfile":"<filename>","fromform":"valuefromform", "fromform2":"valuefromform2",...rest of form at top level}
dJson.encrypt = function(credentials, json, cb) {
	this._init(credentials);
var root=this;
	var jsonObj;

	if(jsonObj = this._checkJson(json)) {
		this.ENCRYPTED = true;
		this.request.method = "encryptjson";
		var tempRequest=this.request;
console.log(JSON.stringify(this.request));
		for(var attr in jsonObj) {
			if(jsonObj.hasOwnProperty(attr)) {
				this.request[attr] = jsonObj[attr];
			};
		};

		var request = JSON.stringify(this.request);

		SPNAPI.makeRequest(
			JSON.stringify(this.request),
			function(request,response){
			root.request=tempRequest;
			console.log(JSON.stringify(root.request));
	        	cb(response);    

	    	}
		);		
		} else 
			cb(null);
};

//{"agent":"SuperNET","method":"decryptjson","passphrase":"<passphrase>","permanentfile":"<filename>"}
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

// Read file contents from html5 file system
var readJsonEncryptedFile = function(filename,callback){

	fileSystem.root.getFile(filename, {}, function(fileEntry) {

		fileEntry.file(function(file) {
			var reader = new FileReader();

			reader.onloadend = function(e) {
				console.log("file content " + filename, this.result.toString());
				callback(this.result.toString());
			};

			reader.readAsText(file);
		}, function(e){
			errorHandler(e);
			callback(e.message);
		});

	}, function(e){
		errorHandler(e);
		callback(e.message);
	});
};

$(document).ready(function() {

	var encryptBtn = $('#debug_json_encrypt'),
		decryptBtn = $('#debug_json_decrypt'),
		debugJsonResult = $('#debug_json_result'),
		debugFileResult = $('#debug_json_file'),
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

			// Get file contents
			var resObj = dJson._checkJson(response);
			if(resObj && resObj.filename) {
				readJsonEncryptedFile(resObj.filename, function(filedata) {
					//console.log('returned filedata', filedata);
					debugFileResult.text(filedata);
				});
			}
		});
		
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

	$("#debug_clear_response").click(function(e) {
		e.preventDefault();
		debugJsonResult.text("JSON response");
		debugFileResult.text("encrypted file content");
	});
});



