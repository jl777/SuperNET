$('document').ready(function(){

	$('#login-form').formValidation({
	        framework: 'bootstrap',
	        err: {
	            container: '#messages'
	        },
	        icon: {
	            valid: 'glyphicon glyphicon-ok',
	            invalid: 'glyphicon glyphicon-remove',
	            validating: 'glyphicon glyphicon-refresh'
	        },
	        fields: {
	            passphrasetext: {
	                validators: {
	                    callback: {
	                    		message: 'Incorrect passphrase, it consist of 24-word. Try to type or paste the passphrase one more time.',
	                            callback: function (value, validator, $field) {
	                            	if($("#passphrase-text").val().length) {
											$('#login-hint').removeClass('hide');
											$('#account-login').removeClass('disabled');
											$('#account-login').prop('disabled', false);
											return true;
									} else {
										$('#login-hint').addClass('hide');
										$('#account-login').addClass('disabled');
										$('#account-login').prop('disabled', true);
										return {
	                                    	valid: false,
	                                    	message: 'Incorrect passphrase, it consist of 24-word. Try to type or paste the passphrase one more time.'
	                                	}
									}
	                                return true;
	                            }
	                        }    
	                }
	            }
	        }
	});



	$('#add-passphrase-text').keyup(function(e){
		e.preventDefault();
		if($(this).val().length) {
			if(createdPassPhrase.trim() == $(this).val().trim()) {
				$('#paassphrase-confirmation-hint').removeClass('hide');
					$('#add-account').removeClass('disabled');
					$('#add-account').prop('disabled', false);
				} else {
					$('#paassphrase-confirmation-hint').removeClass('hide');
					$('#confirmation-message').text('Incorrect passphrase, it consist of 24-word. Try to type or paste the passphrase one more time.');
					$('#confirmation-message').addClass('errorMessage');
					$('#add-account').addClass('disabled');
					$('#add-account').prop('disabled', true);
				}
			$('#passphrase-text').removeClass('disabled');
		} else {
			$('#confirmation-message').text('Type or paste the passphrease to confirm you saved it properly');
			$('#confirmation-message').removeClass('errorMessage');
		}
	});

	$('#create-account').click(function(e) {
		e.preventDefault();
		loadCreateAccountScreen();	
		
	});

	$('#login-back').click(function(e) {
		e.preventDefault();
		loadLoginScreen();	
		
	});

	$('#create-account-next').click(function(e) {
		e.preventDefault();
		loadSaveAccountScreen();	
		
	});

	$('#account-back').click(function(e) {
		e.preventDefault();
		loadBacktoAccountScreen();	
		
	});

	function loadCreateAccountScreen() {
		$('#login-form').data('formValidation').resetForm();
		$('#window-close').addClass('hide');
		$('#login-hint').addClass('hide');
		$('#login-form').addClass('hide');
		$('#login-acreen-actions').addClass('hide');
		

		$('#login-back').removeClass('hide');
		$('#accounts-label').removeClass('hide');
		$('#passphrase-hint').removeClass('hide');
		$('#create-account-form').removeClass('hide');
		$('#create-account-actions').removeClass('hide');

		var passphrase = PassPhraseGenerator.generatePassPhrase();

	        $('#create-passphrase-text').html(passphrase);
	        $( '#passphrase-save-check' ).prop( "checked", false ).trigger('change');
	};

	function loadLoginScreen() {
		$('#window-close').removeClass('hide');
		$('#login-hint').removeClass('hide');
		$('#login-form').removeClass('hide');
		$('#login-form').removeClass('hide');
		$('#login-acreen-actions').removeClass('hide');

		$('#login-back').addClass('hide');
		$('#accounts-label').addClass('hide');
		$('#passphrase-hint').addClass('hide');
		$('#create-account-form').addClass('hide');
		$('#create-account-actions').addClass('hide');
	    $('#create-passphrase-text').html('');
	    $("#create-passphrase-text").prop("disabled", false);
	};

	function loadSaveAccountScreen() {
		$('#account-back').removeClass('hide');
		$('#paassphrase-confirmation-hint').removeClass('hide');
		$('#add-account-form').removeClass('hide');
		$('#add-account-actions').removeClass('hide');
		$('#add-passphrase-text').html('').val('');
		
		createdPassPhrase = $('#create-passphrase-text').val();

		$('#login-back').addClass('hide');
		$('#passphrase-hint').addClass('hide');
		$('#create-account-form').addClass('hide');
		$('#create-account-actions').addClass('hide');
	}

	function loadBacktoAccountScreen() {
		$('#account-back').addClass('hide');
		$('#paassphrase-confirmation-hint').addClass('hide');
		$('#add-account-form').addClass('hide');
		$('#add-account-actions').addClass('hide');

		$('#login-back').removeClass('hide');
		$('#passphrase-hint').removeClass('hide');
		$('#create-account-form').removeClass('hide');
		$('#create-account-actions').removeClass('hide');
		$( '#passphrase-save-check' ).prop( "checked", false ).trigger('change');
	};

	$('#passphrase-save-check').change(function(e) {
		e.preventDefault();

		if($(this).is(":checked")) {
			$('#create-account-next').removeClass('disabled');
			$('#create-account-next').prop('disabled', false);
		} else {
			$('#create-account-next').addClass('disabled');
			$('#create-account-next').prop('disabled', true);
		}
	});
});	