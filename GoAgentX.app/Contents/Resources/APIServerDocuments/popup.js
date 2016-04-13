var rules = [];

function api(path) {
	return '/' + path;
}

function load_profiles() {
	$.getJSON(api('profiles'), function(data) {
		var profiles = data.profiles;
		$('#profile').children().remove();
		for (var i = 0; i < profiles.length; ++i) {
			var profile = profiles[i];
			$('#profile').append('<option value="' + profile.profile + '">' + profile.name + '</option>');
			$('#profile').val('AutoDetect');
		}

		load_pac_content();
	});
}

function load_pac_content() {
	$.getJSON(api('pac_content'), function(data) {
		var data = {
			command: 'pac',
			pac: data.pac_content
		};
		send_sandbox_command(data);
	});

	$.getJSON(api('rules'), function(data) {
		rules = data.rules;
	});
}

function send_sandbox_command(data) {
	var win = $('#sandbox').get(0).contentWindow;
	win.postMessage(data, '*');
}

function process_url(url) {
	if (!url) {
		$('#domain').val('');
		update_form_with_rule(null);
		return;
	}

	var host = '', trimedHost = '';

	$('#url_host').attr('href', url);
	host = $('#url_host').attr('host');
	trimedHost = host;
	if (host.length > 0) {
		var hosts = host.split('.');
		if ((hosts.length > 2 && hosts[hosts.length-1].length >= 3) ||
			hosts.length > 3) {
			hosts.shift();
			trimedHost = '.' + hosts.join('.');
		}
	}
	$('#domain').val(trimedHost);

	send_sandbox_command({
		command: 'find_rule',
		url: url,
		host: host
	});
}

function get_current_settings() {
	if (typeof(chrome) != 'undefined' && chrome.tabs) {
		chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
			var url = tabs[0].url || '';
			process_url(url);
		});
	} else {
		var url = location.search.substr(1);
		process_url(url);
	}
}

function start_update_view() {
	$('#domain, #profile, #btn').attr('disabled', 'disabled');

	$.getJSON(api('status'), function(data) {
		if (data && data.status == 'success') {
			$('#domain, #profile, #btn').removeAttr('disabled');
			load_profiles();

			$('#domain').focus();
		}
	});
}

function update_form_action(isAdd) {
	$('#btn').removeClass('pure-button-primary').removeClass('pure-button-warning');
	if (isAdd) {
		$('#form').attr('action', 'add_domain');
		$('#btn').addClass('pure-button-primary').html('Add Rule');
	} else {
		$('#form').attr('action', 'remove_domain');
		$('#btn').addClass('pure-button-warning').html('Remove Rule');
	}
}

function update_form_with_rule(rule) {
	if (rule) {
		$('#domain').val(rule.rule);
		$('#profile').val(rule.identifier);
		update_form_action(false);
	} else {
		$('#profile').val('AutoDetect');
		update_form_action(true);
	}
}

$(function() {
	window.addEventListener('message', function(event) {
		var cmd = event.data.command;
		if (cmd == 'pac_loaded') {
			get_current_settings();
		} else if (cmd == 'rule_found') {
			var rule = event.data.rule;
			update_form_with_rule(rule);	
		}
	});

	$('#btn').on('click', function(e) {
		$.getJSON(api($('#form').attr('action')), {
			domain: $('#domain').val(),
			profile: $('#profile').val()
		}, function(data) {
			if (typeof(chrome) != 'undefined' && chrome.tabs) {
				chrome.tabs.reload();
				window.close();
			} else {
				location.href = 'app://closewindow';
			}
		});

		return false;
	});

	$('#domain').on('input', function(e) {
		var currentRule = $('#domain').val();
		for (var i = 0; i < rules.length; ++i) {
			if (currentRule == rules[i].rule) {
				update_form_action(false);
				$('#profile').val(rules[i].identifier);
				return;
			}
		}

		update_form_action(true);
		$('#profile').val('AutoDetect');
	});

	start_update_view();
});
