// Azure Workload Identity password plugin for pixl-server-storage
// Copyright (c) 2026 Joseph Huckaby
// Released under the MIT License
//
// Use as a passwordPlugin command:
//   "passwordPlugin": "node node_modules/pixl-server-storage/plugins/azure-workload-identity.js"
//
// Required env vars (injected automatically by the Azure Workload Identity webhook):
//   AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE

var https = require('https');
var fs = require('fs');

function fetchToken(callback) {
	var tenant_id = process.env.AZURE_TENANT_ID;
	var client_id = process.env.AZURE_CLIENT_ID;
	var token_file = process.env.AZURE_FEDERATED_TOKEN_FILE;

	if (!tenant_id || !client_id || !token_file) {
		return callback(new Error("Azure Workload Identity requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE env vars"));
	}

	var federated_token;
	try { federated_token = fs.readFileSync(token_file, 'utf8').trim(); }
	catch(e) { return callback(new Error("Azure Workload Identity: failed to read token file '" + token_file + "': " + e.message)); }

	var body = new URLSearchParams({
		grant_type: 'client_credentials',
		client_id: client_id,
		scope: 'https://ossrdbms-aad.database.windows.net/.default',
		client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
		client_assertion: federated_token
	}).toString();

	var options = {
		hostname: 'login.microsoftonline.com',
		path: '/' + tenant_id + '/oauth2/v2.0/token',
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'Content-Length': Buffer.byteLength(body)
		}
	};

	var req = https.request(options, function(res) {
		var data = '';
		res.on('data', function(chunk) { data += chunk; });
		res.on('end', function() {
			try {
				var parsed = JSON.parse(data);
				if (parsed.access_token) {
					// Azure tokens include expires_in (typically 3599s); subtract 5 min safety margin
					var ttl = Math.max(0, parseInt(parsed.expires_in || 3600, 10) - 300);
					return callback(null, { password: parsed.access_token, ttl: ttl });
				}
				callback(new Error("Azure token fetch failed (HTTP " + res.statusCode + "): " + data));
			} catch(e) { callback(e); }
		});
	});

	req.setTimeout(10000, function() { req.destroy(new Error("Azure token fetch timed out")); });
	req.on('error', callback);
	req.write(body);
	req.end();
}

module.exports = fetchToken;

if (require.main === module) {
	// Run as a passwordPlugin command: consume stdin (ignored), write result to stdout
	var input = '';
	process.stdin.on('data', function(d) { input += d; });
	process.stdin.on('end', function() {
		fetchToken(function(err, result) {
			if (err) {
				process.stdout.write(JSON.stringify({ code: 'auth', description: err.message }) + '\n');
				process.exit(1);
			}
			process.stdout.write(JSON.stringify(result) + '\n');
		});
	});
}
