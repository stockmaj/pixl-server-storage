// Unit tests for Azure Workload Identity password plugin
// Copyright (c) 2026 Joseph Huckaby
// Released under the MIT License

var fs = require('fs');
var path = require('path');
var os = require('os');
var https = require('https');

var fetchToken = require('../plugins/azure-workload-identity.js');

function withEnv(vars, fn) {
	var originals = {};
	Object.keys(vars).forEach(function(k) {
		originals[k] = process.env[k];
		if (vars[k] == null) delete process.env[k];
		else process.env[k] = vars[k];
	});
	try { fn(); }
	finally {
		Object.keys(originals).forEach(function(k) {
			if (originals[k] == null) delete process.env[k];
			else process.env[k] = originals[k];
		});
	}
}

function mockHttpsRequest(statusCode, responseBody) {
	var EventEmitter = require('events');
	var origRequest = https.request;
	https.request = function(options, cb) {
		var res = new EventEmitter();
		res.statusCode = statusCode;
		var fakeReq = new EventEmitter();
		fakeReq.write = function() {};
		fakeReq.setTimeout = function() {};
		fakeReq.destroy = function(err) { fakeReq.emit('error', err); };
		fakeReq.end = function() {
			setImmediate(function() {
				cb(res);
				setImmediate(function() {
					res.emit('data', typeof responseBody === 'string' ? responseBody : JSON.stringify(responseBody));
					res.emit('end');
				});
			});
		};
		return fakeReq;
	};
	return function restore() { https.request = origRequest; };
}

function tmpTokenFile(content) {
	var file = path.join(os.tmpdir(), 'pixl-awi-test-' + process.pid + '-' + Date.now() + '.txt');
	fs.writeFileSync(file, content, 'utf8');
	return file;
}

module.exports = {
	tests: [

		function fetchToken_missingEnvVars(test) {
			test.expect(1);
			withEnv({ AZURE_TENANT_ID: null, AZURE_CLIENT_ID: null, AZURE_FEDERATED_TOKEN_FILE: null }, function() {
				fetchToken(function(err) {
					test.ok(err && /AZURE_TENANT_ID/.test(err.message), "Error mentions missing env vars: " + (err && err.message));
					test.done();
				});
			});
		},

		function fetchToken_unreadableTokenFile(test) {
			test.expect(1);
			withEnv({
				AZURE_TENANT_ID: 'tid',
				AZURE_CLIENT_ID: 'cid',
				AZURE_FEDERATED_TOKEN_FILE: '/nonexistent/path/to/token'
			}, function() {
				fetchToken(function(err) {
					test.ok(err && /failed to read token file/.test(err.message), "Error mentions token file: " + (err && err.message));
					test.done();
				});
			});
		},

		function fetchToken_happyPath(test) {
			test.expect(3);
			var tokenFile = tmpTokenFile('FAKE_FEDERATED_TOKEN\n');
			var restore = mockHttpsRequest(200, { access_token: 'ENTRA_TOKEN', expires_in: 3599 });

			withEnv({ AZURE_TENANT_ID: 'test-tid', AZURE_CLIENT_ID: 'test-cid', AZURE_FEDERATED_TOKEN_FILE: tokenFile }, function() {
				fetchToken(function(err, result) {
					restore();
					try { fs.unlinkSync(tokenFile); } catch(e) {}
					test.ok(!err, "No error: " + err);
					test.ok(result && result.password === 'ENTRA_TOKEN', "Returned access_token as password");
					test.ok(result && result.ttl === 3299, "TTL is expires_in - 300: " + result.ttl);
					test.done();
				});
			});
			// restore env is synchronous in finally block so it's safe here
			// but we still need to reach the async callback above — test.done() handles it
		},

		function fetchToken_usesCorrectEndpoint(test) {
			test.expect(2);
			var tokenFile = tmpTokenFile('FAKE_TOKEN');
			var capturedOptions = null;
			var EventEmitter = require('events');
			var origRequest = https.request;
			https.request = function(options, cb) {
				capturedOptions = options;
				var res = new EventEmitter();
				res.statusCode = 200;
				var fakeReq = new EventEmitter();
				fakeReq.write = function() {};
				fakeReq.setTimeout = function() {};
				fakeReq.destroy = function() {};
				fakeReq.end = function() {
					setImmediate(function() {
						cb(res);
						setImmediate(function() {
							res.emit('data', JSON.stringify({ access_token: 'TOK', expires_in: 3599 }));
							res.emit('end');
						});
					});
				};
				return fakeReq;
			};

			withEnv({ AZURE_TENANT_ID: 'my-tenant', AZURE_CLIENT_ID: 'my-cid', AZURE_FEDERATED_TOKEN_FILE: tokenFile }, function() {
				fetchToken(function(err) {
					https.request = origRequest;
					try { fs.unlinkSync(tokenFile); } catch(e) {}
					test.ok(capturedOptions && capturedOptions.hostname === 'login.microsoftonline.com', "Calls login.microsoftonline.com");
					test.ok(capturedOptions && capturedOptions.path.indexOf('my-tenant') >= 0, "Path contains tenant ID");
					test.done();
				});
			});
		},

		function fetchToken_rejectsErrorResponse(test) {
			test.expect(2);
			var tokenFile = tmpTokenFile('FAKE_TOKEN');
			var restore = mockHttpsRequest(401, { error: 'invalid_client' });

			withEnv({ AZURE_TENANT_ID: 'tid', AZURE_CLIENT_ID: 'cid', AZURE_FEDERATED_TOKEN_FILE: tokenFile }, function() {
				fetchToken(function(err) {
					restore();
					try { fs.unlinkSync(tokenFile); } catch(e) {}
					test.ok(err && /Azure token fetch failed/.test(err.message), "Error mentions fetch failure");
					test.ok(err && /HTTP 401/.test(err.message), "Error includes HTTP status");
					test.done();
				});
			});
		},

		function fetchToken_networkError(test) {
			test.expect(1);
			var tokenFile = tmpTokenFile('FAKE_TOKEN');
			var EventEmitter = require('events');
			var origRequest = https.request;
			https.request = function(options, cb) {
				var fakeReq = new EventEmitter();
				fakeReq.write = function() {};
				fakeReq.setTimeout = function() {};
				fakeReq.destroy = function() {};
				fakeReq.end = function() {
					setImmediate(function() { fakeReq.emit('error', new Error('ECONNREFUSED')); });
				};
				return fakeReq;
			};

			withEnv({ AZURE_TENANT_ID: 'tid', AZURE_CLIENT_ID: 'cid', AZURE_FEDERATED_TOKEN_FILE: tokenFile }, function() {
				fetchToken(function(err) {
					https.request = origRequest;
					try { fs.unlinkSync(tokenFile); } catch(e) {}
					test.ok(err && /ECONNREFUSED/.test(err.message), "Network error propagates: " + (err && err.message));
					test.done();
				});
			});
		},

		function fetchToken_requestTimeout(test) {
			test.expect(1);
			var tokenFile = tmpTokenFile('FAKE_TOKEN');
			var EventEmitter = require('events');
			var origRequest = https.request;
			https.request = function(options, cb) {
				var fakeReq = new EventEmitter();
				fakeReq.write = function() {};
				fakeReq.setTimeout = function(ms, handler) { setImmediate(handler); };
				fakeReq.destroy = function(err) { setImmediate(function() { fakeReq.emit('error', err); }); };
				fakeReq.end = function() {};
				return fakeReq;
			};

			withEnv({ AZURE_TENANT_ID: 'tid', AZURE_CLIENT_ID: 'cid', AZURE_FEDERATED_TOKEN_FILE: tokenFile }, function() {
				fetchToken(function(err) {
					https.request = origRequest;
					try { fs.unlinkSync(tokenFile); } catch(e) {}
					test.ok(err && /timed out/.test(err.message), "Timeout error propagates: " + (err && err.message));
					test.done();
				});
			});
		},

		function fetchToken_ttlFallbackWhenExpiresInAbsent(test) {
			test.expect(1);
			var tokenFile = tmpTokenFile('FAKE_TOKEN');
			var restore = mockHttpsRequest(200, { access_token: 'TOK' }); // no expires_in

			withEnv({ AZURE_TENANT_ID: 'tid', AZURE_CLIENT_ID: 'cid', AZURE_FEDERATED_TOKEN_FILE: tokenFile }, function() {
				fetchToken(function(err, result) {
					restore();
					try { fs.unlinkSync(tokenFile); } catch(e) {}
					// fallback: assumes 3600s, subtracts 300 => 3300
					test.ok(result && result.ttl === 3300, "TTL defaults to 3300 when expires_in absent: " + (result && result.ttl));
					test.done();
				});
			});
		}

	]
};
