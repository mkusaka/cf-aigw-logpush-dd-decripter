import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('AI Gateway Logpush Decrypter', () => {
	// Test credentials - DO NOT use in production
	const TEST_LOGPUSH_TOKEN = 'test-token-12345';
	
	const TEST_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIlO86J/BMXQ+sqaUvaK
OkjYq7cpvzaShKZvle3PHueM7sEJ2+RPmfNWC7nMMmRq5u873NraVsLebboi3J75
3CTnhzPe3ntiGPMpeICSgyR5Dht/E1cEsU3o9KHEEFV4QembwsXPifd7027fDoiT
Gyz/5OATFsb4WjYCpJ5p71m0US3FUoJQaVnYCId+838yOCwOCwRsCi8CsuGaFYiT
ay0RNXm691/5FMQc14/endOU8sqoTh2mmPEheGaxzjRVGOqeazpzdM3VBakp0I2z
1WjBpjQ59qz2D6Vv2ulDomDRPZ+fc8/A4c1iMU7X3IU7FekwhK1YiTPZkazRwPmH
hQIDAQAB
-----END PUBLIC KEY-----`;

	// Helper function to encrypt test data
	async function encryptTestData(data: any): Promise<{ key: string; iv: string; data: string }> {
		// Generate AES key
		const aesKey = await crypto.subtle.generateKey(
			{ name: 'AES-GCM', length: 256 },
			true,
			['encrypt']
		);

		// Export AES key
		const aesKeyData = await crypto.subtle.exportKey('raw', aesKey);

		// Import public key for RSA encryption
		const pemHeader = '-----BEGIN PUBLIC KEY-----';
		const pemFooter = '-----END PUBLIC KEY-----';
		const pemContents = TEST_PUBLIC_KEY
			.replace(pemHeader, '')
			.replace(pemFooter, '')
			.replace(/\s+/g, '');
		
		const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
		const rsaPublicKey = await crypto.subtle.importKey(
			'spki',
			binaryDer.buffer,
			{ name: 'RSA-OAEP', hash: 'SHA-256' },
			false,
			['encrypt']
		);

		// Encrypt AES key with RSA
		const encryptedKey = await crypto.subtle.encrypt(
			{ name: 'RSA-OAEP' },
			rsaPublicKey,
			aesKeyData
		);

		// Generate IV
		const iv = crypto.getRandomValues(new Uint8Array(12));

		// Encrypt data with AES
		const encoder = new TextEncoder();
		const encryptedData = await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv, tagLength: 128 },
			aesKey,
			encoder.encode(JSON.stringify(data))
		);

		return {
			key: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
			iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
			data: btoa(String.fromCharCode(...new Uint8Array(encryptedData)))
		};
	}

	// Environment variables are set in vitest.config.mts

	it('should have environment variables set', () => {
		expect(env.LOGPUSH_TOKEN).toBe(TEST_LOGPUSH_TOKEN);
		expect(env.PRIVATE_KEY).toBeTruthy();
		expect(env.PRIVATE_KEY).toContain('BEGIN PRIVATE KEY');
	});

	it('should reject requests without authentication token', async () => {
		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({}),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(401);
		expect(await response.text()).toBe('unauthorized');
	});


	it('should decrypt encrypted fields and forward to Datadog', async () => {
		// Prepare test data
		const testMetadata = { user: 'test-user', timestamp: Date.now() };
		const testRequestBody = {
			model: 'gpt-3.5-turbo',
			temperature: 0.7,
			metadata: { user_id: 'test-123' },
			max_tokens: 100,
			stream: false
		};
		const testResponseBody = {
			id: 'response-123',
			type: 'message',
			role: 'assistant',
			model: 'gpt-3.5-turbo',
			content: 'Hello Human',
			stop_reason: 'stop_sequence',
			stop_sequence: null,
			usage: {
				input_tokens: 10,
				output_tokens: 20,
				service_tier: 'standard'
			}
		};

		// Encrypt test data
		const encryptedMetadata = await encryptTestData(testMetadata);
		const encryptedRequestBody = await encryptTestData(testRequestBody);
		const encryptedResponseBody = await encryptTestData(testResponseBody);

		const logEntry = {
			logId: 'test-log-123',
			timestamp: new Date().toISOString(),
			Metadata: { type: 'encrypted', ...encryptedMetadata },
			RequestBody: { type: 'encrypted', ...encryptedRequestBody },
			ResponseBody: { type: 'encrypted', ...encryptedResponseBody },
		};

		// Mock fetch to intercept Datadog API call
		const originalFetch = global.fetch;
		let datadogPayload: any = null;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogPayload = JSON.parse(init.body);
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: JSON.stringify(logEntry),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		// Verify response
		expect(response.status).toBe(202);

		// Verify Datadog payload
		expect(datadogPayload).toBeTruthy();
		expect(datadogPayload[0]).toMatchObject({
			ddsource: 'cloudflare',
			service: 'ai-gateway',
			host: 'ai-gateway-host',
			ddtags: 'env:prod,team:infra',
			Metadata: testMetadata,
			RequestBody: testRequestBody,
			ResponseBody: testResponseBody,
		});
	});

	it('should handle logs with unencrypted fields', async () => {
		const logEntry = {
			logId: 'test-log-456',
			timestamp: new Date().toISOString(),
			Metadata: { plainField: 'not encrypted' },
			RequestBody: null,
			ResponseBody: { status: 200 },
		};

		// Mock fetch
		const originalFetch = global.fetch;
		let datadogPayload: any = null;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogPayload = JSON.parse(init.body);
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: JSON.stringify(logEntry),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		expect(response.status).toBe(202);
		expect(datadogPayload[0]).toMatchObject({
			ddsource: 'cloudflare',
			service: 'ai-gateway',
			host: 'ai-gateway-host',
			ddtags: 'env:prod,team:infra',
			Metadata: { plainField: 'not encrypted' },
			ResponseBody: {},
		});
	});

	it('should accept any path for flexibility with Logpush', async () => {
		const request = new IncomingRequest('http://example.com/any/path/here', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: JSON.stringify({ test: 'data' }),
		});

		// Mock fetch
		const originalFetch = global.fetch;
		let datadogPayload: any = null;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogPayload = JSON.parse(init.body);
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		expect(response.status).toBe(202);
		expect(datadogPayload).toBeTruthy();
	});

	it('should reject requests with wrong token', async () => {
		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': 'wrong-token',
			},
			body: JSON.stringify({}),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(401);
		expect(await response.text()).toBe('unauthorized');
	});

	it('should handle gzip compressed requests', async () => {
		// Prepare test data
		const logEntry = {
			logId: 'test-log-789',
			timestamp: new Date().toISOString(),
			Metadata: { plainField: 'gzip test' },
		};

		// Compress with gzip
		const encoder = new TextEncoder();
		const data = encoder.encode(JSON.stringify(logEntry));
		const compressionStream = new CompressionStream('gzip');
		const writer = compressionStream.writable.getWriter();
		writer.write(data);
		writer.close();
		
		const compressedData = await new Response(compressionStream.readable).arrayBuffer();

		// Mock fetch
		const originalFetch = global.fetch;
		let datadogPayload: any = null;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogPayload = JSON.parse(init.body);
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Content-Encoding': 'gzip',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: compressedData,
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		expect(response.status).toBe(202);
		expect(datadogPayload).toBeTruthy();
		expect(datadogPayload[0]).toMatchObject({
			Metadata: { plainField: 'gzip test' },
		});
	});

	it('should handle multiple log entries in NDJSON format', async () => {
		const logEntry1 = {
			logId: 'test-log-001',
			timestamp: new Date().toISOString(),
			Metadata: { entry: 1 },
		};
		const logEntry2 = {
			logId: 'test-log-002',
			timestamp: new Date().toISOString(),
			Metadata: { entry: 2 },
		};
		const logEntry3 = {
			logId: 'test-log-003',
			timestamp: new Date().toISOString(),
			Metadata: { entry: 3 },
		};

		// Create NDJSON format
		const ndjson = [
			JSON.stringify(logEntry1),
			JSON.stringify(logEntry2),
			JSON.stringify(logEntry3),
		].join('\n');

		// Mock fetch
		const originalFetch = global.fetch;
		let datadogPayload: any = null;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogPayload = JSON.parse(init.body);
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: ndjson,
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		expect(response.status).toBe(202);
		expect(datadogPayload).toBeTruthy();
		expect(datadogPayload.length).toBe(3);
		expect(datadogPayload[0]).toMatchObject({ Metadata: { entry: 1 } });
		expect(datadogPayload[1]).toMatchObject({ Metadata: { entry: 2 } });
		expect(datadogPayload[2]).toMatchObject({ Metadata: { entry: 3 } });
	});

	it('should handle decryption errors gracefully', async () => {
		const logEntry = {
			logId: 'test-log-bad',
			timestamp: new Date().toISOString(),
			Metadata: { 
				type: 'encrypted',
				key: 'invalid-base64-!!!',
				iv: 'bad-iv',
				data: 'bad-data'
			},
			RequestBody: { plainField: 'not encrypted' },
		};

		// Mock fetch
		const originalFetch = global.fetch;
		let datadogPayload: any = null;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogPayload = JSON.parse(init.body);
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: JSON.stringify(logEntry),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		// Should still succeed but skip the failed decryption
		expect(response.status).toBe(202);
		expect(datadogPayload).toBeTruthy();
		// Metadata should remain encrypted due to error
		expect(datadogPayload[0].Metadata).toMatchObject({
			type: 'encrypted',
			key: 'invalid-base64-!!!',
			iv: 'bad-iv',
			data: 'bad-data'
		});
	});

	it('should handle Datadog API errors', async () => {
		const logEntry = {
			logId: 'test-log-dd-error',
			timestamp: new Date().toISOString(),
			Metadata: { test: 'datadog error' },
		};

		// Mock fetch to return error
		const originalFetch = global.fetch;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				return new Response('Bad Request', { status: 400 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: JSON.stringify(logEntry),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		expect(response.status).toBe(500);
		expect(await response.text()).toBe('Failed to forward to Datadog');
	});

	it('should handle invalid JSON in request body', async () => {
		// Mock fetch to not be called
		const originalFetch = global.fetch;
		let datadogCalled = false;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogCalled = true;
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: 'invalid json {{{',
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		// Should process empty array when JSON parsing fails for individual lines
		expect(response.status).toBe(202);
		expect(datadogCalled).toBe(true);
	});

	it('should handle empty request body', async () => {
		// Mock fetch
		const originalFetch = global.fetch;
		let datadogPayload: any = null;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogPayload = JSON.parse(init.body);
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: '',
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		expect(response.status).toBe(202);
		expect(datadogPayload).toEqual([]);
	});

	it('should handle R2 storage errors gracefully', async () => {
		// Create a modified env with failing R2 bucket
		const failingEnv = {
			...env,
			LOG_BUCKET: {
				put: async () => {
					throw new Error('R2 storage failed');
				}
			}
		};

		const logEntry = {
			logId: 'test-log-r2-error',
			timestamp: new Date().toISOString(),
			Metadata: { test: 'r2 error' },
		};

		// Mock fetch
		const originalFetch = global.fetch;
		let datadogPayload: any = null;
		
		global.fetch = async (input: any, init?: any) => {
			if (typeof input === 'string' && input.includes('datadoghq.com')) {
				datadogPayload = JSON.parse(init.body);
				return new Response(null, { status: 202 });
			}
			return originalFetch(input, init);
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: JSON.stringify(logEntry),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, failingEnv as any, ctx);
		await waitOnExecutionContext(ctx);

		// Restore original fetch
		global.fetch = originalFetch;

		// Should still succeed despite R2 error
		expect(response.status).toBe(202);
		expect(datadogPayload).toBeTruthy();
	});

	it('should handle worker errors', async () => {
		// Create env without LOGPUSH_TOKEN to trigger internal error path
		const badEnv = {
			...env,
			LOGPUSH_TOKEN: undefined
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: JSON.stringify({}),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, badEnv as any, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(401);
	});

	it('should handle invalid PEM format', async () => {
		// Create env with invalid PRIVATE_KEY
		const badPemEnv = {
			...env,
			PRIVATE_KEY: 'INVALID PEM CONTENT WITHOUT HEADERS'
		};

		const logEntry = {
			logId: 'test-log-pem',
			timestamp: new Date().toISOString(),
			Metadata: { test: 'pem error' },
		};

		const request = new IncomingRequest('http://example.com/ingest', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Logpush-Token': TEST_LOGPUSH_TOKEN,
			},
			body: JSON.stringify(logEntry),
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, badPemEnv as any, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(500);
		expect(await response.text()).toBe('Internal server error');
	});
});
