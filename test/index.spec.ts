import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('AI Gateway Logpush Decrypter', () => {
	// Test credentials - DO NOT use in production
	const TEST_LOGPUSH_TOKEN = 'test-token-12345';
	const TEST_DD_API_KEY = 'test-dd-api-key';
	
	// Test RSA key pair (2048-bit) - Generated for testing only
	const TEST_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDMiU7zon8ExdD6
yppS9oo6SNirtym/NpKEpm+V7c8e54zuwQnb5E+Z81YLucwyZGrm7zvc2tpWwt5t
uiLcnvncJOeHM97ee2IY8yl4gJKDJHkOG38TVwSxTej0ocQQVXhB6ZvCxc+J93vT
bt8OiJMbLP/k4BMWxvhaNgKknmnvWbRRLcVSglBpWdgIh37zfzI4LA4LBGwKLwKy
4ZoViJNrLRE1ebr3X/kUxBzXj96d05TyyqhOHaaY8SF4ZrHONFUY6p5rOnN0zdUF
qSnQjbPVaMGmNDn2rPYPpW/a6UOiYNE9n59zz8DhzWIxTtfchTsV6TCErViJM9mR
rNHA+YeFAgMBAAECggEAFD0+D8Ozl/BPJpHnxW/Z67yLnCpKuj4XL4McpZRbm25E
NtfpNtYXvl8i05Q2DYJ8RY/Et6z8T/uGcQsrKfOdO9h3BJzwX8mLwnZFU0Q9uzZf
uDKmV26T60uPUq2zLf6XIMaSACr8x2Uy3pApCFIhZF4GkEpP+UAFEUAo8MswJlvn
v4UuBjs6DwHEM9SkxdO6inHr8Vp1O36YR3u+QE4CL8PBPWXMYbwPI9ah/uj0PQ14
xWvBgl7wRoDuZ2v8NYNy3f7HSZDPDz3D2LRYwmTi5h5cLg7NUTV34M9BZrMlJYn1
8f1xHdMUoo4p3qb3PfhM7MoxuhbsiDaTYpxVKfLO/QKBgQDl4FNGFYwdOEsb4hWM
WC5mEnomvrhXmuWG5iJEXM2NgzZFhFMRBcCWbsbiksutQzcfHO9OgSeHGa1+MXKL
j7rXHLA2WyWCXIRkgcpxckY1ToL5CQIK/9SK9PUnd74un7k8+kPnxsp4xOYa7gO6
qAhqoofDZhwEZta8j4faWMSk/wKBgQDjx8goptNe9gJAm2rvyQxVALAcnm4p6VA0
EcAEM846dQ10XZ5xHgPvWAiaaPez5l3b2EiVNOIfcLCD9X/8qAvQRkxvjLPs3nY9
sPutU0ePxxMrP1LQqAVWmvq5w22Qs0PD86Q67A45e1ZYo7MY55tfY4GybXQ14/LI
FrjuKJy/ewKBgQDj8nVBCv7cvsSkCqWpfIvOBcaBAyBTJrMx+KTEO25NRG6dsqCY
Qab+xSyM4ln8HqnbPVsD8siajFjgyPG3+Leitbz6uZlRUqKp85YmttVt6MOxZUBU
XemKPWuYToIVQ6dxEw4hGJwP89flnl2uSw/FhhOwLGHd74hChOWHG/0rSwKBgQDh
wCpvp8/LyPQ4hhB5MIBJatIguyCh5zv3LzRotdOJ+mLoVrTmlYH+3/g+2RPOt92E
OxrMzkniMTSwxEsh5Ic418N/tyrH8z+rKtJ1WRmOtRYZgbwZUr1ftWATZk4b4J+k
AMBfKX97lvLgDPY/E6TY6G0tou9PTelcR7DnUVbxKwKBgQC3++0Nq9VdmPgaZXPZ
+NHSnPtOsMvSJ6szfKc6f6u0jSt4ncPqyeFcLael+sIk4Euwozw96o/y+uQ845Ra
aScVcXW9HrdVk3GXJkypzc9uCb/lOz/H4zHDDNlsCe7rRujua9xUS/nMfX8qsFhp
Lp+D3//srHwHTx32sdycdTi8AA==
-----END PRIVATE KEY-----`;
	
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
});
