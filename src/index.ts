/**
 * Cloudflare AI Gateway Logpush Decrypter for Datadog
 * 
 * This Worker decrypts encrypted fields from Cloudflare AI Gateway logs
 * and forwards them to Datadog Logs API.
 */

interface EncryptedField {
	type: 'encrypted';
	key: string;
	iv: string;
	data: string;
}

type FieldValue = EncryptedField | unknown;

interface LogEntry {
	// Encrypted fields
	Metadata?: FieldValue;
	RequestBody?: FieldValue;
	ResponseBody?: FieldValue;
	
	// Other fields from the log
	Endpoint?: string;
	Gateway?: string;
	service?: string;
	Cached?: string;
	Model?: string;
	host?: string;
	RateLimited?: string;
	StatusCode?: number;
	Provider?: string;
	[key: string]: unknown;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		try {
			// 1. Validate shared token authentication
			const authToken = request.headers.get('X-Logpush-Token');
			if (authToken !== env.LOGPUSH_TOKEN) {
				return new Response('unauthorized', { status: 401 });
			}

			// 2. Get Datadog API key from headers
			const ddApiKey = request.headers.get('DD-API-KEY');
			if (!ddApiKey) {
				return new Response('Missing DD-API-KEY header', { status: 400 });
			}

			// 3. Parse incoming JSON
			const encrypted: LogEntry = await request.json();

			// 4. Import RSA private key
			const pemHeader = '-----BEGIN PRIVATE KEY-----';
			const pemFooter = '-----END PRIVATE KEY-----';
			
			// Extract the base64 content between headers
			const keyContent = env.PRIVATE_KEY.trim();
			const startIndex = keyContent.indexOf(pemHeader) + pemHeader.length;
			const endIndex = keyContent.indexOf(pemFooter);
			
			if (startIndex === -1 || endIndex === -1) {
				throw new Error('Invalid PEM format');
			}
			
			const pemContents = keyContent
				.substring(startIndex, endIndex)
				.replace(/\s+/g, '');
			
			const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
			
			const rsaKey = await crypto.subtle.importKey(
				'pkcs8',
				binaryDer.buffer,
				{
					name: 'RSA-OAEP',
					hash: 'SHA-256',
				},
				false,
				['decrypt']
			);

			// Helper function to decode base64
			const base64Decode = (str: string): Uint8Array => {
				return Uint8Array.from(atob(str), c => c.charCodeAt(0));
			};

			// Helper function to decrypt a field
			async function decryptField(encObj: EncryptedField): Promise<unknown> {
				// Decrypt the AES key using RSA
				const aesKeyData = await crypto.subtle.decrypt(
					{ name: 'RSA-OAEP' },
					rsaKey,
					base64Decode(encObj.key)
				);

				// Import the AES key
				const aesKey = await crypto.subtle.importKey(
					'raw',
					aesKeyData,
					{ name: 'AES-GCM' },
					false,
					['decrypt']
				);

				// Decrypt the data using AES-GCM
				const decryptedData = await crypto.subtle.decrypt(
					{
						name: 'AES-GCM',
						iv: base64Decode(encObj.iv),
						tagLength: 128,
					},
					aesKey,
					base64Decode(encObj.data)
				);

				// Convert to string and parse JSON
				const plaintext = new TextDecoder().decode(decryptedData);
				return JSON.parse(plaintext);
			}

			// 5. Decrypt encrypted fields
			const decrypted: LogEntry = { ...encrypted };
			
			for (const field of ['Metadata', 'RequestBody', 'ResponseBody']) {
				if (encrypted[field]?.type === 'encrypted') {
					decrypted[field] = await decryptField(encrypted[field] as EncryptedField);
				}
			}

			// 6. Forward to Datadog
			const datadogPayload = [{
				ddsource: 'cloudflare',
				service: 'ai-gateway',
				host: 'ai-gateway-host',
				ddtags: 'env:prod,team:infra',
				...decrypted,
			}];

			// Use configurable endpoint with default to US1 region
			const ddEndpoint = env.DD_LOGS_ENDPOINT || 'https://http-intake.logs.datadoghq.com/api/v2/logs';
			
			const datadogResponse = await fetch(
				ddEndpoint,
				{
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'DD-API-KEY': ddApiKey,
					},
					body: JSON.stringify(datadogPayload),
				}
			);

			if (!datadogResponse.ok) {
				console.error('Datadog API error:', datadogResponse.status, await datadogResponse.text());
				return new Response('Failed to forward to Datadog', { status: 500 });
			}

			// Return 202 Accepted
			return new Response(null, { status: 202 });

		} catch (error) {
			console.error('Worker error:', error);
			return new Response('Internal server error', { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;
