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

interface RequestBodyData {
	model?: string;
	temperature?: number;
	metadata?: {
		user_id?: string;
		[key: string]: unknown;
	};
	max_tokens?: number;
	thinking?: {
		budget_tokens?: number;
		type?: string;
	};
	stream?: boolean;
	[key: string]: unknown;
}

interface ResponseBodyData {
	id?: string;
	type?: string;
	role?: string;
	model?: string;
	content?: string;
	stop_reason?: string | null;
	stop_sequence?: string | null;
	usage?: {
		input_tokens?: number;
		cache_creation_input_tokens?: number;
		cache_read_input_tokens?: number;
		output_tokens?: number;
		service_tier?: string;
		[key: string]: unknown;
	};
	[key: string]: unknown;
}

type FieldValue = EncryptedField | RequestBodyData | ResponseBodyData | unknown;

interface LogEntry {
	// Encrypted fields
	Metadata?: FieldValue;
	RequestBody?: FieldValue;
	ResponseBody?: FieldValue;
	
	// Fields actually provided by AI Gateway Logpush
	Endpoint?: string;
	Gateway?: string;
	service?: string;
	Cached?: boolean | string;
	Model?: string;
	host?: string;
	RateLimited?: boolean | string;
	StatusCode?: number;
	Provider?: string;
	
	// Note: Performance fields like Duration, tokens_in, tokens_out are available
	// through AI Gateway API but NOT included in Logpush dataset
	
	[key: string]: unknown;
}

interface DatadogLogEntry {
	ddsource: string;
	service: string;
	host: string;
	ddtags: string;
	Cached?: boolean | string;
	Endpoint?: string;
	Gateway?: string;
	Metadata?: unknown;
	Model?: string;
	Provider?: string;
	RateLimited?: boolean | string;
	StatusCode?: number;
	RequestBody?: {
		model?: string;
		temperature?: number;
		metadata?: {
			user_id?: string;
			[key: string]: unknown;
		};
		max_tokens?: number;
		thinking?: {
			budget_tokens?: number;
			type?: string;
		};
		stream?: boolean;
	};
	ResponseBody?: {
		id?: string;
		type?: string;
		role?: string;
		model?: string;
		content?: string;
		stop_reason?: string | null;
		stop_sequence?: string | null;
		usage?: {
			input_tokens?: number;
			cache_creation_input_tokens?: number;
			cache_read_input_tokens?: number;
			output_tokens?: number;
			service_tier?: string;
			[key: string]: unknown;
		};
	};
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		// Generate request ID for tracking
		const requestId = crypto.randomUUID();
		const requestTimestamp = new Date().toISOString();
		
		try {
			// Accept any path for flexibility with Logpush configuration
			const url = new URL(request.url);
			if (!url.pathname.startsWith('/')) {
				return new Response('not found', { status: 404 });
			}
			// Helper function for constant time string comparison
			const timingSafeEqual = (a: string, b: string): boolean => {
				try {
					const encoder = new TextEncoder();
					const aBytes = encoder.encode(a);
					const bBytes = encoder.encode(b);
					
					// Note: This will throw if lengths differ, but catching the error
					// might still leak timing information. For maximum security,
					// ensure tokens are always the same length.
					return crypto.subtle.timingSafeEqual(aBytes, bBytes);
				} catch {
					// Length mismatch or other error
					return false;
				}
			};

			// 1. Validate shared token authentication
			const authToken = request.headers.get('X-Logpush-Token');
			
			if (!authToken) {
				console.error('Authentication failed: No auth token provided');
				return new Response('unauthorized', { status: 401 });
			}
			
			if (!env.LOGPUSH_TOKEN) {
				console.error('Authentication failed: LOGPUSH_TOKEN not configured');
				return new Response('unauthorized', { status: 401 });
			}
			
			if (!timingSafeEqual(authToken, env.LOGPUSH_TOKEN)) {
				console.error('Authentication failed: Token mismatch');
				return new Response('unauthorized', { status: 401 });
			}

			// 2. Use Datadog API key from environment

			// 3. Parse incoming JSON (handle gzip if needed)
			let bodyText: string;
			const contentEncoding = request.headers.get('content-encoding');
			
			if (contentEncoding === 'gzip') {
				const gzippedBody = await request.arrayBuffer();
				const decompressedStream = new DecompressionStream('gzip');
				const writer = decompressedStream.writable.getWriter();
				writer.write(new Uint8Array(gzippedBody));
				writer.close();
				
				const decompressedBody = await new Response(decompressedStream.readable).arrayBuffer();
				bodyText = new TextDecoder().decode(decompressedBody);
			} else {
				bodyText = await request.text();
			}
			
			// Parse NDJSON (newline-delimited JSON) - Logpush sends multiple entries
			const lines = bodyText.trim().split('\n');
			
			const logEntries: LogEntry[] = [];
			for (const line of lines) {
				if (line.trim()) {
					try {
						const entry = JSON.parse(line);
						logEntries.push(entry);
					} catch (e) {
						console.error('Failed to parse line:', e);
					}
				}
			}

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

				// Convert to string
				const plaintext = new TextDecoder().decode(decryptedData);
				
				// Try to parse as JSON, but return as string if it fails
				try {
					return JSON.parse(plaintext);
				} catch (jsonError) {
					// If not JSON, return as plain string
					console.log('Decrypted data is not JSON, returning as string:', {
						preview: plaintext.substring(0, 100),
						length: plaintext.length,
						error: jsonError instanceof Error ? jsonError.message : String(jsonError)
					});
					return plaintext;
				}
			}

			// 5. Decrypt encrypted fields for all entries
			const decryptedEntries: LogEntry[] = [];
			const datadogEntries: DatadogLogEntry[] = [];
			const decryptionErrors: any[] = [];
			
			let entryIndex = 0;
			for (const encrypted of logEntries) {
				const decrypted: LogEntry = { ...encrypted };
				const logContext = {
					requestId,
					entryIndex,
					logId: encrypted.logId || 'unknown',
					timestamp: encrypted.timestamp || requestTimestamp,
				};
				
				// Decrypt Metadata if encrypted
				if (encrypted.Metadata && typeof encrypted.Metadata === 'object' && 'type' in encrypted.Metadata && encrypted.Metadata.type === 'encrypted') {
					try {
						decrypted.Metadata = await decryptField(encrypted.Metadata as EncryptedField);
					} catch (e) {
						const errorInfo = {
							field: 'Metadata',
							error: e instanceof Error ? e.message : String(e),
							context: logContext,
							encryptedData: encrypted.Metadata
						};
						console.error(`[${requestId}] Failed to decrypt Metadata:`, errorInfo);
						decryptionErrors.push(errorInfo);
					}
				}
				
				// Decrypt RequestBody if encrypted
				if (encrypted.RequestBody && typeof encrypted.RequestBody === 'object' && 'type' in encrypted.RequestBody && encrypted.RequestBody.type === 'encrypted') {
					try {
						decrypted.RequestBody = await decryptField(encrypted.RequestBody as EncryptedField);
					} catch (e) {
						const errorInfo = {
							field: 'RequestBody',
							error: e instanceof Error ? e.message : String(e),
							context: logContext,
							encryptedData: encrypted.RequestBody
						};
						console.error(`[${requestId}] Failed to decrypt RequestBody:`, errorInfo);
						decryptionErrors.push(errorInfo);
					}
				}
				
				// Decrypt ResponseBody if encrypted
				if (encrypted.ResponseBody && typeof encrypted.ResponseBody === 'object' && 'type' in encrypted.ResponseBody && encrypted.ResponseBody.type === 'encrypted') {
					try {
						decrypted.ResponseBody = await decryptField(encrypted.ResponseBody as EncryptedField);
					} catch (e) {
						const errorInfo = {
							field: 'ResponseBody',
							error: e instanceof Error ? e.message : String(e),
							context: logContext,
							encryptedData: encrypted.ResponseBody
						};
						console.error(`[${requestId}] Failed to decrypt ResponseBody:`, errorInfo);
						decryptionErrors.push(errorInfo);
					}
				}
				
				entryIndex++;
				
				// Store full decrypted entry for R2
				decryptedEntries.push({
					ddsource: 'cloudflare',
					service: 'ai-gateway',
					host: 'ai-gateway-host',
					ddtags: 'env:prod,team:infra',
					...decrypted,
				});
				
				// Create filtered entry for Datadog
				const datadogEntry: DatadogLogEntry = {
					ddsource: 'cloudflare',
					service: 'ai-gateway',
					host: 'ai-gateway-host',
					ddtags: 'env:prod,team:infra',
					Cached: decrypted.Cached,
					Endpoint: decrypted.Endpoint,
					Gateway: decrypted.Gateway,
					Metadata: decrypted.Metadata,
					Model: decrypted.Model,
					Provider: decrypted.Provider,
					RateLimited: decrypted.RateLimited,
					StatusCode: decrypted.StatusCode,
				};
				
				// Filter RequestBody fields
				if (decrypted.RequestBody && typeof decrypted.RequestBody === 'object' && 
					!('type' in decrypted.RequestBody && decrypted.RequestBody.type === 'encrypted')) {
					const requestBody = decrypted.RequestBody as RequestBodyData;
					datadogEntry.RequestBody = {
						model: requestBody.model,
						temperature: requestBody.temperature,
						metadata: requestBody.metadata,
						max_tokens: requestBody.max_tokens,
						thinking: requestBody.thinking,
						stream: requestBody.stream,
					};
				}
				
				// Filter ResponseBody fields
				if (decrypted.ResponseBody && typeof decrypted.ResponseBody === 'object' && 
					!('type' in decrypted.ResponseBody && decrypted.ResponseBody.type === 'encrypted')) {
					const responseBody = decrypted.ResponseBody as ResponseBodyData;
					datadogEntry.ResponseBody = {
						id: responseBody.id,
						type: responseBody.type,
						role: responseBody.role,
						model: responseBody.model,
						content: responseBody.content,
						stop_reason: responseBody.stop_reason,
						stop_sequence: responseBody.stop_sequence,
						usage: responseBody.usage,
					};
				}
				
				datadogEntries.push(datadogEntry);
			}

			// 6. Store logs in R2
			try {
				const now = new Date();
				const dateStr = now.toISOString().split('T')[0]; // YYYY-MM-DD
				const timestamp = now.toISOString().replace(/[:.]/g, '-'); // Replace : and . for filename
				const key = `${dateStr}/${timestamp}_${crypto.randomUUID()}.json`;
				
				const logData = {
					timestamp: now.toISOString(),
					request_id: requestId,
					encrypted_entries: logEntries,
					decrypted_entries: decryptedEntries,
					decryption_errors: decryptionErrors,
					metadata: {
						entry_count: logEntries.length,
						decrypted_count: decryptedEntries.length,
						error_count: decryptionErrors.length,
						source_ip: request.headers.get('cf-connecting-ip'),
						content_encoding: request.headers.get('content-encoding'),
						user_agent: request.headers.get('user-agent'),
						cf_ray: request.headers.get('cf-ray'),
					}
				};
				
				await env.LOG_BUCKET.put(key, JSON.stringify(logData, null, 2), {
					httpMetadata: {
						contentType: 'application/json',
					},
					customMetadata: {
						'log-type': 'ai-gateway',
						'processed-at': now.toISOString(),
					}
				});
			} catch (r2Error) {
				console.error(`[${requestId}] Failed to store logs in R2:`, r2Error);
				// Continue processing even if R2 storage fails
			}

			// 7. Forward to Datadog
			const datadogPayload = datadogEntries;

			// Use configurable endpoint with default to US1 region
			const ddEndpoint = env.DD_LOGS_ENDPOINT || 'https://http-intake.logs.datadoghq.com/api/v2/logs';
			
			const datadogResponse = await fetch(
				ddEndpoint,
				{
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'DD-API-KEY': env.DD_API_KEY,
					},
					body: JSON.stringify(datadogPayload),
				}
			);

			if (!datadogResponse.ok) {
				console.error(`[${requestId}] Datadog API error:`, datadogResponse.status, await datadogResponse.text());
				return new Response('Failed to forward to Datadog', { status: 500 });
			}

			// Return 202 Accepted
			return new Response(null, { status: 202 });

		} catch (error) {
			console.error(`[${requestId}] Worker error:`, error);
			return new Response('Internal server error', { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;
