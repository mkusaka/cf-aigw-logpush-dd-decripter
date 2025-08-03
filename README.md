# Cloudflare AI Gateway Logpush to Datadog Decrypter

Cloudflare Worker that decrypts AI Gateway logs and forwards them to Datadog.

## Overview

This Worker receives encrypted logs from Cloudflare AI Gateway via Logpush, decrypts the sensitive fields (Metadata, RequestBody, ResponseBody), and forwards the decrypted logs to Datadog Logs API.

## Architecture

```
Cloudflare AI Gateway → Logpush → Worker (decrypt) → Datadog Logs
```

## Prerequisites

- Cloudflare account with AI Gateway enabled
- Datadog account with Logs API access
- RSA key pair for encryption/decryption
- Node.js 18+ and pnpm

## Setup

### 1. Install dependencies

```bash
pnpm install
```

### 2. Configure secrets

```bash
# Set your shared authentication token
wrangler secret put LOGPUSH_TOKEN

# Set your RSA private key (paste the entire key including headers)
wrangler secret put PRIVATE_KEY
```

### 3. Configure AI Gateway

1. Generate RSA key pair:
```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

2. Upload `public_key.pem` to AI Gateway settings

3. Configure Logpush destination:
```
https://<YOUR-WORKER>.<SUBDOMAIN>.workers.dev/ingest?header_X-Logpush-Token=<LOGPUSH_TOKEN>&header_DD-API-KEY=<DATADOG_API_KEY>
```

### 4. Deploy

```bash
pnpm run deploy
```

## Development

```bash
# Start local development server
pnpm run dev

# Run tests
pnpm test

# Type check
pnpm run cf-typegen
```

## Configuration

### Environment Variables (Secrets)

- `LOGPUSH_TOKEN`: Shared secret for authenticating Logpush requests
- `PRIVATE_KEY`: RSA private key for decrypting log fields

### Headers

- `X-Logpush-Token`: Must match `LOGPUSH_TOKEN` secret
- `DD-API-KEY`: Datadog API key (passed through from Logpush URL)

### Datadog Configuration

The Worker sends logs to Datadog with the following attributes:
- `ddsource`: cloudflare
- `service`: ai-gateway  
- `host`: ai-gateway-host
- `ddtags`: env:prod,team:infra

Modify these in `src/index.ts` as needed.

## Testing

### Local Testing

```bash
# Test with sample encrypted payload
curl -X POST http://localhost:8787/ingest \
  -H "Content-Type: application/json" \
  -H "X-Logpush-Token: your-test-token" \
  -H "DD-API-KEY: your-datadog-api-key" \
  -d @test-payload.json
```

### Production Testing

```bash
# Test deployed Worker
curl -X POST https://your-worker.subdomain.workers.dev/ingest \
  -H "Content-Type: application/json" \
  -H "X-Logpush-Token: your-token" \
  -H "DD-API-KEY: your-datadog-api-key" \
  -d '{}'
```

## Security Considerations

- Always use HTTPS for the Worker endpoint
- Rotate `LOGPUSH_TOKEN` regularly
- Keep `PRIVATE_KEY` secure and never commit it
- Monitor for unauthorized access attempts
- Use Cloudflare Access or similar for additional protection if needed

## Troubleshooting

### Common Issues

1. **401 Unauthorized**: Check `X-Logpush-Token` header matches secret
2. **400 Bad Request**: Ensure `DD-API-KEY` header is present
3. **500 Internal Server Error**: Check Worker logs for decryption errors
4. **Datadog not receiving logs**: Verify API key and endpoint region

### Debug Mode

Enable debug logging by checking Worker logs in Cloudflare dashboard:
```
wrangler tail
```

## License

MIT