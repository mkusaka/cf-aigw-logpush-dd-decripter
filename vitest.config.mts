import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

// Test RSA key pair for testing purposes only
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

export default defineWorkersConfig({
	test: {
		poolOptions: {
			workers: {
				wrangler: { configPath: './wrangler.jsonc' },
				miniflare: {
					bindings: {
						LOGPUSH_TOKEN: 'test-token-12345',
						PRIVATE_KEY: TEST_PRIVATE_KEY,
						DD_API_KEY: 'test-dd-api-key',
					},
				},
			},
		},
	},
});
