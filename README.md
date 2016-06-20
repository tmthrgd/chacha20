# chacha20

[![GoDoc](https://godoc.org/github.com/tmthrgd/chacha20?status.svg)](https://godoc.org/github.com/tmthrgd/chacha20)
[![Build Status](https://travis-ci.org/tmthrgd/chacha20.svg?branch=master)](https://travis-ci.org/tmthrgd/chacha20)

An AVX/AVX2/pure-Go implementation of the ChaCha20 stream cipher for Golang.

The AVX and AVX2 ChaCha20 implementations were taken from
[cloudflare/sslconfig](https://github.com/cloudflare/sslconfig/blob/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102g.patch).

The pure Go ChaCha20 implementation was taken from [codahale/chacha20](https://github.com/codahale/chacha20).

## Benchmark

```
BenchmarkChaCha20Codahale-8	     200	   5951390 ns/op	 176.19 MB/s	[codahale/chacha20]
BenchmarkChaCha20Go-8      	     300	   5638541 ns/op	 185.97 MB/s	[tmthrgd/chacha20/internal/ref]
BenchmarkChaCha20-8        	    2000	    730687 ns/op	1435.05 MB/s	[tmthrgd/chacha20 - AVX only]
BenchmarkAESCTR-8          	     500	   2600296 ns/op	 403.25 MB/s	[crypto/aes crypto/cipher]
BenchmarkAESGCM-8          	    2000	    864448 ns/op	1213.00 MB/s	[crypto/aes crypto/cipher]
BenchmarkRC4-8             	    1000	   1332092 ns/op	 787.16 MB/s	[crypto/rc4]
```

## License

Unless otherwise noted, the chacha20 source files are distributed under the Modified BSD License found in the LICENSE file.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)
