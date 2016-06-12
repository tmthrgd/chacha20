# chacha20

[![GoDoc](https://godoc.org/github.com/tmthrgd/chacha20?status.svg)](https://godoc.org/github.com/tmthrgd/chacha20)
[![Build Status](https://travis-ci.org/tmthrgd/chacha20.svg?branch=master)](https://travis-ci.org/tmthrgd/chacha20)

An AVX and AVX2 implementation of the ChaCha20 stream cipher for Golang.

For systems with neither AVX nor AVX2, it falls back to
[codahale/chacha20](https://github.com/codahale/chacha20) - a pure Golang implementation.

The ChaCha20 implementation was taken from
[cloudflare/sslconfig](https://github.com/cloudflare/sslconfig/blob/master/patches/openssl__chacha20_poly1305_cf.patch).

## Benchmark

```
BenchmarkChaCha20Go-8	     300	   5845269 ns/op	 179.39 MB/s	[codahale/chacha20]
BenchmarkChaCha20-8  	    2000	    734242 ns/op	1428.11 MB/s	[tmthrgd/chacha20 - AVX only]
BenchmarkAESCTR-8    	     500	   2591008 ns/op	 404.70 MB/s	[crypto/aes crypto/cipher]
BenchmarkAESGCM-8    	     500	   2363450 ns/op	 443.66 MB/s	[crypto/aes crypto/cipher]
BenchmarkRC4-8       	    1000	   1335411 ns/op	 785.21 MB/s	[crypto/rc4]
```

## License

Unless otherwise noted, the ip-blocker-agent source files are distributed under the Modified BSD License
found in the LICENSE file.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)
