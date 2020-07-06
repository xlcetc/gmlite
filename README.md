# gmlite
gmlite is a standalone C library that implements chinese SM2, SM3, SM4 and SM9 standard. However, it's big number and elliptic curve code are taken from [GmSSL](https://github.com/guanzhi/GmSSL) :). SSL's crypto library is very general and efficient, but it's also very complicated, while I did some simplification and optimization for SM2, SM3 and SM9, gmlite is still not lite at all. I don't like it.

# Diffrence
Something that differs from [GmSSL](https://github.com/guanzhi/GmSSL).

* SM3 avx2 implementation.
* BN curve bilinear pairing implementation.
* SM2, SM4, SM9 test with random input data(key, msg, id, etc).
* Constant-time PKCS7 padding.
* Use system provided RNG.
* Lehmer exgcd algorithm.
* CMake build system.
* gmlite does not support 32 bit OS, I screw it up :).
* ...