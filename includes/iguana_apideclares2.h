#ifdef WIN32
STRING_ARG(hash, sha224, message);
STRING_ARG(hash, sha256, message);
STRING_ARG(hash, sha384, message);
STRING_ARG(hash, sha512, message);
STRING_ARG(hash, rmd128, message);
STRING_ARG(hash, rmd160, message);
STRING_ARG(hash, rmd256, message);
STRING_ARG(hash, rmd320, message);
STRING_ARG(hash, sha1, message);
STRING_ARG(hash, md2, message);
STRING_ARG(hash, md4, message);
STRING_ARG(hash, md5, message);
STRING_ARG(hash, tiger192_3, message);
STRING_ARG(hash, whirlpool, message);

TWO_STRINGS(hmac, sha224, message, passphrase);
TWO_STRINGS(hmac, sha256, message, passphrase);
TWO_STRINGS(hmac, sha384, message, passphrase);
TWO_STRINGS(hmac, sha512, message, passphrase);
TWO_STRINGS(hmac, rmd128, message, passphrase);
TWO_STRINGS(hmac, rmd160, message, passphrase);
TWO_STRINGS(hmac, rmd256, message, passphrase);
TWO_STRINGS(hmac, rmd320, message, passphrase);
TWO_STRINGS(hmac, sha1, message, passphrase);
TWO_STRINGS(hmac, md2, message, passphrase);
TWO_STRINGS(hmac, md4, message, passphrase);
TWO_STRINGS(hmac, md5, message, passphrase);
TWO_STRINGS(hmac, tiger192_3, message, passphrase);
TWO_STRINGS(hmac, whirlpool, message, passphrase);
#endif