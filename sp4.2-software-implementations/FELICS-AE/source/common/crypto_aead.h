#ifndef CRYPTO_AEAD_H
#define CRYPTO_AEAD_H

#include <stddef.h>
#include <stdint.h>

int crypto_aead_encrypt(
	uint8_t *c, size_t *clen,
	const uint8_t *m, size_t mlen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
);

int crypto_aead_decrypt(
	uint8_t *m, size_t *mlen,
	const uint8_t *c, size_t clen,
	const uint8_t *ad, size_t adlen,
	const uint8_t *npub,
	const uint8_t *k
);

#endif /* CRYPTO_AEAD_H */
