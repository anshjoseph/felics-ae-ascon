int romulus_n_encrypt (
			 unsigned char* c, size_t* clen,
			 const unsigned char* m, size_t mlen,
			 const unsigned char* ad, size_t adlen,
			 const unsigned char* npub,
			 const unsigned char* k
		       );

int romulus_n_decrypt(
unsigned char *m,size_t *mlen,
const unsigned char *c,size_t clen,
const unsigned char *ad,size_t adlen,
const unsigned char *npub,
const unsigned char *k
		      );
