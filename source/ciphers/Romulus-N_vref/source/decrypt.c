/*
 * Date: 21 April 2021
 * Contact: Romulus Team (Mustafa Khairallah - mustafa.khairallah@ntu.edu.sg)
 * Romulus-N as compliant with the Romulus v1.3 specifications. 
 * This file icludes crypto_aead_decrypt()
 * It superseeds earlier versions developed by Mustafa Khairallah and maintained
 * by Mustafa Khairallah, Thomas Peyrin and Kazuhiko Minematsu
 */

#include "crypto_aead.h"
#include "api.h"
#include "variant.h"
#include "skinny.h"
#include "romulus_n.h"

int crypto_aead_decrypt(
unsigned char *m,size_t *mlen,
const unsigned char *c,size_t clen,
const unsigned char *ad,size_t adlen,
const unsigned char *npub,
const unsigned char *k
)
{

  return romulus_n_decrypt(m,mlen,c,clen,ad,adlen,npub,k);
  
}
