#ifndef GRAIN128AEAD_H
#define GRAIN128AEAD_H

#include <stddef.h>
#include <stdint.h>

#define STREAM_BYTES	16
#define MSG_BYTES		0

enum GRAIN_ROUND {INIT, ADDKEY, NORMAL};

typedef struct {
	uint8_t lfsr[128];
	uint8_t nfsr[128];
	uint8_t auth_acc[64];
	uint8_t auth_sr[64];
} grain_state;

typedef struct {
	uint8_t *message;
	size_t msg_len;
} grain_data;

void init_grain(grain_state *grain, const uint8_t *key, const uint8_t *iv);
uint8_t next_lfsr_fb(grain_state *grain);
uint8_t next_nfsr_fb(grain_state *grain);
uint8_t next_h(grain_state *grain);
uint8_t shift(uint8_t fsr[128], uint8_t fb);
void auth_shift(uint8_t sr[32], uint8_t fb);
uint8_t next_z(grain_state *grain, uint8_t, uint8_t);
void generate_keystream(grain_state *grain, grain_data *data, uint8_t *);
int encode_der(size_t, uint8_t **);

#endif
