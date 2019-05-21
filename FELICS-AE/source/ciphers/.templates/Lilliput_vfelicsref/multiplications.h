#ifndef MULTIPLICATIONS_H
#define MULTIPLICATIONS_H

#include <stdint.h>

#include "parameters.h"

static void _multiply_M(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    y[7] = x[6];
    y[6] = x[5];
    y[5] = x[5]<<3 ^ x[4];
    y[4] = x[4]>>3 ^ x[3];
    y[3] = x[2];
    y[2] = x[6]<<2 ^ x[1];
    y[1] = x[0];
    y[0] = x[7];
}

static void _multiply_M2(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t x_M_5 = x[5]<<3 ^ x[4];
    uint8_t x_M_4 = x[4]>>3 ^ x[3];

    y[7] = x[5];
    y[6] = x_M_5;
    y[5] = x_M_5<<3 ^ x_M_4;
    y[4] = x_M_4>>3 ^ x[2];
    y[3] = x[6]<<2  ^ x[1];
    y[2] = x[5]<<2  ^ x[0];
    y[1] = x[7];
    y[0] = x[6];
}

static void _multiply_M3(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t x_M_5  = x[5]<<3  ^ x[4];
    uint8_t x_M_4  = x[4]>>3  ^ x[3];
    uint8_t x_M2_5 = x_M_5<<3 ^ x_M_4;
    uint8_t x_M2_4 = x_M_4>>3 ^ x[2];

    y[7] = x_M_5;
    y[6] = x_M2_5;
    y[5] = x_M2_5<<3 ^ x_M2_4;
    y[4] = x_M2_4>>3 ^ x[6]<<2 ^ x[1];
    y[3] = x[5]<<2   ^ x[0];
    y[2] = x_M_5<<2  ^ x[7];
    y[1] = x[6];
    y[0] = x[5];
}

static void _multiply_MR(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    y[0] = x[1];
    y[1] = x[2];
    y[2] = x[3]    ^ x[4]>>3;
    y[3] = x[4];
    y[4] = x[5]    ^ x[6]<<3;
    y[5] = x[3]<<2 ^ x[6];
    y[6] = x[7];
    y[7] = x[0];
}

static void _multiply_MR2(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t x_MR_4 = x[5] ^ x[6]<<3;

    y[0] = x[2];
    y[1] = x[3]    ^ x[4]>>3;
    y[2] = x[4]    ^ x_MR_4>>3;
    y[3] = x_MR_4;
    y[4] = x[3]<<2 ^ x[6]      ^ x[7]<<3;
    y[5] = x[4]<<2 ^ x[7];
    y[6] = x[0];
    y[7] = x[1];
}

static void _multiply_MR3(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t x_MR_4  = x[5]    ^ x[6]<<3;
    uint8_t x_MR2_4 = x[3]<<2 ^ x[6]    ^ x[7]<<3;

    y[0] = x[3]      ^ x[4]>>3;
    y[1] = x[4]      ^ x_MR_4>>3;
    y[2] = x_MR_4    ^ x_MR2_4>>3;
    y[3] = x_MR2_4;
    y[4] = x[0]<<3   ^ x[4]<<2   ^ x[7];
    y[5] = x_MR_4<<2 ^ x[0];
    y[6] = x[1];
    y[7] = x[2];
}

#endif /* MULTIPLICATIONS_H */
