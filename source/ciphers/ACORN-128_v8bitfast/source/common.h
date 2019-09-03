#ifndef COMMON_H
#define COMMON_H

#define maj(x,y,z)   ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))  )
#define ch(x,y,z)    ( ((x) & (y)) ^ ((~x) & (z)) )

#endif /* COMMON_H */
