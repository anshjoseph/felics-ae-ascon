#ifndef UTILS_H
#define UTILS_H

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))

void permutation(uint8_t* S, int start, int rounds);

#endif /* UTILS_H */
