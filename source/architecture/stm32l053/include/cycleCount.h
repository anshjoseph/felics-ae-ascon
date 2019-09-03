#include <stdint.h>

#ifndef __CYCLE_COUNT_H__
#define __CYCLE_COUNT_H__

extern uint32_t __cycleCountStart;
extern uint32_t __cycleCountStop;

#define CYCLE_COUNT_START \
	SysTick->VAL = 0x00000000; \
	__asm__("nop"); \
	__cycleCountStart = SysTick->VAL

#define CYCLE_COUNT_STOP \
	__cycleCountStop =  SysTick->VAL

#define CYCLE_COUNT_ELAPSED (__cycleCountStart - __cycleCountStop - 19)

#define CYCLE_COUNT_INIT \
	SysTick->LOAD = 0x00ffffff; \
    SysTick->VAL = 0; \
    SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk; \
	asm("nop"); \
    __cycleCountStart = 0; \
    __cycleCountStop = 0;


#endif /* __CYCLE_COUNT_H__ */