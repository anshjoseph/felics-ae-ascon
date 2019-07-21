# Setup STM32L053 for FELICS-AE

## Build `libstm32l053.a`

If you need to rebuild `libstm32l053.a`, follow these instructions :  

1. Download and install STM32CubeMX available [here](https://www.st.com/en/development-tools/stm32cubemx.html) and open it.
2. Under the `New project` section select `Access to board selector` and type `NUCLEO-L053R8` in the search bar. Only one board should be listed, double click on it. CubeMX will ask if you want to "Initialize all peripherals with their default mode", answer "yes" to this question.
3. You will now see a window with the MCU and a graphical pinout configuration.   
Click on pin `PC13` and select `Reset_State`. Do the same for pin `PA5`. This will disable green LED and blue push button.
4. Go to the `Project Manager` top tab and setup project informations (name, location, ...). Set `Application Structure` to `Advanced` and `Toolchain/IDE` to `Makefile`.
5. Click on the `Code Generator` left tab. Under the `STM32Cube Firmware Library Package` section select `Copy only the necessary library files`. Under the `Generated files` section check `Generate peripheral initialization as pair of '.c/.h' file per peripheral`.
6. Click on the top right `GENERATE CODE` button. It will generate all source files and propose to open the folder.
7. Problem with Makefile projects is that it is missing a mandatory file for `printf` redirect. So you need to restart the whole process but instead of `Makefile` under `Toolchain/IDE` you need to select `SW4STM32` and choose an other name for the project. You can now click `GENERATE CODE`, open folder and got to `Core/Src` and copy the file `syscalls.c` to the previously generated Makefile project under `Core/Src`. You can delete the project generated for `SW4STM32`.    

The project is now generated with all necessary files but we need to modify them :
1. Open `main.h` and move these lines to `usart.h` :
```
#include "stm32l0xx_hal.h"

#define USART_TX_Pin GPIO_PIN_2
#define USART_TX_GPIO_Port GPIOA
#define USART_RX_Pin GPIO_PIN_3
#define USART_RX_GPIO_Port GPIOA
```
2. Create new files `error_handler.c/.h`, add includes guards to `.h` file and move the function declaration `void Error_Handler(void)` from `main.h` to `error_handler.h`. You can now delete `main.h`.
3. In `error_handler.c`, include `error_handler.h` and add an empty definition of `Error_Handler()` :   
```
void Error_Handler(void) {}
```
4. In `usart.h` add this function declaration :   
```
void __io_putchar(uint8_t ch);
```

5. In `usart.c` add these includes :
```
#include "error_handler.h"
#include <stdio.h>
#include <stdint.h>
```
Add this function definition :
```
void __io_putchar(uint8_t ch) {
  HAL_UART_Transmit(&huart2, &ch, 1, 1);
} 
```
And add this line before the end of the function `void MX_USART2_UART_Init(void)` :
```
setbuf(stdout, NULL);
```
6. Create files `system_clock.c/.h`, add includes guard to `.h` file and add also this function declaration :
```
void SystemClock_Config(void);
```
In `system_clock.c` add these includes :
```
#include "stm32l0xx_hal.h"
#include "system_clock.h"
#include "error_handler.h"
```
And move the function definition `void SystemClock_Config(void){...}` from `main.c` to `system_clock.c`.   

7. Create `cycleCount.c` and fill it with :
```
#include <stdint.h>

uint32_t __cycleCountStart;
uint32_t __cycleCountStop;
```
For tests you will need to copy `cycleCount.h` from `FELICS-AE/source/architecture/stm32l053/include` to the `Inc` directory.

8. To check that the lib is working, open `main.c` and add these includes :
```
#include "error_handler.h"
#include "system_clock.h"
#include "cycleCount.h"
```
And in the `main(void)` function, after calls to all init function add :
```
  CYCLE_COUNT_INIT;
  printf("Start\r\n");
  while (1)
  {
    CYCLE_COUNT_START;
    for(int i=0; i<1000; i++);
    CYCLE_COUNT_STOP;
    printf("t = %d\r\n",CYCLE_COUNT_ELAPSED);
  }
```

9. Now we need to add newly created `.c` files to the `Makefile`.
Open `Makefile` and add to `C_SOURCES` variable :
```
C_SOURCES =  \
Core/Src/main.c \
Core/Src/gpio.c \
Core/Src/usart.c \
Core/Src/system_clock.c \
Core/Src/error_handler.c \
Core/Src/cycleCount.c \
Core/Src/syscalls.c \
...
```
Change optimization level to O3 : `OPT = -O3`

10. We can now run `make` to compile all source files. If there's no error, you can go to `build` directory, then move `main.o` with `mv main.o ..` and then run :
```
arm-none-eabi-ar rcs ../libstm32l053.a *.o
```
We can now link `main.o` with `libstm32l053.a` and create the final bin file :
```
cd ..
arm-none-eabi-gcc main.o -mcpu=cortex-m0plus -mthumb   -specs=nano.specs -TSTM32L053R8Tx_FLASH.ld -Wl,--whole-archive libstm32l053.a -Wl,--no-whole-archive -Wl,--gc-sections -o test.elf
```
Then convert to `hex` and flash with `st-flash` tool :
```
arm-none-eabi-objcopy -O ihex test.elf test.hex
st-flash --format ihex write test.hex
```
Then open your serial terminal tool and reset the board with reset button, you should see outputs like this :
```
Start
test
t = 4219
test
t = 4219
test
t = 4219
test
t = 4219
test
t = 4219
```
If this works, you can now use `libstm32l053.a` for architecture `STM32L053` in FELICS-AE.