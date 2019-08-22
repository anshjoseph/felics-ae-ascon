/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include "cipher.h"


#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE


#if defined(PC)
/* Definitions for PC, common to all scenarios. */

#if (SCENARIO == SCENARIO_0)
/* Definitions for PC, during the vector-checking step. */

#elif (SCENARIO == SCENARIO_1)
/* Definitions for PC, during the benchmark step. */

#endif  /* SCENARIO */
#endif /* PC */


#if defined(ARM)
/* Definitions for ARM, common to all scenarios. */

#if (SCENARIO == SCENARIO_0)
/* Definitions for ARM, during the vector-checking step. */

#elif (SCENARIO == SCENARIO_1)
/* Definitions for ARM, during the benchmark step. */

#endif  /* SCENARIO */
#endif /* ARM */


#if defined(MSP)
/* Definitions for MSP, common to all scenarios. */

#if (SCENARIO == SCENARIO_0)
/* Definitions for MSP, during the vector-checking step. */

#elif (SCENARIO == SCENARIO_1)
/* Definitions for MSP, during the benchmark step. */

#endif  /* SCENARIO */
#endif /* MSP */


#if defined(AVR)
/* Definitions for AVR, common to all scenarios. */

#if (SCENARIO == SCENARIO_0)
/* Definitions for AVR, during the vector-checking step. */

#elif (SCENARIO == SCENARIO_1)
/* Definitions for AVR, during the benchmark step. */

#endif  /* SCENARIO */
#endif /* AVR */



#endif /* DATA_TYPES_H */
