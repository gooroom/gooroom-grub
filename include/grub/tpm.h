/* Begin TCG extension */

/* Common header file for i386-pc and EFI */

/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2014,2015  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_CPU_TPM_H
#define GRUB_CPU_TPM_H

#include <grub/types.h>

#ifndef TPM_BOOLEAN
typedef enum { false = 0, true = 1 } BOOLEAN;
#define TPM_BOOLEAN
#endif

/************************* constants *************************/

#define SHA1_DIGEST_SIZE 20

/* Measure into following PCRs */
#define TPM_LOADER_MEASUREMENT_PCR 9
#define TPM_COMMAND_MEASUREMENT_PCR 8
#define TPM_LUKS_HEADER_MEASUREMENT_PCR 11
#define TPM_GRUB2_LOADED_FILES_MEASUREMENT_PCR 12

/************************* macros *************************/

#ifdef TGRUB_DEBUG
//	#define DEBUG_PRINT(_x_)	grub_printf(_x_)
	#define DEBUG_PRINT(...)
#else
	#define DEBUG_PRINT(...)
#endif

/************************* functions *************************/

/* print SHA1 hash of input */
void EXPORT_FUNC(print_sha1) ( grub_uint8_t* inDigest );

/*  Measure string */
void EXPORT_FUNC(grub_TPM_measure_string) ( const char* string );
/*  Measure file */
void EXPORT_FUNC(grub_TPM_measure_file) ( const char* filename, const grub_uint8_t index );
/* 	Measure buffer */
void EXPORT_FUNC(grub_TPM_measure_buffer) ( const void* buffer, const grub_uint32_t bufferLen, const grub_uint8_t index );

void EXPORT_FUNC(grub_TPM_readpcr) ( const grub_uint8_t index, grub_uint8_t* result );

void grub_TPM_unseal( const grub_uint8_t* sealedBuffer, const grub_size_t inputSize, grub_uint8_t** result, grub_size_t* resultSize );

#endif

/* End TCG Extension */
