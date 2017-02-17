/* Begin TCG Extension */

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

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/sha1.h>
#include <grub/misc.h>

#include <grub/tpm.h>
#include <grub/efi/tpm.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>

// should not be used
//#include <grub/i386/pc/memory.h>
//#include <grub/i386/pc/int.h>

#ifdef TGRUB_DEBUG
	#include <grub/time.h>
#endif

/************************* constants *************************/

/* Ordinals */
static const grub_uint32_t TPM_ORD_PcrRead = 0x00000015;

/************************* struct typedefs *************************/

/* TCG_HashLogExtendEvent Input Parameter Block (Format 2) */
typedef struct {
 	grub_uint16_t ipbLength;
 	grub_uint16_t reserved;
 	grub_uint32_t hashDataPtr;
 	grub_uint32_t hashDataLen;
 	grub_uint32_t pcrIndex;
 	grub_uint32_t reserved2;
 	grub_uint32_t logDataPtr;
 	grub_uint32_t logDataLen;
 } GRUB_PACKED EventIncoming;

/* TCG_HashLogExtendEvent Output Parameter Block */
typedef struct {
 	grub_uint16_t opbLength;
 	grub_uint16_t reserved;
 	grub_uint32_t eventNum;
 	grub_uint8_t  hashValue[SHA1_DIGEST_SIZE];
} GRUB_PACKED EventOutgoing;

typedef struct {
	grub_uint32_t pcrIndex;
	grub_uint32_t eventType;
	grub_uint8_t digest[SHA1_DIGEST_SIZE];
	grub_uint32_t eventDataSize;
	grub_uint8_t event[0];
} GRUB_PACKED Event;

/* TPM_PCRRead Incoming Operand */
typedef struct {
	grub_uint16_t tag;
	grub_uint32_t paramSize;
	grub_uint32_t ordinal;
	grub_uint32_t pcrIndex;
} GRUB_PACKED PCRReadIncoming;

/* TPM_PCRRead Outgoing Operand */
typedef struct {
	grub_uint16_t tag;
	grub_uint32_t paramSize;
	grub_uint32_t returnCode;
	grub_uint8_t pcr_value[SHA1_DIGEST_SIZE];
} GRUB_PACKED PCRReadOutgoing;

/************************* static functions *************************/

/* Invokes TCG_HashLogExtendEvent
 *
 * we hash ourself
 *
 *  grub_fatal() on error
 *  Page 116 TCG_PCClientImplementation_1-21_1_00
 */

/*modified to use in efi*/

//THIS IS GLOBAL VAR FOR EFI
static grub_efi_guid_t tpm_guid = EFI_TPM_GUID;
BOOLEAN tpm_present(efi_tpm_protocol_t *tpm)
{

	grub_efi_status_t status;
	TCG_EFI_BOOT_SERVICE_CAPABILITY caps;
	grub_uint32_t flags;
	grub_addr_t eventlog, lastevent;

	if (tpm == NULL) {
//		grub_fatal ( "grub_TPM not present._TPM_PRESENT");
		return false;
	}

	caps.Size = (grub_uint8_t)sizeof(caps);
	status = efi_call_5 (tpm->status_check, tpm, &caps, &flags,
							   &eventlog, &lastevent);

	if (status != EFI_SUCCESS || caps.TPMDeactivatedFlag
		|| !caps.TPMPresentFlag)
			return false;

	return true;
}

grub_efi_status_t
grub_TPM_efi_hashLogExtendEvent(efi_tpm_protocol_t* tpm, const grub_uint8_t* inDigest, grub_uint8_t pcrIndex, const char* descriptions )
{
	//grub_printf(" grub_TPM_efi_hashLogExtendEvent \n");
	grub_efi_status_t status;

	grub_uint32_t algorithm, eventnum = 0;
	grub_addr_t lastevent;
	Event* event;
	
	// Prepare Event struct
	grub_uint32_t strSize = grub_strlen(descriptions);
	grub_uint32_t eventStructSize = strSize + sizeof(Event);
	event = grub_zalloc(eventStructSize);

	if (!event)
	{
		grub_fatal( "grub_TPM_efi_hashLogExtendEvent: memory allocation failed" );
	}

	event->pcrIndex = pcrIndex;
	event->eventType = 0x0d; // EV_IPL
	event->eventDataSize = strSize + 1;
	algorithm = 0x00000004;

	status = efi_call_7(tpm->log_extend_event, tpm, inDigest,
                                           (grub_uint64_t)eventStructSize, algorithm, event,
                                           &eventnum, &lastevent);

	switch (status) {
		case GRUB_EFI_SUCCESS:
//			grub_printf("EFI SUCCESS \n");
			return EFI_SUCCESS;
		case GRUB_EFI_DEVICE_ERROR:
			return grub_error (GRUB_ERR_IO, N_("Command failed"));
		case GRUB_EFI_INVALID_PARAMETER:
			return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
		case GRUB_EFI_BUFFER_TOO_SMALL:
			return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Output buffer too small"));
		case GRUB_EFI_NOT_FOUND:
			return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
		default:
			return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
	}
}
/************************* non-static functions *************************/

/* grub_fatal() on error */
void
grub_TPM_readpcr( const grub_uint8_t index, grub_uint8_t* result ) {

	CHECK_FOR_NULL_ARGUMENT( result )

	PassThroughToTPM_InputParamBlock *passThroughInput = NULL;
	PCRReadIncoming *pcrReadIncoming = NULL;
	PCRReadIncoming Incoming;
	grub_uint16_t inputlen = sizeof( *passThroughInput ) - sizeof( passThroughInput->TPMOperandIn ) + sizeof( *pcrReadIncoming );

	PassThroughToTPM_OutputParamBlock *passThroughOutput = NULL;
	PCRReadOutgoing* pcrReadOutgoing = NULL;
	grub_uint16_t outputlen = sizeof( *passThroughOutput ) - sizeof( passThroughOutput->TPMOperandOut ) + sizeof( *pcrReadOutgoing );

	passThroughInput = grub_zalloc( inputlen );
	if( !passThroughInput ) {
		grub_fatal( "readpcr: memory allocation failed" );
	}

	passThroughInput->IPBLength = inputlen;
	passThroughInput->OPBLength = outputlen;

	 pcrReadIncoming = (PCRReadIncoming *)&(passThroughInput->TPMOperandIn[0]);
	 Incoming.tag = TPM_TAG_RQU_COMMAND;
	 Incoming.paramSize = sizeof( *pcrReadIncoming );
	 Incoming.ordinal = TPM_ORD_PcrRead;
	 Incoming.pcrIndex = index;

	 pcrReadIncoming = &Incoming;
	 //CONVERT
	grub_uint32_t tmp = grub_swap_bytes16_compile_time( TPM_TAG_RQU_COMMAND );
	pcrReadIncoming->tag = tmp;
	tmp = grub_swap_bytes32( sizeof( *pcrReadIncoming ) );
	pcrReadIncoming->paramSize = tmp;
	tmp = grub_swap_bytes32_compile_time( TPM_ORD_PcrRead );
	pcrReadIncoming->ordinal = tmp;
	tmp = grub_swap_bytes32( (grub_uint32_t) index);
	pcrReadIncoming->pcrIndex = tmp;

	pcrReadIncoming = (PCRReadIncoming *)&(passThroughInput->TPMOperandIn[0]);
	grub_memcpy(pcrReadIncoming, &Incoming, sizeof(Incoming));

	passThroughOutput = grub_zalloc( outputlen );
	if( ! passThroughOutput ) {
		grub_free( passThroughInput );
	        grub_fatal( "readpcr: memory allocation failed" );
	}

	grub_TPM_efi_passThroughToTPM( passThroughInput, passThroughOutput );
	grub_free( passThroughInput );

	pcrReadOutgoing = (void *)passThroughOutput->TPMOperandOut;
	grub_uint32_t tpm_PCRreadReturnCode = grub_swap_bytes32( pcrReadOutgoing->returnCode );

	if( tpm_PCRreadReturnCode != TPM_SUCCESS ) {
		grub_free( passThroughOutput );

		if( tpm_PCRreadReturnCode == TPM_BADINDEX ) {
            grub_fatal( "readpcr: bad pcr index" );
		}

        grub_fatal( "readpcr: tpm_PCRreadReturnCode: %u", tpm_PCRreadReturnCode );
	}

	grub_memcpy( result, pcrReadOutgoing->pcr_value, SHA1_DIGEST_SIZE );
	grub_free( passThroughOutput );
}

/* Invokes TCG_StatusCheck Int1A interrupt

   Returns:
   returnCode: int1A return codes
   major version
   minor version
   featureFlags
   eventLog
   edi

   For more information see page 115 TCG_PCClientImplementation 1.21

 *//*modified to use in efi*/

grub_err_t
grub_TPM_efi_statusCheck( grub_uint32_t* returnCode, const grub_uint8_t* major, const grub_uint8_t* minor, grub_uint32_t* featureFlags, grub_addr_t *eventLog, grub_addr_t *edi )
{
	//TPM TESTING
	grub_printf("grub_TPM_efi_statusCheck \n");
	efi_tpm_protocol_t *tpm;
	grub_efi_status_t status;
	TCG_EFI_BOOT_SERVICE_CAPABILITY caps;

	grub_efi_handle_t *handles;
	grub_efi_handle_t tpm_handle;
	grub_efi_uintn_t num_handles;

	handles = grub_efi_locate_handle(GRUB_EFI_BY_PROTOCOL, &tpm_guid, NULL, &num_handles);
	if (handles && num_handles > 0) {
		tpm_handle = handles[0];
	} else {
		grub_fatal ( "grub_efi locate_handle failed. TPM not present.TPM_efi_statusCheck");
		return EFI_SUCCESS;
	}

	tpm = grub_efi_open_protocol(tpm_handle, &tpm_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

	if (!tpm_present(tpm)) {
		grub_fatal ( "grub_efi_open_protocol failed. grub_TPM not present.TPM_efi_statusCheck");
		return EFI_SUCCESS;
	}

	caps.Size = (grub_uint8_t)sizeof(caps);
	status = efi_call_5 (tpm->status_check, tpm, &caps, featureFlags,
							   eventLog, edi);

	if (status != EFI_SUCCESS || caps.TPMDeactivatedFlag
		|| !caps.TPMPresentFlag)
			return EFI_SUCCESS;

	*returnCode = status;
	return EFI_SUCCESS;
	// never reached here
	// major,minor for compatibility
	// ignore errors
	if ( major == minor ) return true;
}


/* Invokes TCG_PassThroughToTPM

   grub_fatal() on error
   Page 112 TCG_PCClientImplementation_1-21_1_00
 */

/* Modified for efi use */
grub_efi_status_t
grub_TPM_efi_passThroughToTPM
	(const PassThroughToTPM_InputParamBlock* input, PassThroughToTPM_OutputParamBlock* output )
{
	//TPM TESTING
	grub_printf("grub_TPM_efi_passThroughToTPM \n");
	grub_efi_status_t status;
	efi_tpm_protocol_t *tpm = NULL;
	grub_efi_handle_t *handles;
	grub_efi_handle_t tpm_handle;
	grub_efi_uintn_t num_handles;

	grub_uint32_t inhdrsize = sizeof(*input) - sizeof(input->TPMOperandIn);
	grub_uint32_t outhdrsize = sizeof(*output) - sizeof(output->TPMOperandOut);

	CHECK_FOR_NULL_ARGUMENT( input );
	CHECK_FOR_NULL_ARGUMENT( output );

	if ( ! input->IPBLength || ! input->OPBLength ) {
		 grub_fatal( "tcg_passThroughToTPM: ! input->IPBLength || ! input->OPBLength" );
	}

	handles = grub_efi_locate_handle(GRUB_EFI_BY_PROTOCOL, &tpm_guid, NULL, &num_handles);
	if (handles && num_handles > 0) {
		tpm_handle = handles[0];
	} else {
		grub_fatal ( "grub_efi locate_handle failed. TPM not present.TPM_efi_passThroughToTPM");
		return EFI_SUCCESS;
	}

	tpm = grub_efi_open_protocol(tpm_handle, &tpm_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

	if (!tpm_present(tpm)) {
		grub_fatal ( "grub_efi_open_protocol failed. grub_TPM not present.TPM_efi_passThroughToTPM");
		return EFI_SUCCESS;
	}

	status = efi_call_5 (tpm->pass_through_to_tpm, tpm,
				input->IPBLength - inhdrsize, input->TPMOperandIn,
				input->OPBLength - outhdrsize, output->TPMOperandOut);

	switch (status) {
		case GRUB_EFI_SUCCESS:
			return EFI_SUCCESS;
		case GRUB_EFI_DEVICE_ERROR:
			return grub_error (GRUB_ERR_IO, N_("Command failed"));
		case GRUB_EFI_INVALID_PARAMETER:
			return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
		case GRUB_EFI_BUFFER_TOO_SMALL:
			return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Output buffer too small"));
		case GRUB_EFI_NOT_FOUND:
			return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
		default:
			return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
	}
}

/* grub_fatal() on error */
void
grub_TPM_measure_string( const char* string ) {

	DEBUG_PRINT("grub_TPM_measure_string \n");

	efi_tpm_protocol_t *tpm;

	grub_efi_handle_t *handles;
	grub_efi_handle_t tpm_handle;
	grub_efi_uintn_t num_handles;

	handles = grub_efi_locate_handle(GRUB_EFI_BY_PROTOCOL, &tpm_guid, NULL, &num_handles);
	if (handles && num_handles > 0) {
		tpm_handle = handles[0];
	} else {
		DEBUG_PRINT ( "grub_efi locate_handle failed. TPM not present.");
		return;
	}

	tpm = grub_efi_open_protocol(tpm_handle, &tpm_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

	if (!tpm_present(tpm)) {
		DEBUG_PRINT ( "grub_efi_open_protocol failed. grub_TPM not present.");
		return;
	}
	/* TPM check end*/

	CHECK_FOR_NULL_ARGUMENT( string )

	grub_uint32_t result[5] = { 0 };
	grub_err_t err = sha1_hash_string( string, result );
	if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureString: sha1_hash_string failed." );
	}

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE] = { 0 };
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}

#ifdef TGRUB_DEBUG
	DEBUG_PRINT( ( "string to measure: '%s'\n", string ) );
	DEBUG_PRINT( ( "SHA1 of string: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

    /*modified to use in efi*/
	grub_TPM_efi_hashLogExtendEvent( tpm, convertedResult, TPM_COMMAND_MEASUREMENT_PCR, string );    
}

/* grub_fatal() on error */
void
grub_TPM_measure_file( const char* filename, const grub_uint8_t index ) {

	DEBUG_PRINT("grub_TPM_measure_file \n");

	efi_tpm_protocol_t *tpm;

	grub_efi_handle_t *handles;
	grub_efi_handle_t tpm_handle;
	grub_efi_uintn_t num_handles;

	handles = grub_efi_locate_handle(GRUB_EFI_BY_PROTOCOL, &tpm_guid, NULL, &num_handles);
	if (handles && num_handles > 0) {
		tpm_handle = handles[0];
	} else {
		DEBUG_PRINT ( "grub_efi locate_handle failed. TPM not present.");
		return;
	}

	tpm = grub_efi_open_protocol(tpm_handle, &tpm_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

	if (!tpm_present(tpm)) {
		DEBUG_PRINT ( "grub_efi_open_protocol failed. grub_TPM not present.");
		return;
	}
	/* TPM check end*/

	CHECK_FOR_NULL_ARGUMENT( filename )

	/* open file 'raw' (without any pre-processing filters) */
	grub_file_filter_disable_compression ();
	grub_file_t file = grub_file_open( filename );

	if( ! file ) {
        grub_print_error();
        grub_fatal( "grub_TPM_measureFile: grub_file_open failed." );
	}

	/* hash file */
	grub_uint32_t result[5] = { 0 };
	grub_err_t err = sha1_hash_file( file, result  );

    if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureFile: sha1_hash_file failed." );
	}

	grub_file_close( file );

    if ( grub_errno ) {
        grub_fatal( "grub_TPM_measureFile: grub_file_close failed." );
    }

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE] = { 0 };
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}

#ifdef TGRUB_DEBUG
    /* print hash */
	DEBUG_PRINT( ( "measured file: %s\n", filename ) );
	DEBUG_PRINT( ( "SHA1 of file: " ) );
    print_sha1( convertedResult );
    DEBUG_PRINT( ( "\n" ) );
#endif

	/* measure */
	/* modified to use in efi*/
    	grub_TPM_efi_hashLogExtendEvent( tpm, convertedResult, index, filename );
}

void
grub_TPM_measure_buffer( const void* buffer, const grub_uint32_t bufferLen, const grub_uint8_t index )
{
	DEBUG_PRINT("grub_TPM_measure_buffer \n");

	efi_tpm_protocol_t *tpm;

	grub_efi_handle_t *handles;
	grub_efi_handle_t tpm_handle;
	grub_efi_uintn_t num_handles;

	handles = grub_efi_locate_handle(GRUB_EFI_BY_PROTOCOL, &tpm_guid, NULL, &num_handles);
	if (handles && num_handles > 0) {
		tpm_handle = handles[0];
	} else {
		DEBUG_PRINT ( "grub_efi locate_handle failed. TPM not present.");
		return;
	}

	tpm = grub_efi_open_protocol(tpm_handle, &tpm_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

	if (!tpm_present(tpm)) {
		DEBUG_PRINT ( "grub_efi_open_protocol failed. grub_TPM not present.");
		return;
	}
	/* TPM check end*/

	CHECK_FOR_NULL_ARGUMENT( buffer )

	if(bufferLen == 0) return;

	/* hash buffer */
	grub_uint32_t result[5] = { 0 };
	grub_err_t err = sha1_hash_buffer( buffer, bufferLen, result );

	if( err != GRUB_ERR_NONE ) {
		grub_fatal( "grub_TPM_measureBuffer: sha1_hash_buffer failed." );
	}

	/* convert from uint32_t to uint8_t */
	grub_uint8_t convertedResult[SHA1_DIGEST_SIZE] = { 0 };
	int j, i = 0;
	for( j = 0; j < 5; j++ ) {
		convertedResult[i++] = ((result[j]>>24)&0xff);
		convertedResult[i++] = ((result[j]>>16)&0xff);
		convertedResult[i++] = ((result[j]>>8)&0xff);
		convertedResult[i++] = (result[j]&0xff);
	}
	/* measure */
	if (bufferLen != 0)
		grub_TPM_efi_hashLogExtendEvent(tpm, convertedResult, index, "measured buffer" );
}
/* End TCG Extension */
