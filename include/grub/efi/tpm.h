#include <grub/efi/api.h>

#define EFI_TPM_GUID {0xf541796d, 0xa62e, 0x4954, {0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd }};
#define EFI_TPM2_GUID {0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }};
#define EFIAPI

#ifndef TPM_BOOLEAN
typedef enum { false = 0, true = 1 } BOOLEAN;
#define TPM_BOOLEAN
#endif
/*modified for grub*/
grub_efi_status_t tpm_log_event(grub_addr_t buf, grub_uint64_t size, grub_uint8_t pcr,
			 const unsigned char *description);
//EFI_STATUS tpm_log_event(EFI_PHYSICAL_ADDRESS buf, UINTN size, UINT8 pcr,
//			 const CHAR8 *description);


/************************* constants *************************/

#define EFI_SUCCESS	0

/* Command return codes */
#define TPM_BASE 0x0
#define TPM_SUCCESS TPM_BASE
#define TPM_AUTHFAIL (TPM_BASE + 0x1)
#define TPM_BADINDEX (TPM_BASE + 0x2)


/* TODO: 0x10000 does not work for some reason */
/* is  0x20000 and 0x30000 a good choice? */

#define INPUT_PARAM_BLK_ADDR 0x30000
#define OUTPUT_PARAM_BLK_ADDR 0x20000

#define TPM_TAG_RQU_COMMAND 0x00C1

#define TCPA 0x41504354
/************************* macros *************************/

#define CHECK_FOR_NULL_ARGUMENT( argument )                                                                 \
                        if( ! argument ) {                                                                                                  \
                                grub_fatal( "BAD_ARGUMENT: argument is NULL" );                                 \
                        }

/************************* struct typedefs *************************/

typedef struct {
  grub_uint8_t Major;
  grub_uint8_t Minor;
  grub_uint8_t RevMajor;
  grub_uint8_t RevMinor;
} TCG_VERSION;

typedef struct _TCG_EFI_BOOT_SERVICE_CAPABILITY {
  grub_uint8_t          Size;                /// Size of this structure.
  TCG_VERSION    StructureVersion;
  TCG_VERSION    ProtocolSpecVersion;
  grub_uint8_t          HashAlgorithmBitmap; /// Hash algorithms .
  char        TPMPresentFlag;      /// 00h = TPM not present.
  char        TPMDeactivatedFlag;  /// 01h = TPM currently deactivated.
} TCG_EFI_BOOT_SERVICE_CAPABILITY;

typedef struct _TCG_PCR_EVENT {
  grub_uint32_t PCRIndex;
  grub_uint32_t EventType;
  grub_uint8_t digest[20];
  grub_uint32_t EventSize;
  grub_uint8_t  Event[1];
} TCG_PCR_EVENT;

struct efi_tpm_protocol
{
  grub_efi_status_t (EFIAPI *status_check) (struct efi_tpm_protocol *this,
				     TCG_EFI_BOOT_SERVICE_CAPABILITY *ProtocolCapability,
				     grub_uint32_t *TCGFeatureFlags,
				     grub_addr_t *EventLogLocation,
				     grub_addr_t *EventLogLastEntry);
  grub_efi_status_t (EFIAPI *hash_all) (struct efi_tpm_protocol *this,
				 grub_uint8_t *HashData,
				 grub_uint64_t HashLen,
				 grub_uint32_t AlgorithmId,
				 grub_uint64_t *HashedDataLen,
				 grub_uint8_t **HashedDataResult);
  grub_efi_status_t (EFIAPI *log_event) (struct efi_tpm_protocol *this,
				  TCG_PCR_EVENT *TCGLogData,
				  grub_uint32_t *EventNumber,
				  grub_uint32_t Flags);
  grub_efi_status_t (EFIAPI *pass_through_to_tpm) (struct efi_tpm_protocol *this,
					    grub_uint32_t TpmInputParameterBlockSize,
					    grub_uint8_t *TpmInputParameterBlock,
					    grub_uint32_t TpmOutputParameterBlockSize,
					    grub_uint8_t *TpmOutputParameterBlock);
  grub_efi_status_t (EFIAPI *log_extend_event) (struct efi_tpm_protocol *this,
					 grub_addr_t HashData,
					 grub_uint64_t HashDataLen,
					 grub_uint32_t AlgorithmId,
					 TCG_PCR_EVENT *TCGLogData,
					 grub_uint32_t *EventNumber,
					 grub_addr_t *EventLogLastEntry);
};

typedef struct efi_tpm_protocol efi_tpm_protocol_t;

typedef grub_uint32_t EFI_TCG2_EVENT_LOG_BITMAP;
typedef grub_uint32_t EFI_TCG2_EVENT_LOG_FORMAT;
typedef grub_uint32_t EFI_TCG2_EVENT_ALGORITHM_BITMAP;

typedef struct tdEFI_TCG2_VERSION {
  grub_uint8_t Major;
  grub_uint8_t Minor;
} __attribute__ ((packed)) EFI_TCG2_VERSION;

typedef struct tdEFI_TCG2_BOOT_SERVICE_CAPABILITY_1_0 {
  grub_uint8_t Size;
  EFI_TCG2_VERSION StructureVersion;
  EFI_TCG2_VERSION ProtocolVersion;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP HashAlgorithmBitmap;
  EFI_TCG2_EVENT_LOG_BITMAP SupportedEventLogs;
  BOOLEAN TPMPresentFlag;
  grub_uint16_t MaxCommandSize;
  grub_uint16_t MaxResponseSize;
  grub_uint32_t ManufacturerID;
  grub_uint32_t NumberOfPcrBanks;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP ActivePcrBanks;
} EFI_TCG2_BOOT_SERVICE_CAPABILITY_1_0;

typedef struct tdEFI_TCG2_BOOT_SERVICE_CAPABILITY {
  grub_uint8_t Size;
  EFI_TCG2_VERSION StructureVersion;
  EFI_TCG2_VERSION ProtocolVersion;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP HashAlgorithmBitmap;
  EFI_TCG2_EVENT_LOG_BITMAP SupportedEventLogs;
  BOOLEAN TPMPresentFlag;
  grub_uint16_t MaxCommandSize;
  grub_uint16_t MaxResponseSize;
  grub_uint32_t ManufacturerID;
  grub_uint32_t NumberOfPcrBanks;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP ActivePcrBanks;
} __attribute__ ((packed))  EFI_TCG2_BOOT_SERVICE_CAPABILITY;

typedef grub_uint32_t TCG_PCRINDEX;
typedef grub_uint32_t TCG_EVENTTYPE;

typedef struct tdEFI_TCG2_EVENT_HEADER {
  grub_uint32_t HeaderSize;
  grub_uint16_t HeaderVersion;
  TCG_PCRINDEX PCRIndex;
  TCG_EVENTTYPE EventType;
} __attribute__ ((packed)) EFI_TCG2_EVENT_HEADER;

typedef struct tdEFI_TCG2_EVENT {
  grub_uint32_t Size;
  EFI_TCG2_EVENT_HEADER Header;
  grub_uint8_t Event[1];
} __attribute__ ((packed)) EFI_TCG2_EVENT;

struct efi_tpm2_protocol
{
  grub_efi_status_t (EFIAPI *get_capability) (struct efi_tpm2_protocol *this,
				       EFI_TCG2_BOOT_SERVICE_CAPABILITY *ProtocolCapability);
  grub_efi_status_t (EFIAPI *get_event_log) (struct efi_tpm2_protocol *this,
				      EFI_TCG2_EVENT_LOG_FORMAT EventLogFormat,
				      grub_addr_t *EventLogLocation,
				      grub_addr_t *EventLogLastEntry,
				      BOOLEAN *EventLogTruncated);
  grub_efi_status_t (EFIAPI *hash_log_extend_event) (struct efi_tpm2_protocol *this,
					      grub_uint64_t Flags,
					      grub_addr_t DataToHash,
					      grub_uint64_t DataToHashLen,
					      EFI_TCG2_EVENT *EfiTcgEvent);
  grub_efi_status_t (EFIAPI *submit_command) (struct efi_tpm2_protocol *this,
				       grub_uint32_t InputParameterBlockSize,
				       grub_uint8_t *InputParameterBlock,
				       grub_uint32_t OutputParameterBlockSize,
				       grub_uint8_t *OutputParameterBlock);
  grub_efi_status_t (EFIAPI *get_active_pcr_blanks) (struct efi_tpm2_protocol *this,
					      grub_uint32_t *ActivePcrBanks);
  grub_efi_status_t (EFIAPI *set_active_pcr_banks) (struct efi_tpm2_protocol *this,
					     grub_uint32_t ActivePcrBanks);
  grub_efi_status_t (EFIAPI *get_result_of_set_active_pcr_banks) (struct efi_tpm2_protocol *this,
							   grub_uint32_t *OperationPresent,
							   grub_uint32_t *Response);
};

typedef struct efi_tpm2_protocol efi_tpm2_protocol_t;

/* TCG_PassThroughToTPM Input Parameter Block */
typedef struct {
	grub_uint16_t IPBLength;
	grub_uint16_t Reserved1;
	grub_uint16_t OPBLength;
	grub_uint16_t Reserved2;
	grub_uint8_t TPMOperandIn[1];
} GRUB_PACKED PassThroughToTPM_InputParamBlock;

/* TCG_PassThroughToTPM Output Parameter Block */
typedef struct {
	grub_uint16_t OPBLength;
	grub_uint16_t Reserved;
	grub_uint8_t TPMOperandOut[1];
} GRUB_PACKED PassThroughToTPM_OutputParamBlock;

/************************* functions *************************/

/* Invokes TCG_StatusCheck */
grub_err_t EXPORT_FUNC(grub_TPM_efi_statusCheck)( grub_uint32_t* returnCode, const grub_uint8_t* major, const grub_uint8_t* minor, grub_uint32_t* featureFlags, grub_addr_t* eventLog, grub_addr_t* edi);

BOOLEAN EXPORT_FUNC(tpm_present)(efi_tpm_protocol_t *tpm);

grub_efi_status_t EXPORT_FUNC(grub_TPM_efi_hashLogExtendEvent)(const grub_uint8_t * inDigest, grub_uint8_t pcrIndex, const char* descriptions );

/* pass commands to TPM */
grub_efi_status_t EXPORT_FUNC(grub_TPM_efi_passThroughToTPM) ( const PassThroughToTPM_InputParamBlock* input,
		PassThroughToTPM_OutputParamBlock* output );
