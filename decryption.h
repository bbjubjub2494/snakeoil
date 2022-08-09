#pragma once
#include <stdlib.h>
#include "helper.h"
#include "spaestr.h"
#include "psp.h"
#include "encryption.h"
#include "spechars.h"

/// @brief Error codes for library "pads"
typedef enum decr_error_e
{
	/// No error
	DECR_ERROR_OK = 0,

	/// Invalid Id for member
	DECR_ERROR_INVALID_MEMBER_ID = 1,

	/// Error reading file
	DECR_ERROR_READFILE = 2,

	/// Error writing file
	DECR_ERROR_WRITEFILE = 3,

	/// Error few Pads
	DECR_ERROR_FEWPADS = 4,

	/// Error Member ID < 0
	DECR_ERROR_WRONGMEMID = 5,

	/// Error pads count < 0
	DECR_ERROR_WRONGPADSCOUNT = 6,

	/// Error commmon error
	DECR_ERROR_COMMON = 7,

	/// Error open file
	DECR_ERROR_OPENFILE = 8,

	/// Error open file
	DECR_ERROR_HUGEFILE = 9,

	/// Empty file given
	DECR_ERROR_EMPTYFILE = 10,

	/// Empty file given
	DECR_ERROR_HISTORY = 11,
	/// Total # of errors in this list (NOT AN ACTUAL ERROR CODE);
	/// NOTE: that for this to work, it assumes your first error code is value 0 and you let it naturally 
	/// increment from there, as is done above, without explicitly altering any error values above
	DECR_ERROR_COUNT

} decr_error_t;


struct decryptionCfg 
{
	char circle_name[256];
	char dec_time[100];
	char pps[42];

	wchar_t spae_name[100];
	
	size_t member_number;
	size_t first_pad;
	size_t last_pad;
	size_t bits_used;
};

/*-------Opearations for decryptionCfg structure---------------*/
/* Decryption item removed */
/* Decryption item removed */
/* Decryption item removed */
/* Decryption item removed */
/* Decryption item removed */