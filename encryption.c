#pragma warning(disable : 4996)

#include "encryption.h"
#include "spechars.h"
#include "circle.h"
#include <stdio.h>
#include "pads.h"
#include "pps.h"

const size_t PPS_LENGTH             = 42;
const size_t PROGRAM_NUMBER_LENGTH  = 6;
const size_t XOR_BITS_LENGTH        = 6;
const size_t PSP_START_POINT_LENGTH = 26;
const size_t PSP_JUMP_POINT_LENGTH  = 26;
const size_t SPECIAL_CHAR_POSITION  = 26;
const size_t SPECIAL_CHAR_INDEX     = 6;

/* Add total bits to enc config file.                                             */
/* And because it is the first time to create config file,                        */
/* so we can just add total count as we get it.                                   */
/* Set used bits count to 0 and requested bits equal to encrypted file size!      */

enc_error_t store_enc_cfg(const char* f_name, struct encryptionCfg data, char* error_desc)
{
	int open_status;

	/*Accept the file and try to open it*/
	FILE* fileCfg = NULL;
	/*Trying to open the file*/
	fileCfg = open_file(f_name, FILE_MODE_WRITE, &open_status);

	if (open_status != 0)
	{
		strcpy_s(error_desc, 256, "\nError: When trying to open a file for storing encryption data.\n");
		return ENC_ERROR_OPENFILE;
	}

	if (fwrite(&data, sizeof(data), 1, fileCfg) != 1) 
	{
		strcpy_s(error_desc, 256, "\nError: Cannot create enc cfg file.\n");

		fflush(fileCfg);
		fclose(fileCfg);
		return ENC_ERROR_WRITEFILE;
	}

	fflush(fileCfg);
	fclose(fileCfg);
	return ENC_ERROR_OK;
}

wchar_t* encrypt_string(char* str, char* pad, char* error_desc)
{
	const size_t content_len = strlen(str);
	//Since this function is ONLY for small strings (up to Pad len)
	if (content_len >= PAD_LEN)
	{
		strcpy_s(error_desc, 256, "\nError: Enc string is ONLY for small strings.\n");
		return NULL;
	}

	size_t ppsInsertionPoint = 1590533;

	wchar_t* specChar =        ALLOC(sizeof(wchar_t) * 2);
	wchar_t* specPPS =         ALLOC(sizeof(wchar_t) * 9);
	wchar_t* plainSpec =       ALLOC(sizeof(wchar_t) * (content_len / 6 + 2));
	wchar_t* strWithSpecChar = ALLOC(sizeof(wchar_t) * (content_len / 6 + 8));
	wchar_t* strWithSpecPPS =  ALLOC(sizeof(wchar_t) * (content_len / 6 + 9));

	// Create encryption config file data using first Pad
	struct encryptionCfg encData = create_in_memeory_enc_cfg_file(pad, 0);

	//Get spec char by index
	char* encDataSpecialCharIndex = ALLOC(sizeof(char) * 6 + 1);
	memcpy(encDataSpecialCharIndex, encData.specialCharIndex, 6);
	encDataSpecialCharIndex[6] = '\0';

	get_spec_char_by_index(specChar, encDataSpecialCharIndex);
	FREE(encDataSpecialCharIndex);

	/* Do XOR */
	for (size_t k = 0; k < content_len; k++)
	{
		str[k] = (char)((str[k] - '0') ^ (pad[k] - '0') + '0');
	}

	// Convert PPS to spec chars
	char* encDataPPS = ALLOC(sizeof(char) * 42 + 1);
	memcpy(encDataPPS, encData.pps, 42);
	encDataPPS[42] = '\0';

	convert_PPS_to_spec_chars(specPPS, encDataPPS);
	
	FREE(encDataPPS);

	// Convert p-text to spech chars
	char* encDataXorbits = ALLOC(sizeof(char) * 6 + 1);
	memcpy(encDataXorbits, encData.xorbits, 6);
	encDataXorbits[6] = '\0';

	convert_plain_short_txt_to_spec_chars(plainSpec, str, encDataXorbits);
	
	str[0] = '\0';
	FREE(encDataXorbits);

	// DO PSP
	W_PSP(plainSpec, encData.startPoint % wcslen(plainSpec), encData.jumpPoint % wcslen(plainSpec));

	// Insert Special Char
	insert_substring(strWithSpecChar, plainSpec, specChar, encData.specialCharPosition % wcslen(plainSpec));

	// Insert PPS
	if (wcslen(plainSpec) < ppsInsertionPoint)
	{
		ppsInsertionPoint = ppsInsertionPoint % wcslen(plainSpec);
	}
	insert_substring(strWithSpecPPS, strWithSpecChar, specPPS, ppsInsertionPoint);


	FREE(specChar);
	FREE(specPPS);
	FREE(plainSpec);
	FREE(strWithSpecChar);

	return strWithSpecPPS;
}

struct encryptionCfg create_in_memeory_enc_cfg_file(char* fContent, size_t offset)
{
	struct encryptionCfg ec = { 0 };

	/*getting PPS first 42 bits*/
	memcpy(ec.pps, substr(fContent + offset, 0, PPS_LENGTH), PPS_LENGTH);

	/*getting Program number next 6 bits*/
	ec.programNumber = bindec(substr(fContent + offset, PPS_LENGTH, PROGRAM_NUMBER_LENGTH));

	/*getting six bits for XOR*/
	memcpy(ec.xorbits, substr(fContent + offset, PPS_LENGTH + PROGRAM_NUMBER_LENGTH, XOR_BITS_LENGTH), XOR_BITS_LENGTH);

	/*getting start point for PSP*/
	ec.startPoint = bindec(substr(fContent + offset, PPS_LENGTH + PROGRAM_NUMBER_LENGTH + XOR_BITS_LENGTH, PSP_START_POINT_LENGTH));

	/*getting jump point for PSP*/
	ec.jumpPoint = bindec(substr(fContent + offset, PPS_LENGTH + PROGRAM_NUMBER_LENGTH + XOR_BITS_LENGTH + PSP_START_POINT_LENGTH, PSP_JUMP_POINT_LENGTH));

	/*getting special char insertion position*/
	ec.specialCharPosition = bindec(substr(fContent + offset, PPS_LENGTH + PROGRAM_NUMBER_LENGTH + XOR_BITS_LENGTH + PSP_START_POINT_LENGTH + PSP_JUMP_POINT_LENGTH, SPECIAL_CHAR_POSITION));

	/*getting special char index*/
	memcpy(ec.specialCharIndex, substr(fContent + offset, PPS_LENGTH + PROGRAM_NUMBER_LENGTH + XOR_BITS_LENGTH + PSP_START_POINT_LENGTH + PSP_JUMP_POINT_LENGTH + SPECIAL_CHAR_POSITION, SPECIAL_CHAR_INDEX), SPECIAL_CHAR_INDEX);

	return ec;
}

char* get_pps_and_prog_file_contents(char* circle, const char* pads_dir, size_t prog_num, char* error_desc)
{
	/* So, it is the time when we should use                                          */
	/* one of the 64 program file. Since that files were encrypted, so                */
	/* first of all we need to decrypt the file and then only can get useful data.    */
	FILE* progFile    = NULL;
	FILE* progFilePPS = NULL;

	/* Build program file full path!                                                  */
	wchar_t* progFilePath    = CALLOC(sizeof(wchar_t) * _MAX_PATH, 1);
	wchar_t* PPSprogFilePath = CALLOC(sizeof(wchar_t) * _MAX_PATH, 1);

	wcscat_s(progFilePath,    _MAX_PATH, PROGRAMS_DIR);
	wcscat_s(PPSprogFilePath, _MAX_PATH, PROGRAMS_DIR);

	/* Convert to wide string and pass as an argument */
	wchar_t* circleNameW = ALLOC(sizeof(wchar_t) * strlen(circle) + 1);
	mbstowcs_s(NULL, circleNameW, strlen(circle) + 1, circle, strlen(circle));

	wchar_t* progFileNumW = ALLOC(sizeof(wchar_t) * 3);
	_ui64tow_s(prog_num, progFileNumW, 3, 10);

	wcscat_s(progFilePath, _MAX_PATH, circleNameW);
	wcscat_s(progFilePath, _MAX_PATH, L"/");
	wcscat_s(progFilePath, _MAX_PATH, progFileNumW);
	wcscat_s(progFilePath, _MAX_PATH, L".txt");

	int      open_status;

	/*Trying to open the file*/
	progFile = w_open_file(progFilePath, FILE_MODE_READ, &open_status);

	if (open_status != 0)
	{
		strcpy_s(error_desc, 256, "\nError: When trying to open a prog file.\n");
		return NULL;
	}

	/* Fail to set mode to UTF */
	if (-1 == set_file_mode_to_utf(&progFile))
	{
		strcpy_s(error_desc, 256, "\nError: When trying to set file mode to UTF.\n");
		return NULL;
	}

	/* For PPS */
	wcscat_s(PPSprogFilePath, _MAX_PATH, circleNameW);
	wcscat_s(PPSprogFilePath, _MAX_PATH, L"/");
	wcscat_s(PPSprogFilePath, _MAX_PATH, PPS_PROG_FILE);

	/*Trying to open the file*/
	progFilePPS = w_open_file(PPSprogFilePath, FILE_MODE_READ, &open_status);

	if (open_status != 0)
	{
		strcpy_s(error_desc, 256, "\nError: When trying to open a 64.txt.\n");
		return NULL;
	}

	/* Fail to set mode to UTF */
	if (-1 == set_file_mode_to_utf(&progFilePPS))
	{
		strcpy_s(error_desc, 256, "\nError: When trying to set file mode to UTF.\n");
		return NULL;
	}

	// Open and read first Pad
	char* padForProgFile = CALLOC(sizeof(char) * _MAX_PATH, 1);
	strcat_s(padForProgFile, _MAX_PATH, pads_dir);
	strcat_s(padForProgFile, _MAX_PATH, "//");
	strcat_s(padForProgFile, _MAX_PATH, PAD_FOR_PROG_FILE_DECR);

	/*Accept the file and try to open it*/
	FILE* padForCfg = NULL;
	/*Trying to open the file*/
	padForCfg = open_file(padForProgFile, FILE_MODE_READ, &open_status);

	/* Read whole file content into memory                                             */
	char* padContent;
	size_t contentSize = 0;
	int readStatus;

	padContent = c_read_file(padForCfg, &readStatus, &contentSize);
	if (readStatus)
	{
		strcpy_s(error_desc, 256, "\nError: There was an error when reading first pad for config file.\n");
		return NULL;
	}

	struct encryptionCfg progEncData = { 0 };
	progEncData = create_in_memeory_enc_cfg_file(padContent, 0);

	// decrypt program & pps files
       
	/* Decryption item removed */
	/* Decryption item removed */

	char* content = NULL; /* Decryption item removed */
    /* Decryption item removed */

	fclose(padForCfg);
	return content;
}

/* Decryption item removed */

/* Decryption item removed */

/* Decryption item removed */

void get_spec_PPS(struct encryptionCfg e_s, char* content, wchar_t* spec_pps)
{
	/* Lookup table for PPS representation (65th prog file).                         */
	char* PPSlookupTblKeys = ALLOC(sizeof(char) * 64 * 6 + 1);
	char* encDataPPS = ALLOC(sizeof(char) * 6 + 1);
	wchar_t* singlePPSChar = ALLOC(sizeof(wchar_t) * 2);

	for (size_t i = 0; i < 7; i++)
	{
		pps_get_nth_lookup_tbl(PPSlookupTblKeys, i, content);
		
		/* Get PPS from config file content and convert it to spec chars.                 */
		memcpy(encDataPPS, e_s.pps + 6*i, 6);
		encDataPPS[6] = '\0';

		convert_enc_PPS_to_spec_char(singlePPSChar, encDataPPS, PPSlookupTblKeys);

		wmemcpy(spec_pps + i, singlePPSChar, 1);

		spec_pps[7] = '\0';
	}

	FREE(PPSlookupTblKeys);
	FREE(encDataPPS);
}

void get_spec_text(struct encryptionCfg e_s, char* bin_content, char* prog_content, wchar_t* spec_text)
{
	char* encDataXorbits = ALLOC(sizeof(char) * 6 + 1);
	memcpy(encDataXorbits, e_s.xorbits, 6);
	encDataXorbits[6] = '\0';

	char* lookup_tbl_keys = ALLOC(sizeof(char) * 64 * 6 + 1);
	memcpy_s(lookup_tbl_keys, 64 * 6 + 1, prog_content, 64 * 6);
	lookup_tbl_keys[64 * 6] = '\0';

	convert_enc_plain_txt_to_spec_chars(spec_text, bin_content, encDataXorbits, lookup_tbl_keys);

	FREE(encDataXorbits);

}

void insert_spec_char(struct encryptionCfg e_s, wchar_t* spec_content, wchar_t* result)
{
	const size_t p_len = wcslen(spec_content);
	wchar_t* specialChar = ALLOC(sizeof(wchar_t) * 2);
	char* encDataSpecialCharIndex = ALLOC(sizeof(char) * 6 + 1);

	memcpy_s(encDataSpecialCharIndex, 7, e_s.specialCharIndex, 6);
	encDataSpecialCharIndex[6] = '\0';

	get_spec_char_by_index_simple(specialChar, encDataSpecialCharIndex);
	insert_substring(result, spec_content, specialChar, e_s.specialCharPosition % p_len);

	FREE(encDataSpecialCharIndex);
	FREE(specialChar);
}

void insert_pps(struct encryptionCfg e_s, wchar_t* spec_content, wchar_t* s_pps, char* prog_content, wchar_t* result)
{
	char* ppsInsertionPointStr = ALLOC(sizeof(char) * 26 + 1);
	wchar_t* singleCharPtr = ALLOC(sizeof(wchar_t) * 2);

	const size_t ps_len = wcslen(spec_content);

	for (size_t i = 0; i < 7; i++)
	{
		pps_get_nth_position(ppsInsertionPointStr, i, prog_content);
		
		size_t ppsInsertionPoint = bindec(ppsInsertionPointStr);
		if (ps_len < ppsInsertionPoint)
		{
			ppsInsertionPoint = ppsInsertionPoint % ps_len;
		}

		wmemcpy(singleCharPtr, s_pps + i, 1);
		singleCharPtr[1] = '\0';

		if (i == 0)
		{
			insert_substring(result, spec_content, singleCharPtr, ppsInsertionPoint);
		}
		else
		{
			insert_substring(result, result, singleCharPtr, ppsInsertionPoint);
		}
	}
}

wchar_t* biuld_enc_file_name(wchar_t* content, size_t added_bits_count, const wchar_t* dir, char* enc_f_name)
{
	wchar_t* finalFileName = ALLOC(sizeof(wchar_t) * _MAX_FNAME);

	wmemcpy(finalFileName, dir, wcslen(dir));
	finalFileName[wcslen(dir)] = '\0';
	//wcscat(finalFileName, L"\\");

	wcscat(finalFileName, wsub_string(content, 1, 7));
	//finalFileName[wcslen(dir) + 7] = '\0';
	wcscat(finalFileName, L".");

	/* Convert adde bits count  	                 	                              */
	wchar_t vOut[12];
	_itow_s((int)added_bits_count, vOut, sizeof(vOut) / 2, 10);
	wcscat(finalFileName, vOut);
	wcscat(finalFileName, L".");

	/* File's original extension  	                 	                              */
	wchar_t* exten = ALLOC(sizeof(wchar_t) * _MAX_EXT);
	char* fileExten = get_file_ext(enc_f_name);
	
	mbstowcs_s(NULL, exten, strlen(fileExten) + 1, fileExten, strlen(fileExten));
	wcscat(finalFileName, exten);
	wcscat(finalFileName, L".");

	/* Our extension            	                 	                              */
	wcscat(finalFileName, L"spae");
	repl_wcs(finalFileName, L"/", L"!");

	FREE(exten);
	return finalFileName;
}

enc_error_t write_cipher_to_file(const wchar_t* f_name, const wchar_t* cipher, char* error_desc)
{
	FILE* encryptedFinalFile = NULL;

	int      open_status;
	/*Trying to open the file*/
	encryptedFinalFile = w_open_file(f_name, FILE_MODE_WRITE, &open_status);

	if (open_status != 0)
	{
		strcpy_s(error_desc, 256, "\nError: When trying to open a file for cipher writing.\n");
		return ENC_ERROR_OPENFILE;
	}

	/* Fail to set mode to UTF */
	if (-1 == set_file_mode_to_utf(&encryptedFinalFile))
	{
		strcpy_s(error_desc, 256, "\nError: When trying to set final file mode to UTF.\n");
		return ENC_ERROR_OPENFILE;
	}

	fwrite(cipher, 2, wcslen(cipher), encryptedFinalFile);

	fflush(encryptedFinalFile);
	fclose(encryptedFinalFile);

	return ENC_ERROR_OK;
}

encCfgResponse get_option_from_enc_cfg(char* path, char* optName, char* error_desc)
{
	encCfgResponse response;
	FILE* encCfgF = NULL;
	errno_t err;

	/* Open config file */
	err = fopen_s(&encCfgF, path, "rb");
	if (!err && encCfgF != NULL)
	{
		struct encryptionCfg buffer;

		while (fread(&buffer, sizeof(struct encryptionCfg), 1, encCfgF) == 1)
		{
			if (0 == strcmp("usedBitsCount", optName))
			{
				response.int_value = buffer.usedBitsCount;
				fclose(encCfgF);
				return response;
			}

			if (0 == strcmp("totalBitsCount", optName))
			{
				response.int_value = buffer.totalBitsCount;
				fclose(encCfgF);
				return response;
			}

			if (0 == strcmp("availableBitsCount", optName))
			{
				response.int_value = buffer.availableBitsCount;
				fclose(encCfgF);
				return response;
			}

			if (0 == strcmp("requestedBitsCount", optName))
			{
				response.int_value = buffer.requestedBitsCount;
				fclose(encCfgF);
				return response;
			}

			if (0 == strcmp("specialCharPosition", optName))
			{
				response.int_value = buffer.specialCharPosition;
				fclose(encCfgF);
				return response;
			}

			if (0 == strcmp("jumpPoint", optName))
			{
				response.int_value = buffer.jumpPoint;
				fclose(encCfgF);
				return response;
			}

			if (0 == strcmp("startPoint", optName))
			{
				response.int_value = buffer.startPoint;
				fclose(encCfgF);
				return response;
			}

			if (0 == strcmp("programNumber", optName))
			{
				response.int_value = buffer.programNumber;
				fclose(encCfgF);
				return response;
			}

			if (0 == strcmp("pps", optName))
			{
				response.s = ALLOC(sizeof(char) * 42);
				memcpy(response.s, buffer.pps, 42);
				response.s[42] = '\0';
				fclose(encCfgF);
				return response;
			}

			fclose(encCfgF);
		}
	}
	else
	{
		strcpy_s(error_desc, 256, "\nEncryption Config file was not opened.\n");
		exit(EXIT_FAILURE);
	}
	return (encCfgResponse) { .int_value = 0 };
}

size_t* get_member_full_pad_IDs(size_t* all_list, size_t total_pads_count, size_t available_bits_count)
{
	size_t* fI = NULL;
	const size_t count = available_bits_count / PAD_LEN; // How many full pad is it

	if (count > 0)
	{
		fI = &all_list[total_pads_count - count];
		return  fI;
	}
	else
	{
		return fI;
	}
}

int get_member_partially_available_Pad_index(size_t* padList, size_t total_pads_count, size_t availableBits)
{
	size_t count = availableBits / PAD_LEN; // How many full pad is it

	if (count > 0)
	{
		/* Check if available bits count is fully divisable by PAD_SIZE, if not, so we have at */
		/* least one partially available pad, otherwise return no part pad available           */
		if (availableBits % PAD_LEN > 0)
		{
			return (int)(total_pads_count - count - 1);
		}
		else
		{
			return -1;
		}
	}
	/* It is last pad (index) */
	else
	{
		return (int)total_pads_count - 1;
	}
}