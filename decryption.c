#include "decryption.h"

decr_error_t insert_data_into_dec_cfg(const char* cfg_path, struct decryptionCfg data, wchar_t* error_desc)
{
	FILE* f_cfg = NULL;
	fopen_s(&f_cfg, cfg_path, "ab+");
	if (f_cfg == NULL)
	{
		return DECR_ERROR_OPENFILE;
	}

	if (fwrite(&data, sizeof(data), 1, f_cfg) != 1)
	{
		wcscpy_s(error_desc, 256, L"Cannot write record into the decryption cfg file.");
		fclose(f_cfg);
		return DECR_ERROR_WRITEFILE;
	}
	else
	{
		// Flush and close Circle file, since it was successfully created/updated
		fflush(f_cfg);
		fclose(f_cfg);
	}

	return DECR_ERROR_OK;
}

struct decryptionCfg* get_decr_data_by_SPAE_name(const wchar_t* spae_name, wchar_t* error_desc)
{
	/*Accept the file and try to open it*/
	int open_status;

	FILE* f_cfg = NULL;
	/*Trying to open the file*/
	f_cfg = open_file(DECR_CONSTANTLY_UPD_FNAME, FILE_MODE_READ, &open_status);
	if (NULL == f_cfg)
	{
		wcscpy_s(error_desc, 256, L"\nWill be created decryption history file.\n");
		return NULL;
	}

	struct decryptionCfg* buffer = ALLOC(sizeof(struct decryptionCfg) * 1);

	while (fread(buffer, sizeof(struct decryptionCfg), 1, f_cfg) == 1)
	{
		if (0 == wcscmp(spae_name, buffer->spae_name))
		{
			fclose(f_cfg);
			return buffer;
		}
	}

	fclose(f_cfg);
	return NULL;
}


void get_binary_from_c_text(wchar_t* spec_text, struct encryptionCfg e_s, const char* prog_content, char* bin_data)
{
	char* encDataXorbits = ALLOC(sizeof(char) * 6 + 1);
	memcpy(encDataXorbits, e_s.xorbits, 6);
	encDataXorbits[6] = '\0';

	char* lookupTblKeys = ALLOC(sizeof(char) * 64 * 6 + 1);
	memcpy_s(lookupTblKeys, 64 * 6 + 1, prog_content, 64 * 6);
	lookupTblKeys[64 * 6] = '\0';

	/* Convert Spec char to Binary representation */
	convert_spec_chars_to_binary(spec_text, encDataXorbits, bin_data, lookupTblKeys);

	FREE(encDataXorbits);
	FREE(lookupTblKeys);
}


wchar_t** parse_file_name(wchar_t* s, const wchar_t* delim)
{
	wchar_t** result = ALLOC(sizeof(wchar_t) * 6);
	wchar_t* token = NULL;
	wchar_t* buffer;
	/* Get PSP part */
	token = wcstok_s(s, delim, &buffer);

	// loop through the string to extract all other tokens
	size_t i = 0;
	while (token != NULL) {

		result[i] = ALLOC(sizeof(wchar_t) * (long)wcslen(token) + 1);
		wmemcpy(result[i], token, wcslen(token));
		result[i][wcslen(token)] = '\0';

		token = wcstok_s(NULL, delim, &buffer);
		i++;
	}

	return result;
}

enc_error_t write_plain_txt_to_file(const char* f_name, const unsigned char* p_txt, size_t size, char* error_desc)
{
	FILE* decryptedFinalFile = NULL;

	int      open_status;
	/*Trying to open the file*/
	decryptedFinalFile = open_file(f_name, FILE_MODE_WRITE, &open_status);

	if (open_status != 0)
	{
		strcpy_s(error_desc, 256, "\nError: When trying to open a file for p-text writing.\n");
		return ENC_ERROR_OPENFILE;
	}

	fwrite(p_txt, 1, size, decryptedFinalFile);

	fflush(decryptedFinalFile);
	fclose(decryptedFinalFile);

	return ENC_ERROR_OK;
}