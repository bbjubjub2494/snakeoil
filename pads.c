#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pads.h"
#include "helper.h"
#include "userkey.h"
#include "spaestr.h"

pads_error_t create_pads_cfg_file(FILE* f)
{
	struct pads p;
	// Set values to 0
	memset(&p, 0, PADS_STRUCT_SIZE);
	const size_t count = fwrite(&p, PADS_STRUCT_SIZE, 1, f);

	if (count < 1)
	{
		return PADS_ERROR_WRITEFILE;
	}

	return PADS_ERROR_OK;
}

void make_single_pad(char* pad, char* row)
{
	char* temp = ALLOC(_2_POW_23 + 1);
	size_t offset = _2_POW_23, step = 1;

	for (size_t i = 0; i < 7; i++)
	{
		if (step == 1)
		{
			memcpy(pad, row, _2_POW_23);
			pad[_2_POW_23] = '\0';
			memcpy(temp, row + offset, _2_POW_23);
			temp[_2_POW_23] = '\0';
			fmakeXOR(pad, temp);

			step++;
			offset += _2_POW_23;
		}
		else
		{
			memcpy(temp, row + offset, _2_POW_23);
			fmakeXOR(pad, temp);

			step++;
			offset += _2_POW_23;
		}
	}

	FREE(temp);
}

size_t get_first_used_pad_id(size_t* pads_list, size_t count, const char* pads_dir, char* pps, size_t* offset)
{
	size_t pad_id = 0;
	size_t pad_offset = 0;

	char* pad_path = ALLOC(sizeof(char) * _MAX_PATH);
	char* pad_name = ALLOC(sizeof(char) * 8 + 1);

	for (size_t i = 0; i < count; i++)
	{
		_ui64toa_s(pads_list[i], pad_name, 9, 10);
		strcat_s(pad_name, 9, ".txt");

		strcpy_s(pad_path, _MAX_PATH, pads_dir);
		pad_path[strlen(pads_dir)] = '\0';
		strcat_s(pad_path, _MAX_PATH, "\\");
		strcat_s(pad_path, _MAX_PATH, pad_name);

		pad_offset = find_str_in_file(pad_path, pps);
		if (-1 != pad_offset)
		{
			pad_id = pads_list[i];
			*offset = pad_offset;

			return pad_id;
		}
	}

	return 0;
}
