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
