#include "pps.h"
#include "assert.h"

/// <summary>
/// Allocate a new pps_t. NULL on failure.
/// </summary>
/// <param name=""></param>
/// <returns>An init-ed struct</returns>
pps_t* pps_new(void)
{
	pps_t* self;
	self = ALLOC(sizeof(pps_t) * 1);

	self->charInsertionPos = NULL;
	self->lookupTbl        = NULL;

	return self;
}

/// <summary>
/// Set appropriate values for newly created struct members.
/// </summary>
/// <param name="p"></param>
/// <param name="position"></param>
/// <param name="tbl"></param>
void pps_set(pps_t* p, const char* position, const char** tbl)
{
	/* Allocate enough memory */
	p->charInsertionPos = ALLOC(strlen(position)*sizeof(char) + 1);

	/* Assign value to PPS insertion position member */
	strcpy_s(p->charInsertionPos, strlen(position) + 1, position);

	/* Allocate memory for lookup table */
	p->lookupTbl = ALLOC(64 * sizeof(char*));

	/* Assign values using loop */
	for (size_t i = 0; i < 64; i++)
	{
		p->lookupTbl[i] = ALLOC(6 * sizeof(char));

		memcpy(p->lookupTbl[i], tbl[i], 6);
		p->lookupTbl[i][6] = '\0';
	}

	return;
}

/// <summary>
/// Marshaling PPS struct (7 element) into an "array".
/// </summary>
/// <param name="ppsData">Result array</param>
/// <param name="pps">Filled struct</param>
void pps_struct_into_array(char* ppsData, pps_t* pps)
{
	size_t pps_offset = 0;

	for (size_t i = 0; i < PPS_CHARS_COUNT; i++)
	{
		memcpy(ppsData + pps_offset, (pps + i)->charInsertionPos, strlen((pps + i)->charInsertionPos));

		pps_offset += strlen((pps + i)->charInsertionPos);
	}
	
	for (size_t i = 0; i < PPS_CHARS_COUNT; i++)
	{
		for (size_t j = 0; j < 64; j++) //SPEC_CHARS_COUNT
		{
			memcpy(ppsData + pps_offset, (pps + i)->lookupTbl[j], strlen((pps + i)->lookupTbl[j]));
			pps_offset += 6;
		}
	}

	ppsData[pps_offset] = '\0';
}

void pps_get_nth_position(char* pos, size_t n, char* data)
{
	assert(n < 7);
	size_t seek = 64 * 6 + n * 26;

	memcpy_s(pos, 27, data + seek, 26);
	pos[26] = '\0';
}

void pps_get_nth_lookup_tbl(char* tbl, size_t n, char* data)
{
	assert(n < 7);
	size_t seek = 64 * 6 + 7 * 26 + n*64*6;

	memcpy_s(tbl, 64 * 6 + 1, data + seek, 64 * 6);
	tbl[64 * 6] = '\0';
}

/// <summary>
/// Freed allocated struct obj
/// </summary>
/// <param name="p"></param>
void pps_free(pps_t* p)
{
	FREE(p->charInsertionPos);

	FREE(p->lookupTbl);

}
