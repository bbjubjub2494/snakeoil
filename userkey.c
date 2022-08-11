#pragma warning(disable : 4996)
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "userkey.h"
#include "mem.h"
#include "spaestr.h"
#include "helper.h"
#include "psp.h"

char* trim_uk(char* u_key, char* error_desc)
{
	if (NULL == u_key) {
		strcpy_s(error_desc, 256, "\nError: empty argument given to expand_uk() function!\n");
		return NULL;
	}

	char* trimmed_uk = ALLOC(UK_LENGHT + 1);

	strncpy_s(trimmed_uk, UK_LENGHT + 1, u_key, UK_LENGHT);
	trimmed_uk[UK_LENGHT] = '\0';

	return trimmed_uk;
}


/*Expand UserKey file*/
char* expand_uk(char* key, char* error_desc)
{
	if (NULL == key) {
		strcpy_s(error_desc, 256, "\nError: empty argument given to expand_uk() function!\n");
		return NULL;
	}

	size_t integer_part  = 0;
	size_t remained_part = 0;
	size_t key_len       = 0;

	char* uk = ALLOC(sizeof(char) * UK_LENGHT + 1);

	key_len = strlen(key);
	if (key_len == 0) {
		strcpy_s(error_desc, 256, "\nError: empty data submitted. Pls, check!\n");
		return NULL;
	}

	//get integer part of divided, eg. 2^26/18 = 3728270
	integer_part = UK_LENGHT / key_len;

	//get remained part, eg 4
	remained_part = UK_LENGHT % key_len;

	size_t index = 0;
	while (integer_part-- > 0)
	{
		strcpy_s(uk + index, key_len + 1, key);
		index += key_len;
	}

	strncpy_s(uk + index, remained_part + 1, key, remained_part);
	uk[UK_LENGHT] = '\0';

	return uk;
}

void expand_uk_in(char* uk, char* key, char* error_desc)
{
	if (NULL == key) {
		strcpy_s(error_desc, 256, "\nError: empty argument given to expand_uk() function!\n");
		return;
	}

	size_t integer_part = 0, remained_part = 0, key_len = 0;
	//char* uk = ALLOC(sizeof(char) * UK_LENGHT + 1);

	key_len = strlen(key);
	if (key_len == 0) {
		strcpy_s(error_desc, 256, "\nError: empty data submitted. Pls, check!\n");
		return;
	}

	//get integer part of divided, eg. 2^26/18 = 3728270
	integer_part = UK_LENGHT / key_len;

	//get remained part, eg 4
	remained_part = UK_LENGHT % key_len;

	size_t index = 0;
	while (integer_part-- > 0)
	{
		strcpy_s(uk + index, key_len + 1, key);
		index += key_len;
	}

	strncpy_s(uk + index, remained_part + 1, key, remained_part);
	uk[UK_LENGHT] = '\0';
}

void combine_strands(char* strand, char** list, size_t n)
{
	strand[0] = '\0';

	/* Read whole file content into memory
	 *  Allocate enough heap size for file content*/
	char* fContent;
	size_t contentSize = 0;
	int readStatus;

	FILE* strd = NULL;
	for (size_t i = 0; i < n; i++) 
	{
		fopen_s(&strd, list[i], "rb");
		if (!strd) 
		{
			printf("Strand file opening failed%s\n", list[i]);
		}
		fContent = c_read_file(strd, &readStatus, &contentSize);
		if (readStatus)
			printf("\nThere was an error when reading strand file: %d\n", readStatus);

		strcat(strand, fContent);

		FREE(fContent);
		fclose(strd);
	}
}

void merge_sequences_by_content(char* result, char** list, size_t n)
{
	result[0] = '\0';

	for (size_t i = 0; i < n; i++)
	{
		strcat(result, list[i]);
	}
}

void collect_logic_op_methods(char* bits, const char* str)
{
	if (strlen(str) < _2_POW_23)
	{
		return;
	}

	for (size_t i = 0; i < 8; i++)
	{
		bits[i] = str[i * _2_POW_23];
	}
}

void do_logical_operation(char* b, char* pb, char* bd, const char* m)
{
	char* buk_i = ALLOC(_2_POW_23 + 1);
	char* bday_i = ALLOC(_2_POW_23 + 1);
	size_t offset = 0;

	for (size_t i = 0; i < 8; i++)
	{
		if (m[i] == '1')
		{
			memcpy(buk_i, pb + offset, _2_POW_23);
			buk_i[_2_POW_23] = '\0';
			memcpy(bday_i, bd + offset, _2_POW_23);
			bday_i[_2_POW_23] = '\0';
			fmakeXOR(buk_i, bday_i);
			strcat(b, buk_i);
		}
		else
		{
			memcpy(buk_i, pb + offset, _2_POW_23);
			buk_i[_2_POW_23] = '\0';
			memcpy(bday_i, bd + offset, _2_POW_23);
			bday_i[_2_POW_23] = '\0';
			fmakeXNOR(buk_i, bday_i);
			strcat(b, buk_i);
		}

		offset += _2_POW_23;
	}

	FREE(buk_i);
	FREE(bday_i);
}

void do_logical_operation_for_the_next_pad(char* b, char* pb, char* bd, const char* m)
{
	char* buk_i = ALLOC(_2_POW_23 + 1);
	size_t offset = 0;

	for (size_t i = 0; i < 8; i++)
	{
		if (m[i] == '1')
		{
			memcpy(buk_i, pb + offset, _2_POW_23);
			buk_i[_2_POW_23] = '\0';
			fmakeXOR(buk_i, bd);
			strcat(b, buk_i);
			b[(i + 1) * _2_POW_23] = '\0';
		}
		else
		{
			memcpy(buk_i, pb + offset, _2_POW_23);
			buk_i[_2_POW_23] = '\0';
			fmakeXNOR(buk_i, bd);
			strcat(b, buk_i);
			b[(i + 1) * _2_POW_23] = '\0';
		}

		offset += _2_POW_23;
	}

	FREE(buk_i);
}

void get_start_jump_points(char* buk, size_t* start, size_t* jump)
{
	char* sp = ALLOC(23 + 1);
	char* jp = ALLOC(23 + 1);
	size_t offset = 0;

	for (size_t i = 0; i < 8; i++)
	{
		memcpy(sp, buk + offset, 23);
		sp[23] = '\0';
		memcpy(jp, buk + offset + 23, 23);
		jp[23] = '\0';

		start[i] = bindec(sp);
		jump[i] = bindec(jp);

		offset += _2_POW_23;
	}

	FREE(sp);
	FREE(jp);
}

void create_MRS_file(char* mrs, const char* input, size_t* sp, size_t* jp)
{
	char* tmpBuff = ALLOC(_2_POW_23 + 1);
	mrs[0] = '\0';
	size_t offset = 0;

	for (size_t i = 0; i < 8; i++)
	{
		memcpy(tmpBuff, input + offset, _2_POW_23);
		tmpBuff[_2_POW_23] = '\0';
		char* psp = PSP(tmpBuff, sp[i], jp[i]);
		strcat(mrs, psp);

		offset += _2_POW_23;
		FREE(psp);
	}

	FREE(tmpBuff);
}

void generate_specialchars_lookup_table(char*** finalTable, const char* bukPart, const char* mrsPart, size_t* seeker, size_t pointer_shift, size_t* size)
{
	// We will store unique tuples here
	char** uniqueTuple = ALLOC(128 * sizeof(char*));
	// This one is just for temporary use when we collecting the next tuple
	char tmpUniqueTuple[16][7] = { 0 };

	size_t offset = 0;
	size_t count = 0;

	while (*size < 72) //was 65
	{
		size_t pointerPosition = pointer_shift;

		// Value for first elem we getting from buk, second value from mrs.
		for (size_t i = 0; i < 8; i++)
		{
			memcpy(tmpUniqueTuple[i * 2], bukPart + pointerPosition + *seeker * 6, 6);
			tmpUniqueTuple[i * 2][6] = '\0';

			memcpy(tmpUniqueTuple[i * 2 + 1], mrsPart + pointerPosition + *seeker * 6, 6);
			tmpUniqueTuple[i * 2 + 1][6] = '\0';

			pointerPosition += _2_POW_23;
		}
		offset += 6;
		/* We collected next portion of bits from BUK adn MRS strings.
		 * Now we should check if collected bits are unique.
		 */
		for (size_t i = 0; i < 16; i++)
		{
			uniqueTuple[count + i] = ALLOC(8 * sizeof(char));
			memcpy(uniqueTuple[count + i], tmpUniqueTuple[i], sizeof(*tmpUniqueTuple));
			uniqueTuple[count + i][6] = '\0';
		}

		// Check uniquness
		count = arrayUniqueWithoutSorting(uniqueTuple, count + 16);

		if (count >= 64)
		{
			finalTable[*size] = ALLOC(64 * sizeof(char*));

			for (size_t i = 0; i < 64; i++)
			{

				finalTable[*size][i] = ALLOC(6 * sizeof(char));

				memcpy(finalTable[*size][i], uniqueTuple[i], 6);
				finalTable[*size][i][6] = '\0';
				uniqueTuple[i] = NULL;
			}
			(*size)++;

			count = 0;
		}

		(*seeker)++;
	}
}

/*
 * Generating XOR/XNOR data for the 64 program files
 */
void generate_logical_op_data_for_program_files(char* logicalPointsArray, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset)
{
	//char* logicalBit = NEW(logicalBit);
	char* logicalBit;
	size_t size = 0;

	while (size < 64)
	{
		size_t pointerPosition = 0;

		for (size_t i = 0; i < 8; i++)
		{
			logicalBit = spae_substr(bukPart, pointerPosition + offset + *seeker * 1, 1);
			logicalPointsArray[size] = logicalBit[0];
			size++;

			logicalBit = spae_substr(mrsPart, pointerPosition + offset + *seeker * 1, 1);
			logicalPointsArray[size] = logicalBit[0];
			size++;

			pointerPosition += _2_POW_23;
		}
		(*seeker)++;
	}

	logicalPointsArray[64] = '\0';

	FREE(logicalBit);
}

/*
* REARRANGEMENT POINTS FOR BASE USER KEY SEQ's
*/
void generate_rearrangement_points_for_program_files(char** bukRearrangementPointsArray, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset)
{
	char* singlePointStr = ALLOC(sizeof(char) * 23 + 1);

	size_t size = 0;

	for (size_t i = 0; i < 8; i++)
	{
		memcpy_s(singlePointStr, 24, bukPart + offset + *seeker * 23, 23);
		singlePointStr[23] = '\0';

		bukRearrangementPointsArray[size] = ALLOC(24);
		memcpy(bukRearrangementPointsArray[size], singlePointStr, 23);
		bukRearrangementPointsArray[size][23] = '\0';
		size++;

		memcpy_s(singlePointStr, 24, mrsPart + offset + *seeker * 23, 23);
		singlePointStr[23] = '\0';

		bukRearrangementPointsArray[size] = ALLOC(24);
		memcpy(bukRearrangementPointsArray[size], singlePointStr, 23);
		bukRearrangementPointsArray[size][23] = '\0';
		size++;

		(*seeker)++;
	}

	FREE(singlePointStr);
}

void get_PPS_insertion_point(char** PPSpointStr, const char* buk, size_t offset)
{
	for (size_t i = 0; i < 7; i++)
	{
		PPSpointStr[i] = ALLOC(26 * sizeof(char));

		memcpy(PPSpointStr[i], buk + offset + 26*i, 26);
		PPSpointStr[i][26] = '\0';
	}
}

void rearrange_files(char* bkr, const char* buffer, char** points)
{
	char* temp = NEW(temp);
	size_t offset = 0;

	for (size_t i = 0; i < 8; i++)
	{
		size_t point = bindec(points[i]);
		if (_2_POW_23 < point) {
			point = point % _2_POW_23;
		}

		RESIZE(temp, (long)point + 1);

		memcpy(bkr + offset, buffer + offset + point, _2_POW_23 - point);
		bkr[_2_POW_23 - point] = '\0';
		memcpy(bkr + offset + _2_POW_23 - point, buffer + offset, point);
		bkr[_2_POW_23] = '\0';

		offset += _2_POW_23;
	}

	FREE(temp);
}

int collect_unique_bits_for_pads_permutation(size_t* final_array, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset, char* error_desc)
{
	char uniqueness_checker[_512_BUFFER] = { 0 };
	char* tmp_nine_bits = ALLOC(sizeof(char) * _512_BITS_TUPLE_SIZE + 1);

	size_t pointerPosition = 0;
	size_t array_key       = 0;
	size_t i               = 0;

	while (*seeker + _512_BITS_TUPLE_SIZE < UK_LENGHT && i < _512_BUFFER)
	{
		if (i < _512_BUFFER)
		{
			memcpy(tmp_nine_bits, bukPart + offset + *seeker, _512_BITS_TUPLE_SIZE);
			tmp_nine_bits[_512_BITS_TUPLE_SIZE] = '\0';

			array_key = bindec(tmp_nine_bits);
			if (array_key >= 0 && array_key < _512_BUFFER)
			{
				if (uniqueness_checker[array_key] == 0)
				{
					uniqueness_checker[array_key] = 1;
					final_array[i] = array_key;
					i++;
				}
			}
		}

		if (i < _512_BUFFER)
		{
			memcpy(tmp_nine_bits, mrsPart + offset + *seeker, _512_BITS_TUPLE_SIZE);
			tmp_nine_bits[_512_BITS_TUPLE_SIZE] = '\0';

			array_key = bindec(tmp_nine_bits);
			if (array_key >= 0 && array_key < _512_BUFFER)
			{
				if (uniqueness_checker[array_key] == 0)
				{
					uniqueness_checker[array_key] = 1;
					final_array[i] = array_key;
					i++;
				}
			}
		}
		
		//pointerPosition += _2_POW_23;
		(*seeker)+= _512_BITS_TUPLE_SIZE;
	}

	if (i < _512_BUFFER)
	{
		strcpy_s(error_desc, 256, "\nError: Not enough bits for transposition bits for Pads permutation.\n");
		return UK_ERROR_NOT_ENOUGH_BITS;
	}

	return UK_ERROR_OK;
}

void permutate_pad(char* res, char* pad, size_t pad_num, size_t* points)
{
	char* buffer = ALLOC(sizeof(char) * _512_BUFFER + 1);

	size_t offset = 0;
	size_t len = strlen(pad);
	size_t modified_permutation_values_array[512];

	for (size_t i = 0; i < _512_BUFFER; i++)
	{
		modified_permutation_values_array[i] = points[i] ^ (pad_num & _511_MASKING_BITS);
		assert(modified_permutation_values_array[i] < _512_BUFFER);
	}

	while (*pad != 0)
	{
		memcpy_s(buffer, _512_BUFFER + 1, pad, _512_BUFFER);
		buffer[_512_BUFFER] = '\0';

		for (size_t i = 0; i < _512_BUFFER; i++)
		{
			res[offset] = buffer[modified_permutation_values_array[i]];
			offset++;
		}
		pad += _512_BUFFER;
	}

	res[len] = '\0';
}