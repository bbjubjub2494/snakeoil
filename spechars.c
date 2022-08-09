//#pragma warning(disable : 4996)
#include "spechars.h"
#include "mem.h"
#include "pps.h"

/// <summary>
///	Init spec chars table with the predefined random six-bits values.
/// </summary>
void init_spec_chars_table_random()
{
	_random = map_create();
	_dagger = map_create();

	for (size_t i = 0; i < SPEC_CHARS_COUNT; i++)
	{
		map_set(_random, random_keys[i], spec_values[i]);
		map_set(_dagger, random_keys[i], spec_values[i]);
	}
}

/// <summary>
/// Init spec chars table with the simple order six-bits values.
/// </summary>
void init_spec_chars_table_simple()
{
	_uk = map_create();
	_simple = map_create();

	for (size_t i = 0; i < SPEC_CHARS_COUNT; i++)
	{
		map_set(_uk, simple_keys[i], spec_values[i]);
		map_set(_simple, simple_keys[i], spec_values[i]);
	}
}

/// <summary>
/// 
/// </summary>
struct map_t* init_enc_spec_chars_table(char* keys)
{
	struct map_t* m_s = { 0 };

	m_s = map_create();
	
	size_t offset = 0;
	char* key = ALLOC(sizeof(char) * 6 + 1);

	for (size_t i = 0; i < 64; i++)
	{
		memcpy_s(key, 7, keys + offset, 6);
		key[6] = '\0';

		map_set(m_s, key, spec_values[i]);
		offset += 6;
	}

	FREE(key);

	return m_s;
}

/// <summary>
/// Free allocated resource
/// </summary>
/// <param name="m"></param>
void free_struct_map(struct map_t* m)
{
	FREE(m->name);
	FREE(m->nxt);
	FREE(m->value);
	FREE(m);
}

/* Decryption item removed */

char* convert_spec_char_to_binary_for_uk(const wchar_t* content)
{
	size_t tmp = 0;
	const size_t length = wcslen(content);
	const size_t buffer_size = length * KEY_BITS_LEN + 1 + 6;

	char* key = ALLOC(sizeof(char) * KEY_BITS_LEN);
	char* result = ALLOC(sizeof(char) * buffer_size);

	init_spec_chars_table_simple();

	for (size_t i = 0; i < length; i++)
	{
		wchar_t vOut[2] = { content[i], 0 };

		key = map_get_key_by_val(_uk, vOut);

		memcpy_s(result + tmp, buffer_size, key, 6);

		tmp += 6;
	}

	result[tmp] = '\0';

	free_struct_map(_uk);

	return result;
}

void get_spec_char_by_index(wchar_t* r, char* index)
{
	init_spec_chars_table_random();

	wmemcpy(r, map_get(_random, index), 1);
	r[1] = '\0';

	free_struct_map(_random);
}

void get_spec_char_by_index_simple(wchar_t* r, char* index)
{
	init_spec_chars_table_simple();

	wmemcpy(r, map_get(_simple, index), 1);
	r[1] = '\0';

	free_struct_map(_simple);
}

void convert_PPS_to_spec_chars(wchar_t* ppsSpec, char* pps)
{
	init_spec_chars_table_simple();

	size_t offset = 0;
	size_t l = strlen(pps) / 6;

	char* splitted = ALLOC(7 * sizeof(char));

	for (size_t i = 0; i < l; i++)
	{
		memcpy(splitted, pps + offset, 6);
		splitted[6] = '\0';
		ppsSpec[i] = *map_get(_simple, splitted);
		offset += 6;
	}
	ppsSpec[l] = '\0';

	FREE(splitted);

	free_struct_map(_simple);
}

/* Decryption item removed */


/* Decryption item removed */


void convert_plain_short_txt_to_spec_chars(wchar_t* pSpec, char* pTxt, char* xorBits)
{
	init_spec_chars_table_random();

	size_t offset = 0;
	size_t l = strlen(pTxt) / 6;
	
	char* splitted = ALLOC(7 * sizeof(char));
	unsigned char* xoredIndex = NULL;

	for (size_t i = 0; i < 64; i++)
	{
		xoredIndex = xor_short_strings(random_keys[i], xorBits);
		xoredKeys[i] = xoredIndex;
		map_set(_random, xoredKeys[i], spec_values[i]);
		FREE(xoredIndex);
	}


	for (size_t i = 0; i < l; i++)
	{
		memcpy(splitted, pTxt + offset, 6);
		splitted[6] = '\0';
		pSpec[i] = *map_get(_random, splitted);
		offset += 6;
	}
	pSpec[l] = '\0';

	FREE(splitted);
	FREE(xoredIndex);

	free_struct_map(_random);
}

/* Decryption item removed */

void convert_enc_PPS_to_spec_char(wchar_t* ppsSpec, char* pps, char* lookupKeys)
{
	struct map_t* enc_map_s = init_enc_spec_chars_table(lookupKeys);

	wchar_t* single = ALLOC(sizeof(wchar_t) * 2);

	single = map_get(enc_map_s, pps);

	wmemcpy(ppsSpec, single, wcslen(single));

	ppsSpec[wcslen(single)] = '\0';

	free_struct_map(enc_map_s);
}

void convert_enc_PPS_to_spec_chars_simple(wchar_t* ppsSpec, char* pps)
{
	init_spec_chars_table_simple();

	size_t offset = 0;
	char* splitted = ALLOC(8 * sizeof(char));

	size_t l = strlen(pps) / 6;

	for (size_t i = 0; i < l; i++)
	{
		memcpy(splitted, pps + offset, 6);
		splitted[6] = '\0';
		ppsSpec[i] = *map_get(_simple, splitted);
		offset += 6;
	}
	ppsSpec[l] = '\0';

	FREE(splitted);

	free_struct_map(_simple);
}

void convert_enc_plain_txt_to_spec_chars(wchar_t* plainSpec, char* binCont, char* xorBits, char* lookupKeys)
{
	size_t offset = 0;
	char* splitted = ALLOC(8 * sizeof(char));
	size_t l = strlen(binCont) / 6;

	unsigned char* xoredIndex = ALLOC(7 * sizeof(unsigned char));

	size_t shift = 0;
	char* key = ALLOC(sizeof(char) * 6 + 1);

	for (size_t i = 0; i < 64; i++)
	{
		memcpy_s(key, 7, lookupKeys + shift, 6);
		key[6] = '\0';

		xoredIndex = xor_short_strings(key, xorBits);
		xoredIndex[6] = '\0';

		wxoredKeys[bindec(xoredIndex)] = spec_values[i];

		shift += 6;
	}

	for (size_t i = 0; i < l; i++)
	{
		memcpy(splitted, binCont + offset, 6);
		splitted[6] = '\0';
		plainSpec[i] = *wxoredKeys[bindec(splitted)];
		offset += 6;
	}
	plainSpec[l] = '\0';

	FREE(splitted);
	FREE(xoredIndex);
	FREE(key);
}
