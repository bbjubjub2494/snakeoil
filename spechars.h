#pragma once
#include "map.h"
#include "helper.h"

#define SPEC_CHARS_COUNT 64
#define KEY_BITS_LEN     6

static const char* simple_keys[64] =
{ "000000", "000001", "000010", "000011", "000100", "000101", "000110", "000111",
 "001000", "001001", "001010", "001011", "001100", "001101", "001110", "001111",
 "010000", "010001", "010010", "010011", "010100", "010101", "010110", "010111",
 "011000", "011001", "011010", "011011", "011100", "011101", "011110", "011111",
 "100000", "100001", "100010", "100011", "100100", "100101", "100110", "100111",
 "101000", "101001", "101010", "101011", "101100", "101101", "101110", "101111",
 "110000", "110001", "110010", "110011", "110100", "110101", "110110", "110111",
 "111000", "111001", "111010", "111011", "111100", "111101", "111110", "111111"
};

static const char* random_keys[64] =
{ "011110", "010100", "110100", "101000", "001110", "101110", "000101", "000100",
 "011011", "000111", "001011", "001101", "101101", "010011", "110000", "100010",
 "100111", "000001", "001001", "110010", "111110", "010101", "100101", "001010",
 "001100", "101001", "111111", "101011", "111100", "010000", "101100", "111011",
 "011100", "111000", "101010", "111001", "110110", "000110", "011101", "011010",
 "110011", "100100", "100001", "010010", "011000", "000011", "101111", "110101",
 "100011", "000000", "010001", "010111", "000010", "111101", "001111", "100110",
 "011111", "100000", "011001", "010110", "110001", "111010", "110111", "001000"
};

static const wchar_t* spec_values[64] =
{ L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7",
 L"8", L"9", L"A", L"B", L"C", L"D", L"E", L"F",
 L"G", L"H", L"I", L"J", L"K", L"L", L"M", L"N",
 L"O", L"P", L"Q", L"R", L"S", L"T", L"U", L"V",
 L"W", L"X", L"Y", L"Z", L"a", L"b", L"c", L"d",
 L"e", L"f", L"g", L"h", L"i", L"j", L"k", L"l",
 L"m", L"n", L"o", L"p", L"q", L"r", L"s", L"t",
 L"u", L"v", L"w", L"x", L"y", L"z", L"\u2020", L"/"
};

char* xoredKeys[64];
wchar_t* wxoredKeys[64];

static struct map_t* _uk;
static struct map_t* _random;
static struct map_t* _simple;
static struct map_t* _dagger;

void init_spec_chars_table_random();
void init_spec_chars_table_simple();
struct map_t* init_enc_spec_chars_table(char* keys);
void free_struct_map(struct map_t* m);

/* Decryption item removed */
char* convert_spec_char_to_binary_for_uk(const wchar_t* content);
void get_spec_char_by_index(wchar_t* r, char* index);
void get_spec_char_by_index_simple(wchar_t* r, char* index);
void convert_PPS_to_spec_chars(wchar_t* ppsSpec, char* pps);
/* Decryption item removed */
void convert_plain_short_txt_to_spec_chars(wchar_t* pSpec, char* pTxt, char* xorBits);
void convert_enc_PPS_to_spec_char(wchar_t* ppsSpec, char* pps, char* lookupKeys);
void convert_enc_PPS_to_spec_chars_simple(wchar_t* ppsSpec, char* pps);
void convert_enc_plain_txt_to_spec_chars(wchar_t* plainSpec, char* binCont, char* xorBits, char* lookupKeys);
/* Decryption item removed */