#pragma once

/// @brief Error codes for library "circle"
typedef enum uk_error_e
{
	/// No error
	UK_ERROR_OK = 0,

	/// Error opening/reading file
	UK_ERROR_FILE,

	/// Empty argument
	UK_ERROR_EMPTY_ARG,

	/// Out of range
	UK_ERROR_OUT_OF_RANGE,

	/// Not enough bits
	UK_ERROR_NOT_ENOUGH_BITS

} uk_error_t;

#define UK_LENGHT 134217728 //User Key lenght 2^26
#define STRANDS_DIR "strands/"
#define _2_POW_23 8388608              //pad file standart size 2^23
#define _512_BUFFER 512                //for pads disgussing
#define _511_MASKING_BITS 511                //for pads disgussing
#define _512_BITS_TUPLE_SIZE 9                //for pads disgussing

//char uniqueness_checker[_512_BUFFER] = { 0 };

/*******************************************************************************

	Function :      trim_uk(char* u_key, char* error_desc);

	Parameters :    key -
						key string whcih we need to cut.

	Returns :       Cut user key string to 2^26 lenght

	Description :   Takes a 01's string and cuts it to 2^26.

*******************************************************************************/
char* trim_uk(char* u_key, char* error_desc);

/*******************************************************************************

	Function :      char* expand_uk(char* key, char* error_desc);

	Parameters :    key -
						key string whcih we need to extend.

	Returns :       Extended user key string up to 2^26

	Description :   Takes a 01's string and extends it up to 2^26 repetedaly
					concatenating given part.

*******************************************************************************/
char* expand_uk(char* key, char* error_desc);
void expand_uk_in(char* uk, char* key, char* error_desc);

/*Combine strands*/
void combine_strands(char* strand, char** list, size_t n);

void merge_sequences_by_content(char* result, char** list, size_t n);

void collect_logic_op_methods(char* bits, const char* str);

void do_logical_operation(char* b, char* pb, char* bd, const char* m);

void do_logical_operation_for_the_next_pad(char* b, char* pb, char* bd, const char* m);

void get_start_jump_points(char* buk, size_t* start, size_t* jump);

void create_MRS_file(char* mrs, const char* input, size_t* sp, size_t* jp);

void generate_specialchars_lookup_table(char*** finalTable, const char* bukPart, const char* mrsPart, size_t* seeker, size_t pointer_shift, size_t* size);

void generate_logical_op_data_for_program_files(char* logicalPointsArray, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset);

void generate_rearrangement_points_for_program_files(char** bukRearrangementPointsArray, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset);

void get_PPS_insertion_point(char** PPSpointStr, const char* buk, size_t offset);

void rearrange_files(char* bkr, const char* buffer, char** points);

int collect_unique_bits_for_pads_permutation(size_t* final_array, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset, char* error_desc);

void permutate_pad(char* res, char* pad, size_t pad_num, size_t* points);
/* Decryption item removed */