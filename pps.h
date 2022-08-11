#pragma once
#ifndef PPS_LIB_H
#define PPS_LIB_H

#include <string.h>
#include "mem.h"

#define PPS_CHARS_COUNT 7
#define PPS_STRUCT_RAW_LEN 2870 // ppp_ch_count x pps_insetion_pos_len + full lookup table for each char

typedef struct {
    char* charInsertionPos;
    char** lookupTbl;
} pps_t;

// pps_t prototypes.

pps_t* pps_new(void);

void pps_set(pps_t* p, const char* position, const char** tbl);

void pps_struct_into_array(char* ppsData, pps_t* pps);

void pps_get_nth_position(char* pos, size_t n, char* data);

void pps_get_nth_lookup_tbl(char* tbl, size_t n, char* data);

void pps_free(pps_t* p);


#endif