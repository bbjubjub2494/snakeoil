#pragma once
#include <stdarg.h>
#include <string.h>
#include <limits.h>

#include "assert.h"
#include "mem.h"
#include "helper.h"

extern char* Str_sub(const char* s, size_t i, size_t j);
extern char* Str_dup(const char* s, size_t i, size_t j, size_t n);
extern wchar_t* W_Str_dup(const wchar_t* s, size_t i, size_t j, size_t n);

void insert_substring(wchar_t* res, wchar_t* a, wchar_t* b, size_t position);
wchar_t* wsub_string(wchar_t* string, size_t position, size_t length);
size_t repl_wcs(wchar_t* line, const wchar_t* search, const wchar_t* replace);
char* spae_substr(const char* str, size_t start, size_t length);