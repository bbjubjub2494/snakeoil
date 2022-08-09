#include "spaestr.h"

#define idx(i, len) ((i) <= 0 ? (i) + (len) : (i) - 1)
#define convert(s, i, j) do { size_t len; \
	assert(s); len = strlen(s); \
	i = idx(i, len); j = idx(j, len); \
	if (i > j) { size_t t = i; i = j; j = t; } \
	assert(i >= 0 && j <= len); } while (0)

#define wconvert(s, i, j) do { size_t len; \
	assert(s); len = wcslen(s); \
	i = idx(i, len); j = idx(j, len); \
	if (i > j) { size_t t = i; i = j; j = t; } \
	assert(i >= 0 && j <= len); } while (0)

char* Str_sub(const char* s, size_t i, size_t j) {
	char* str, * p;
	convert(s, i, j);
	p = str = ALLOC((long)(j - i + 1));
	while (i < j)
		*p++ = s[i++];
	*p = '\0';
	return str;
}

char* spae_substr(const char* str, size_t start, size_t length)
{
	char* _substr;

	size_t len = strlen(str);
	assert(start >= 0 && length <= len && (start + length) <= len && "Hey, you are trying to get more then possible!");

	//aloc mem
	_substr = ALLOC((long)(length + 1) * sizeof(char));

	if (_substr != NULL)
	{
		strncpy_s(_substr, length + 1, str + start, length);
		//finalize adding ending null
		_substr[length] = '\0';
	}

	return _substr;
}

char* Str_dup(const char* s, size_t i, size_t j, size_t n) {
	size_t k;
	char* str, * p;
	assert(n >= 0);
	convert(s, i, j);
	p = str = ALLOC((long)(n * (j - i) + 1));
	if (j - i > 0)
		while (n-- > 0)
			for (k = i; k < j; k++)
				*p++ = s[k];
	*p = '\0';
	return str;
}

wchar_t* W_Str_dup(const wchar_t* s, size_t i, size_t j, size_t n) {
	size_t k;
	wchar_t* str, * p;
	assert(n >= 0);
	wconvert(s, i, j);
	p = str = ALLOC((long)(sizeof(wchar_t) * (n * (j - i) + 1)));
	if (j - i > 0)
		while (n-- > 0)
			for (k = i; k < j; k++)
				*p++ = s[k];
	*p = '\0';
	return str;
}

wchar_t* wsub_string(wchar_t* string, size_t position, size_t length)
{
	wchar_t* pointer;
	int c;

	pointer = ALLOC((long)(sizeof(wchar_t) * (length + 1)));
	//pointer = (wchar_t*)malloc(sizeof(wchar_t) * length + 1);

	if (pointer == NULL)
		exit(EXIT_FAILURE);

	for (c = 0; c < length; c++)
		*(pointer + c) = *((string + position - 1) + c);

	*(pointer + c) = '\0';

	return pointer;
}

void insert_substring(wchar_t* res, wchar_t* a, wchar_t* b, size_t position)
{
	wchar_t* f, * e;
	size_t length, len_b;

	length = wcslen(a);
	len_b = wcslen(b);

	f = wsub_string(a, 1, position);
	e = wsub_string(a, position + 1, length - position + 1);

	wcscpy_s(res, length + len_b + 1, L"");
	wcsncat_s(res, length + len_b + 1, f, position);
	//free(f);
	wcsncat_s(res, length + len_b + 1, b, len_b);
	wcsncat_s(res, length + len_b + 1, e, length - position);
	//free(e);
}

size_t repl_wcs(wchar_t* line, const wchar_t* search, const wchar_t* replace)
{
	size_t count;
	wchar_t* sp; // start of pattern

	//printf("replacestr(%s, %s, %s)\n", line, search, replace);
	if ((sp = wcsstr(line, search)) == NULL) {
		return(0);
	}
	count = 1;
	size_t sLen = wcslen(search);
	size_t rLen = wcslen(replace);
	if (sLen > rLen) {
		// move from right to left
		wchar_t* src = sp + sLen;
		wchar_t* dst = sp + rLen;
		while ((*dst = *src) != '\0') { dst++; src++; }
	}
	else if (sLen < rLen) {
		// move from left to right
		size_t tLen = wcslen(sp) - sLen;
		wchar_t* stop = sp + rLen;
		wchar_t* src = sp + sLen + tLen;
		wchar_t* dst = sp + rLen + tLen;
		while (dst >= stop) { *dst = *src; dst--; src--; }
	}
	wmemcpy(sp, replace, rLen);

	count += repl_wcs(sp + rLen, search, replace);

	return(count);
}