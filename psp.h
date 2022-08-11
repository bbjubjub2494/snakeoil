#pragma once
char* PSP(char* buffer, size_t startP, size_t jumpP);
void W_PSP(wchar_t* buffer, size_t startP, size_t jumpP);
wchar_t* reverse_PSP_decr(wchar_t* buffer, size_t startP, size_t jumpPoint);
/* Decryption item removed */
void validate_jump_point(size_t* jp);
void validate_start_point(size_t* sp);

/* Decryption item removed */