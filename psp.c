#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>
#include "prime.h"
#include "mem.h"
#include "spaestr.h"
#include "psp.h"

#define MRS_LEN 8388608

//TODO Do start and jump points validation
char* PSP(char* buffer, size_t startP, size_t jumpP)
{
    size_t index, contentLen, next_Prime = 0;

    /*Get the len of result content*/
    contentLen = strlen(buffer);

    char* resultBuffer = ALLOC(contentLen + 1184);
    size_t* ghost = ALLOC(1184 * sizeof(size_t)); // The PRIME GAP 1,184 	43,841,547,845,541,059
    char* ghosted;

    if (jumpP == 0 && contentLen < 100)
    {
        //jumpP = get_effective_jump_point(jumpPoint, contentLen);
        jumpP = 1;
    }
    else
    {
        validate_jump_point(&jumpP);
    }

    if (startP >= 0 && contentLen < 100)
    {
        /* Do nothing */
        ;
    }
    else
    {
        validate_start_point(&startP);
    }

    /*Assign StartPint's char to result buffer as a first symbol*/
    index = startP;
    memcpy(&resultBuffer[0], &buffer[index], 1); /*May change to 	//resultBuf[0] = result[index];	//resultBuf[1] = L'\0'; ?????*/
    resultBuffer[1] = '\0';

    //check if file size number is Prime number
    if (isPrime(contentLen) == 0)
    {
        //not a prime?
        next_Prime = nextPrime(contentLen);
        //adding some Ghost bits
        char* gBits = Str_dup("+", 1, 0, next_Prime - contentLen);

        ghosted = ALLOC(next_Prime + 1);
        memcpy(ghosted, buffer, contentLen);
        ghosted[contentLen] = '\0';
        strncat_s(ghosted, next_Prime + 1, gBits, next_Prime - contentLen);

        //strcat(ghosted, gBits);
        contentLen = next_Prime - 1;
    }
    else
    {
        ghosted = ALLOC(contentLen + 1);
        memcpy(ghosted, buffer, contentLen);
        ghosted[contentLen] = '\0';

        next_Prime = contentLen;
        contentLen--;
    }

    size_t j = 0;
    for (size_t i = 1; i <= contentLen; i++)
    {
        index = (index + jumpP) % next_Prime;
        if (ghosted[index] == '+')
        {
            ghost[j] = i;
            j++;
        }
        memcpy(&resultBuffer[i], &ghosted[index], 1);
        //resultBuf[i] = result[index];
        resultBuffer[i + 1] = '\0';
    }

    //Find and Replace all ghost symbols with empty string
    for (size_t i = 0; i < j; i++)
    {
        memcpy(&resultBuffer[ghost[i] - i], &resultBuffer[ghost[i] + 1 - i], strlen(resultBuffer) + i - ghost[i]);
    }

    FREE(ghost);
    FREE(ghosted);

    return resultBuffer;
}

void W_PSP(wchar_t* buffer, size_t startP, size_t jumpPoint)
{
    size_t index, next_Prime = 0, contentLen, contentBaseLen;

    /*Get the len of result content*/
    contentBaseLen = contentLen = wcslen(buffer);

    startP = startP % contentLen;
    size_t jumpP = jumpPoint % contentLen;

    if (jumpP == 0 && contentLen < 100)
    {
        //jumpP = get_effective_jump_point(jumpPoint, contentLen);
        jumpP = 1;
    }
    else
    {
        validate_jump_point(&jumpP);
    }

    if (startP >= 0 && contentLen < 100)
    {
        /* Do nothing */
        ;
    }
    else
    {
        validate_start_point(&startP);
    }

    wchar_t* resultBuffer = ALLOC((sizeof(wchar_t) * (contentLen + 1184)));
    size_t* ghost = ALLOC(1184 * sizeof(size_t)); // The PRIME GAP 1,184 	43,841,547,845,541,059
    wchar_t* ghosted = NULL;


    /*Assign StartPint's char to result buffer as a first symbol*/
    index = startP;
    wmemcpy(&resultBuffer[0], &buffer[index], 1); /*May change to 	//resultBuf[0] = result[index];	//resultBuf[1] = L'\0'; ?????*/
    resultBuffer[1] = L'\0';

    //check if file size number is Prime number
    if (isPrime(contentLen) == 0)
    {
        //not a prime?
        next_Prime = nextPrime(contentLen);
        //adding some Ghost bits
        wchar_t* gBits = W_Str_dup(L"+", 1, 0, next_Prime - contentLen);

        ghosted = ALLOC(sizeof(wchar_t) * (next_Prime + 1));
        wmemcpy_s(ghosted, next_Prime + 1, buffer, contentLen);
        ghosted[contentLen] = L'\0';

        wcsncat_s(ghosted, next_Prime + 1, gBits, next_Prime - contentLen);
        contentLen = next_Prime - 1;

        FREE(gBits);
    }

    else
    {
        ghosted = ALLOC((sizeof(wchar_t) * (contentLen + 1)));
        wmemcpy(ghosted, buffer, contentLen);
        ghosted[contentLen] = '\0';

        next_Prime = contentLen;
        contentLen--;
    }

    size_t j = 0;
    for (size_t i = 1; i <= contentLen; i++)
    {
        index = (index + jumpP) % next_Prime;
        if (ghosted[index] == '+')
        {
            ghost[j] = i;
            j++;
        }
        wmemcpy(&resultBuffer[i], &ghosted[index], 1);
    }
    resultBuffer[contentLen + 1] = L'\0';

    //Find and Replace all ghost symbols with empty string
    for (size_t i = 0; i < j; i++)
    {
        wmemcpy(&resultBuffer[ghost[i] - i], &resultBuffer[ghost[i] + 1 - i], wcslen(resultBuffer) + i - ghost[i]);
    }

    wmemcpy(buffer, resultBuffer, contentBaseLen);
    buffer[contentBaseLen] = L'\0';

    FREE(ghost);
    FREE(ghosted);
    FREE(resultBuffer);
}

/* Decryption item removed */

/* Decryption item removed */

/* Decryption item removed */

void validate_jump_point(size_t* jp)
{
    if (*jp <= 0)
    {
        *jp += 100;
    }
}

void validate_start_point(size_t* sp)
{
    if (*sp <= 0)
    {
        *sp += 100;
    }
}

/* Decryption item removed */

/* Decryption item removed */