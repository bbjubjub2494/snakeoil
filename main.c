#pragma warning(disable : 4996)
#include "main.h"
#include "encryption.h"

const size_t SEEK_NUMBER = 138;

int inline is_wstring_empty(wchar_t* s);

size_t inline howManyFullPadsIsIt(size_t bitsCount)
{
    return bitsCount / PAD_LEN;
}

size_t inline get_used_bits_count_of_part_pad(size_t ub)
{
    return ub % PAD_LEN;
}

size_t inline get_available_bits_count_of_part_pad(size_t ub)
{
    return PAD_LEN - get_used_bits_count_of_part_pad(ub);
}

SPAE_DLL_EXPIMP char* SPAE_CALL convert_uk_to_bin(wchar_t* data, char* error_desc)
{
    const size_t length = wcslen(data);

    /* If empty string given */
    if (0 == length)
    {
        strcpy_s(error_desc, 256, "\nWhen trying to convert User Key to binary. Empty data given as an input value.\n");
        return NULL;
    }

    // Convert spec chars to six bits 
    char* bin_content = convert_spec_char_to_binary_for_uk(data);

    // Len of binary string must be exactly equal to (6 * length)!!!
    // Otherwise it means there where some issue when converting spec to 6-bits
    const size_t bin_len = strlen(bin_content);

    // Check if converting op went ok
    if (bin_len != (6 * length))
    {
        strcpy_s(error_desc, 256, "\nWhen trying to convert User Key to binary. There is an issue when converting spec-chars to 6-bits.\n");
        return NULL;
    }

    return bin_content;
}

SPAE_DLL_EXPIMP char* SPAE_CALL create_uk(char* key, char* error_desc)
{
    size_t keyLen = 0;
    keyLen = strlen(key);

    // if data is NULL or empty
    if (keyLen <= 0)
    {
        strcpy_s(error_desc, 256, "\nEmpty data given as an input value when User Key should be created.\n");
        return NULL;
    }

    // if potential key len is less than 2^26 we shall to exapnd it
    if (keyLen < UK_LENGHT)
    {
        return expand_uk(key, error_desc);
    }

    // if potential key len is more than 2^26 we shall to trunc it
    if (keyLen > UK_LENGHT)
    {
        return trim_uk(key, error_desc);
    }

    // otherwise if len is exactly the same as 2^26 just return it
    return key;
}

SPAE_DLL_EXPIMP wchar_t* SPAE_CALL sanitize_uk_file(wchar_t* user_file, int* wrong_chars_count, char* error_desc)
{
    size_t offset = 0;
    size_t tmp = 0;

    // Our spec chars white list. u2020 is our DAGGER!
    static wchar_t whitelist_chars[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\u2020/";

    wchar_t* f_content = NULL;
    size_t   content_size = 0;
    int      read_status;
    int      open_status;

    // Accept the file and try to open it
    FILE* f = NULL;

    // Trying to open the file in read mode
    f = w_open_file(user_file, FILE_MODE_READ, &open_status);

    // Check file opening status
    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file for sanitizing in order to use us UK.\n");
        return NULL;
    }

    // Fail to set mode to UTF 
    if (-1 == set_file_mode_to_utf(&f))
    {
        strcpy_s(error_desc, 256, "\nError: When trying to set file mode to UTF.\n");
        return NULL;
    }

    // Read whole file content into memory 
    f_content = wc_read_file(f, &read_status, &content_size);

    if (read_status)
    {
        strcpy_s(error_desc, 256, "Error opening or reading a file.");
        return NULL;
    }

    // Check if there were some content but useful content was empty
    if (is_wstring_empty(f_content) == 1)
    {
        strcpy_s(error_desc, 256, "\nError: empty data submitted. Pls, check!\n");
        return NULL;
    }

    wchar_t* result = ALLOC(content_size + 2);
    wchar_t* cp = f_content; /* Cursor into string */
    const wchar_t* end = f_content + wcslen(f_content);

    size_t index = wcsspn(cp, whitelist_chars);
    if (index == wcslen(cp))
    {
        return cp;
    }

    for (cp += index; cp != end; cp += wcsspn(cp, whitelist_chars))
    {
        cp++; /* We are skipping bad char */

        wmemcpy(result + offset, f_content + tmp, index);
        offset += index;
        tmp += (index + 1);
        index = wcsspn(cp, whitelist_chars);
        wmemcpy(result + offset, f_content + tmp, index);
        *wrong_chars_count += 1;
    }

    result[offset + index] = '\0';
    //result[offset] = '\0';
    return result;
}

SPAE_DLL_EXPIMP wchar_t* SPAE_CALL sanitize_uk_file_content(wchar_t* content, int* wrong_chars_count, char* error_desc)
{
    size_t offset = 0;
    size_t tmp = 0;

    static wchar_t whitelist_chars[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\u2020/";

    size_t   content_size = 0;

    // Check if there were some content but useful content was empty
    if (is_wstring_empty(content) == 1)
    {
        strcpy_s(error_desc, 256, "\nError: empty data submitted. Pls, check!\n");
        return NULL;
    }
    else
    {
        content_size = wcslen(content);
    }

    wchar_t* result = ALLOC(content_size + 2);

    wchar_t* cp = content; /* Cursor into string */
    const wchar_t* end = content + wcslen(content);

    size_t index = wcsspn(cp, whitelist_chars);
    if (index == wcslen(cp))
    {
        return cp;
    }

    for (cp += index; cp != end; cp += wcsspn(cp, whitelist_chars))
    {
        cp++; /* We are skipping bad char */

        wmemcpy(result + offset, content + tmp, index);
        offset += index;
        tmp += (index + 1);
        index = wcsspn(cp, whitelist_chars);
        wmemcpy(result + offset, content + tmp, index);
        *wrong_chars_count += 1;
    }

    result[offset + index] = '\0';
    return result;
}



SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circles_info(struct circle* data, int size, char* error_descr)
{
    FILE* fp1 = NULL;

    fopen_s(&fp1, CIRCLE_FILE_NAME, "rb");
    if (fp1 == NULL)
    {
        strcpy_s(error_descr, 256, "\nError opening Circle config file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    /* Check if file exists but contains no any data. */
    if (0 == is_file_empty(fp1))
    {
        strcpy_s(error_descr, 256, "\nThere is no any Circle to show.\n");
        fclose(fp1);

        return CIRCLE_ERROR_FILE_EMPTY;
    }

    if (data != NULL)
    {
        struct circle buffer;
        fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file

        int i = 0; // Will store circles count
        while (fread(&buffer, CIRCLE_SIZE, 1, fp1) == 1)
        {
            if (buffer.master) // We must see only records which master = 1, since this value indicates circle "head".
            {
                memcpy(data + i, &buffer, CIRCLE_SIZE * 1);
                i++;
            }
        }

        // If nothing found in the cfg file
        if (0 == i)
        {
            strcpy_s(error_descr, 256, "There is something wrong or corrupted in Circle config file.");
            fclose(fp1);

            return CIRCLE_ERROR_FILE_CURRUPT;
        }
    }
    else
    {
        fclose(fp1);
        return CIRCLE_ERROR_NOMEM;
    }

    fclose(fp1);
    return CIRCLE_ERROR_OK;
}

SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circle_members_data(struct member* data, int size, const char* c_name, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* fp1 = NULL;
    /*Trying to open the file*/
    fp1 = open_file(CIRCLE_FILE_NAME, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open Circle cfg file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    if (data != NULL)
    {
        struct circle buffer;

        fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file

        int i = 0;
        while (fread(&buffer, CIRCLE_SIZE, 1, fp1) == 1)
        {
            if (strcmp(c_name, buffer.circle_name) == 0)
            {
                memcpy(data + i, &buffer.mbr, sizeof(struct member) * 1);
                i++;
            }
        }
        // If nothing found in the cfg file
        if (0 == i)
        {
            strcpy_s(error_desc, 256, "Circle has not any member or Circle config file is corrupted.");
            fclose(fp1);
            return CIRCLE_ERROR_FILE_CURRUPT;
        }
    }
    else
    {
        fclose(fp1);
        return CIRCLE_ERROR_NOMEM;
    }

    fclose(fp1);
    return CIRCLE_ERROR_OK;
}


SPAE_DLL_EXPIMP int SPAE_CALL get_circles_count(char* error_descr)
{
    int circles_c = 0;

    FILE* fp1 = NULL;
    fopen_s(&fp1, CIRCLE_FILE_NAME, "rb");
    if (fp1 == NULL)
    {
        strcpy_s(error_descr, 256, "Cannot open Circles config file.");
        return CIRCLE_ERROR_OPENF;
    }

    /* Check if file exists but contains no any data. */
    if (0 == is_file_empty(fp1))
    {
        strcpy_s(error_descr, 256, "Circle config file exists but it is empty.");
        //return CIRCLE_ERROR_FILE_EMPTY;
        fclose(fp1);
        return circles_c;
    }

    struct circle buffer;
    fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(buffer), 1, fp1) == 1)
    {
        if (buffer.master)
        {
            ++circles_c;
        }
    }

    fclose(fp1);
    return circles_c;
}

SPAE_DLL_EXPIMP int SPAE_CALL get_circle_members_count(const char* c, char* error_desc)
{
    int members_c = 0;
    int open_status;

    // Accept the file and try to open it
    FILE* fCircleCfg = NULL;
    fCircleCfg = open_file(CIRCLE_FILE_NAME, FILE_MODE_READ, &open_status);

    // Check open file status
    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Circle cfg file.\n");
        return 0;
    }

    // Start to read
    struct circle buffer;
    fseek(fCircleCfg, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(buffer), 1, fCircleCfg) == 1)
    {
        if (strcmp(c, buffer.circle_name) == 0)
        {
            members_c++;
        }
    }

    fflush(fCircleCfg);
    fclose(fCircleCfg);

    return members_c;
}

SPAE_DLL_EXPIMP int SPAE_CALL check_if_circle_locked(const char* c_name, char* error_desc)
{
    int is_locked = 0; //not locked

    // Check if Circle locked
    is_locked = is_circle_locked(c_name, error_desc);

    return is_locked;
}

SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circle_data_by_name(struct circle* data, const char* c_name, char* error_desc)
{
    int open_status;

    // Accept the file and try to open it
    FILE* fp1 = NULL;
    // Trying to open the file
    fp1 = open_file(CIRCLE_FILE_NAME, FILE_MODE_READ, &open_status);
    // Chek open file status
    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Circle cfg file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    if (data != NULL)
    {
        struct circle buffer;

        fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file

        while (fread(&buffer, CIRCLE_SIZE, 1, fp1) == 1)
        {
            if (strcmp(c_name, buffer.circle_name) == 0 && buffer.master == 1)
            {
                memcpy(data, &buffer, CIRCLE_SIZE * 1);

                fclose(fp1);
                return CIRCLE_ERROR_OK;
            }
        }
    }
    else
    {
        fclose(fp1);
        return CIRCLE_ERROR_NOMEM;
    }

    fclose(fp1);
    return CIRCLE_ERROR_OK;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL get_pad_cfg_head(struct pads* data, const char* cfg_path, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* fp1 = NULL;
    /*Trying to open the file*/
    fp1 = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }
    size_t ret_code = fread(data, PADS_STRUCT_SIZE, 1, fp1);

    /*If error*/
    if (ret_code != PADS_STRUCT_SIZE) {
        if (feof(fp1))
        {
            fclose(fp1);
            strcpy_s(error_desc, 256, "\nError reading pad config file: unexpected end of file.\n");
            exit(EXIT_FAILURE);
        }
        else if (ferror(fp1))
        {
            fclose(fp1);
            strcpy_s(error_desc, 256, "\nError reading pad config\n");
            exit(EXIT_FAILURE);
        }
    }

    fclose(fp1);
    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_valid_pads_count(const char* cfg_path, int vpc, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.valid_pads = vpc;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fflush(nf);
    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_invalid_pads_count(const char* cfg_path, int ipc, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.invalid_pads = ipc;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    fflush(nf);
    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_generated_pads_count_into_cfg_head(const char* cfg_path, int gc, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.generated_pads = gc;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fflush(nf);
    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_new_request_data_into_cfg_head(const char* cfg_path, int total, int generated, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.total_count = total;
    pads_head_data.generated_pads = generated;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fflush(nf);
    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_single_pad(char* pad, char* mrs, char* buk, char* prog_dir, char* error_desc)
{
    /*                                                                   */
    /*    Generate Spec Chars Lookup tbl                                 */
    /*                                                                   */
    size_t seeker = 0;
    size_t offset = 0;
    size_t shift = 368;
    size_t s     = 0;

    size_t* first_pads_disgussing_bits = ALLOC(_512_BUFFER * sizeof(size_t));
    collect_unique_bits_for_pads_permutation(first_pads_disgussing_bits, buk, mrs, &seeker, offset + shift, error_desc);

    offset = seeker;
    seeker = 0;

    char*** lookupTbl = ALLOC(72 * sizeof(char**)); //was 64(must be 65 at least)
    generate_specialchars_lookup_table(lookupTbl, buk, mrs, &seeker, offset, &s);

    //multiply by 6 since for chars we were used six bits
    offset += seeker * 6;
    seeker = 0;

    /*                                                                   */
    /*    Collect logical operation methods for 64 prog files            */
    /*                                                                   */
    char* logicalMethodsForProgFiles = ALLOC(64 * sizeof(char));
    generate_logical_op_data_for_program_files(logicalMethodsForProgFiles, buk, mrs, &seeker, offset);
    /*                                                                   */
    /*    REARRANGEMENT POINTS FOR BASE USER KEY SEQ's                   */
    /*    Since during above step we used $seeker * 6 bits from every seq*/
    /*    getting new offset so, the next offset point will be           */
    /*                                                                   */
    offset += seeker;
    seeker = 0;

    char** rearrangementPointsArray = ALLOC(16 * sizeof(char*));
    generate_rearrangement_points_for_program_files(rearrangementPointsArray, buk, mrs, &seeker, offset);

    /*                                                                   */
    /*    PSP START/JUMP POINTS FOR MRS SEQ's                            */
    /*                                                                   */
    offset += seeker * 23;
    seeker = 0;

    char** pointPPS = ALLOC(7 * sizeof(char*));
    get_PPS_insertion_point(pointPPS, buk, offset);

    /*                                                                   */
    /*    Rearrange BUK files                                            */
    /*                                                                   */

    char* bukr = ALLOC(UK_LENGHT + 1);
    rearrange_files(bukr, buk, rearrangementPointsArray);

    /*-------------------------------------------FIRST PAD--------------------------------------------------------*/
                /*                                                                   */
                /*    Collect Start&Jump points for the next pad                     */
                /*                                                                   */

    /*                                                                   */
    /*    XOR/XNOR -ing base MRS files with base User Key files and      */
    /*    make ROW files.                                                */
    /*    Collect Logicical Op Methods for BUK generating                */
    /*                                                                   */
    char rowLogicMethods[8] = { 0 };
    collect_logic_op_methods(rowLogicMethods, mrs);

    char* row = CALLOC(UK_LENGHT + 1, 1);
    do_logical_operation(row, mrs, bukr, rowLogicMethods);

    char* tmp_pad = ALLOC(_2_POW_23 + 1);
    make_single_pad(tmp_pad, row);

    permutate_pad(pad, tmp_pad, 1, first_pads_disgussing_bits);

    /* Reset transposition array */
    ZERO_ANY(size_t, pads_disgussing_bits, _512_BUFFER);

    FREE(tmp_pad);

    pps_t* _pps_ptr;

    // allocating memory for n numbers of struct person
    _pps_ptr = (pps_t*)ALLOC(7 * sizeof(pps_t));
    for (size_t i = 0; i < 7; i++)
    {
        pps_set(_pps_ptr + i, pointPPS[i], lookupTbl[PROG_FILES_COUNT + i]);
    }
    
    /* Marshaling struct into array */
    /* Allocated memory size is: ppp_ch_count x pps_insetion_pos_len + full lookup table for each char */
    char* ppsData = (char*)ALLOC(sizeof(char)*(PPS_CHARS_COUNT * 26 + PPS_CHARS_COUNT * 64 * 6) + 1);
    pps_struct_into_array(ppsData, _pps_ptr);
    pps_free(_pps_ptr); //Be careful here!!!
    create_64_prog_files(pad, lookupTbl, ppsData, logicalMethodsForProgFiles, prog_dir, error_desc);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL reset_pad_cfg_file(char* path)
{
    FILE* f;

    fopen_s(&f, path, "wb");
    if (f == NULL) {
        printf("error in opening file : \n");
        exit(EXIT_FAILURE);
    }

    struct pads p = { 0 };
    fwrite(&p, sizeof(struct pads), 1, f);

    struct pad pd;
    memset(&pd, 0, sizeof(struct pad));

    fflush(f);
    fclose(f);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL combine_strands_into_sequence(char* combined_seq, char* strands_dir, char* error_desc)
{
    /*                                                                   */
    /*    Get strands list                                               */
    /*                                                                   */

    // Number of returned files. For strands it alwasy should be exactly 8
    size_t n = 0;
    char** list = dirlist(strands_dir, "txt", &n);
    // Die if number is more or less than 8.
    if (n != STRANDS_COUNT)
    {
        strcpy_s(error_desc, 256, "\nError: Pls, check strands count.\n");
        return PADS_ERROR_STRANDS;
    }

    char** strands_list_full_path = ALLOC(STRANDS_COUNT * sizeof(char*));
    for (size_t i = 0; i < STRANDS_COUNT; i++)
    {
        strands_list_full_path[i] = build_file_full_path(strands_dir, list[i]);
    }

    /*                                                                   */
    /*    Combine strands into one large string. At the end we are free  */
    /*    list memory.                                                   */
    /*                                                                   */
    combine_strands(combined_seq, strands_list_full_path, n);

    FREE(strands_list_full_path);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL make_buk_file(char* buk, char* uk_str, char* strands, char* error_desc)
{
    /*                                                                   */
    /*    Collect Logicical Op Methods for BUK generating                */
    /*                                                                   */
    char bukLogicMethods[8] = { 0 };
    collect_logic_op_methods(bukLogicMethods, uk_str);

    /*                                                                   */
    /*    Make XOR or XNOR and generate BUK files                        */
    /*                                                                   */

    do_logical_operation(buk, uk_str, strands, bukLogicMethods);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL make_mrs_file(char* mrs, char* buk, char* strands, char* error_desc)
{
    /*                                                                   */
    /*    Collect Start&Jump points                                      */
    /*                                                                   */
    size_t startPoints[8] = { 0 };
    size_t jumpPoints[8] = { 0 };

    get_start_jump_points(buk, startPoints, jumpPoints);

    /*                                                                   */
    /*    Create MRS files                                               */
    /*                                                                   */

    create_MRS_file(mrs, strands, startPoints, jumpPoints);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP char*** SPAE_CALL generate_special_chars_lookup_table(char* buk, char* mrs, size_t* seeker, char* error_desc)
{
    char*** tbl = ALLOC(64 * sizeof(char**));
    char** uniqueTuple = ALLOC(128 * sizeof(char*));
    char tmpUniqueTuple[16][7] = { 0 };

    size_t offset = 0;
    size_t count = 0;
    size_t size = 0;

    while (size < 65)
    {
        size_t pointerPosition = 0;

        for (size_t i = 0; i < 8; i++)
        {
            memcpy(tmpUniqueTuple[i * 2], buk + pointerPosition + *seeker * 6, 6);
            tmpUniqueTuple[i * 2][6] = '\0';

            memcpy(tmpUniqueTuple[i * 2 + 1], mrs + pointerPosition + *seeker * 6, 6);
            tmpUniqueTuple[i * 2 + 1][6] = '\0';


            pointerPosition += _2_POW_23;
        }
        offset += 6;
        for (size_t i = 0; i < 16; i++)
        {
            uniqueTuple[count + i] = ALLOC(8 * sizeof(char));
            memcpy(uniqueTuple[count + i], tmpUniqueTuple[i], sizeof(*tmpUniqueTuple));
            uniqueTuple[count + i][6] = '\0';
        }

        count = arrayUniqueWithoutSorting(uniqueTuple, count + 16);

        if (count >= 64)
        {
            tbl[size] = ALLOC(64 * sizeof(char*));

            for (size_t i = 0; i < 64; i++)
            {

                tbl[size][i] = ALLOC(6 * sizeof(char));

                memcpy(tbl[size][i], uniqueTuple[i], 6);
                tbl[size][i][6] = '\0';
                uniqueTuple[i] = NULL;
            }
            size++;
            count = 0;
        }

        (*seeker)++;
    }
    return tbl;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL generate_data_for_the_next_pad(char* buk, char* mrs, char* bukr, char* pmrs, size_t* sp, size_t* jp, size_t* rp, char* error_desc)
{
    size_t size = 0, pspStartPoint = 0, pspJumpPoint = 0, rP = 0, offset = 0;

    char* singlePSPdata = ALLOC(sizeof(char) * 46 + 1);
    char* singleReStr = ALLOC(sizeof(char) * 23 + 1);

    for (size_t i = 0; i < 8; i++)
    {
        /* Collect PSP points */
        memcpy(singlePSPdata, pmrs + offset, 46);
        singlePSPdata[46] = '\0';

        pspStartPoint = bindec(spae_substr(singlePSPdata, 0, 23));
        pspJumpPoint = bindec(spae_substr(singlePSPdata, 23, 23));
        sp[size] = pspStartPoint;
        jp[size] = pspJumpPoint;

        /* Collect rearranging points */
        
        memcpy(singleReStr, bukr + offset, 23);
        singleReStr[23] = '\0';

        rP = bindec(spae_substr(singleReStr, 0, 23));
        rp[size] = rP;

        size++;
        offset += _2_POW_23;
    }

    int is_empty_array = is_array_set_to_zero(pads_disgussing_bits, _512_BUFFER);

    if (is_empty_array == 0)
    {
        size_t shift = 368;
        size_t seeker = 0;

        collect_unique_bits_for_pads_permutation(pads_disgussing_bits, buk, mrs, &seeker, shift, error_desc);
    }

    FREE(singlePSPdata);
    FREE(singleReStr);

    return PADS_ERROR_OK;
}

/*                                                                   */
/*    XOR/XNOR -ing base MRS files with base User Key files and      */
/*    make ROW files.                                                */
/*    Collect Logicical Op Methods for BUK generating                */
/*                                                                   */
SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_pad(char* pad, char* mrs, char* bukr, char* error_desc)
{
    char rowLogicMethods[8] = { 0 };
    collect_logic_op_methods(rowLogicMethods, mrs);

    char* row = CALLOC(UK_LENGHT + 1, 1);
    do_logical_operation(row, mrs, bukr, rowLogicMethods);

    make_single_pad(pad, row);

    FREE(row);
    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL validate_pad(char* pad, char* error_desc)
{
    if (strlen(pad) != _2_POW_23)
    {
        strcpy_s(error_desc, 256, "\nError: Pad len is not equal to 8388608.\n");
        return 0;
    }
    else
    {
        const size_t ones_count = get_ones_count_in_file(pad);
        if (is_number_in_1SD_range(ones_count))
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
}

SPAE_DLL_EXPIMP int SPAE_CALL validate_pad_by_first_42bits(char* pad, char* cfg_path, char* error_desc)
{
    struct pad p;

    char* pps = ALLOC(sizeof(char) * 43);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    int open_status;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    memcpy_s(pps, 43, pad, 42);
    pps[42] = '\0';

    fseek(nf, sizeof(struct pads), SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&p, sizeof(struct pad), 1, nf) == 1)
    {
        if (strcmp(pps, p.pps) == 0)
        {
            fflush(nf);
            fclose(nf);

            return 1; // Pad is invalid - there is an PPS in prev Pads with the same bits
        }
    }

    fflush(nf);
    fclose(nf);

    FREE(pps);
    return 0;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL write_pad_into_file(char* pad, char* path, int id, char* error_desc)
{
    char* padFullPath = CALLOC(sizeof(char) * _MAX_PATH, 1);
    char* padName = ALLOC(sizeof(char) * 7);

    // Building the pad path
    _ui64toa_s(id, padName, 7, 10);                // converting pad's # from inti to char
    strcat_s(padFullPath, _MAX_PATH + 1, path);    // Pads dir
    strcat_s(padFullPath, _MAX_PATH + 1, "/");     // Add backslash
    strcat_s(padFullPath, _MAX_PATH + 1, padName); // Concatenate pad # num
    strcat_s(padFullPath, _MAX_PATH + 1, ".txt");  // Add extenssion

    int open_status;

    /*Accept the file and try to open it*/
    FILE* f_pad = NULL;
    /*Trying to open the file*/
    f_pad = open_file(padFullPath, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Pad file for writing.\n");
        return PADS_ERROR_OPENFILE;
    }
    else
    {
        fwrite(pad, sizeof(char), _2_POW_23, f_pad);

        fflush(f_pad);
        fclose(f_pad);

        return PADS_ERROR_OK;
    }
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL add_new_pad_block(char* pad, char* buk, char* mrs, char* cfg_path, int current_pad_id, int prev_pad_id, char* error_desc)
{
    struct pad n_p = { 0 };
    n_p = collect_data_about_next_pad(pad, buk, mrs, current_pad_id, prev_pad_id, error_desc);
    FILE* f;

    fopen_s(&f, cfg_path, "ab+");
    if (f == NULL)
    {
        strcpy_s(error_desc, 256, "\nError: error in opening file for adding new Pad blcok!\n");
        return PADS_ERROR_OPENFILE;
    }

    /* Write/append the next generated pad block */
    fwrite(&n_p, PAD_STRUCT_SIZE, 1, f);

    fflush(f);
    fclose(f);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL rearrange_next_pad_BUK_file(char* bukr, const char* buk, size_t* rearrange_points, char* error_desc)
{
    size_t offset = 0;

    for (size_t i = 0; i < 8; i++)
    {
        size_t point = rearrange_points[i];
        if (_2_POW_23 < point) {
            point = point % _2_POW_23;
        }

        memcpy(bukr + offset, buk + offset + point, _2_POW_23 - point);
        memcpy(bukr + offset + _2_POW_23 - point, buk + offset, point);

        offset += _2_POW_23;
    }

    bukr[offset] = '\0';

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL permutate_next_pad_MRS_file(char* pmrs, const char* mrs, size_t* start_points, size_t* jump_points, char* error_desc)
{
    size_t offset = 0;
    char* tmp = ALLOC(sizeof(char) * _2_POW_23 + 1);

    for (size_t i = 0; i < 8; i++)
    {
        memcpy(tmp, mrs + offset, _2_POW_23);
        tmp[_2_POW_23] = '\0';
        char* psp = PSP(tmp, start_points[i], jump_points[i]);
        memcpy(pmrs + offset, psp, _2_POW_23);

        offset += _2_POW_23;

        FREE(psp);
    }
    pmrs[offset] = '\0';
    FREE(tmp);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_next_row_file(char* next_row, char* bukr, char* pmrs, const char* prev_pad, char* error_desc)
{

    /*                                                                   */
    /*    Collect Logicical Op Methods                                   */
    /*                                                                   */
    char preROWLogicMethods[8] = { 0 };

    collect_logic_op_methods(preROWLogicMethods, pmrs);

    /*                                                                   */
    /*    Make XOR Logical operation with PRE_ROW files and Prev. pad    */
    /*                                                                   */
    char* preROW = CALLOC(UK_LENGHT + 1, 1);

    do_logical_operation(preROW, bukr, pmrs, preROWLogicMethods);

    int open_status;

    /*Accept the file and try to open it*/
    FILE* prev_p = NULL;
    /*Trying to open the file*/
    prev_p = open_file(prev_pad, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open prev Pad file.\n");
        return PADS_ERROR_OPENFILE;
    }

    char* fContent;
    size_t contentSize = 0;
    int readStatus;

    fContent = c_read_file(prev_p, &readStatus, &contentSize);
    if (readStatus > 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to read prev Pad file.\n");
        return PADS_ERROR_READFILE;
    }

    fclose(prev_p);

    do_logical_operation_for_the_next_pad(next_row, preROW, fContent, preROWLogicMethods);

    FREE(preROW);
    FREE(fContent);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL generate_single_pad(char* pad, size_t pad_num, char* row, char* error_desc)
{
    char* temp = ALLOC(_2_POW_23 + 1);
    size_t offset = _2_POW_23, step = 1;

    char* tmp_pad = ALLOC(_2_POW_23 + 1);

    for (size_t i = 0; i < 7; i++)
    {
        if (step == 1)
        {
            memcpy(tmp_pad, row, _2_POW_23);
            tmp_pad[_2_POW_23] = '\0';
            memcpy(temp, row + offset, _2_POW_23);
            temp[_2_POW_23] = '\0';
            fmakeXOR(tmp_pad, temp);

            step++;
            offset += _2_POW_23;
        }
        else
        {
            memcpy(temp, row + offset, _2_POW_23);
            fmakeXOR(tmp_pad, temp);

            step++;
            offset += _2_POW_23;
        }
    }

    int is_empty_array = is_array_set_to_zero(pads_disgussing_bits, _512_BUFFER);

    if (is_empty_array == 0)
    {
        memcpy_s(pad, _2_POW_23 + 1, tmp_pad, _2_POW_23);
        tmp_pad[_2_POW_23] = '\0';
    }
    else
    {
        permutate_pad(pad, tmp_pad, pad_num, pads_disgussing_bits);
    }

    FREE(tmp_pad);
    FREE(temp);

    return PADS_ERROR_OK;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL get_data_from_last_pad_block(const char* cfg_path, int* id, size_t* sp, size_t* jp, size_t* rp, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* cfg_f = NULL;
    /*Trying to open the file*/
    cfg_f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open Circle cfg file for reading last Pad block.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Pass the cfg head part
    fseek(cfg_f, sizeof(struct pads), SEEK_SET);

    struct pad p;
    // May be not effective but anyway
    while (fread(&p, sizeof(struct pad), 1, cfg_f) == 1)
        ;

    for (size_t i = 0; i < 8; i++)
    {
        sp[i] = p.nextPSPstartPoints[i];
        jp[i] = p.nextPSPjumpPoints[i];
        rp[i] = p.nextPSPrearrnagePoints[i];
    }

    *id = p.id;

    fclose(cfg_f);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_uk_by_content_1_8(char* uk, char* buk, char* mrs, char** list, char* strands, int count, char* error_desc)
{
    /*                                                                   */
    /*    Combine sequences into one large string.						 */
    /*                                                                   */
    char* tempMergedSeqs = CALLOC(sizeof(char) * (int)count * _2_POW_23 + 1, 1);
    merge_sequences_by_content(tempMergedSeqs, list, count);

    expand_uk_in(uk, tempMergedSeqs, error_desc);
    FREE(tempMergedSeqs);
    /*                                                                   */
    /*    Collect Logicical Op Methods for BUK generating                */
    /*                                                                   */
    char bukLogicMethods[8] = { 0 };
    collect_logic_op_methods(bukLogicMethods, uk);

    /*                                                                   */
    /*    Make XOR or XNOR and generate BUK files                        */
    /*                                                                   */
    do_logical_operation(buk, uk, strands, bukLogicMethods);

    /*                                                                   */
    /*    Collect Start&Jump points                                      */
    /*                                                                   */
    size_t startPoints[8] = { 0 };
    size_t jumpPoints[8] = { 0 };

    get_start_jump_points(buk, startPoints, jumpPoints);

    /*                                                                   */
    /*    Create MRS files                                               */
    /*                                                                   */
    create_MRS_file(mrs, strands, startPoints, jumpPoints);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_uk_by_content_8_16(char* uk, char* buk, char* mrs, char** list, char* strands, size_t count, char* error_desc)
{
    merge_sequences_by_content(uk, list, count);
    expand_uk(uk, error_desc);

    /*                                                                   */
    /*    We need to replace some B-Day files with submitted seq         */
    /*                                                                   */
    const size_t replaced_file_count = count - 8;

    char* strands_replaced = CALLOC(UK_LENGHT + 1, 1);

    merge_sequences_by_content(strands_replaced, list + 8, replaced_file_count);
    strcat_s(strands_replaced, UK_LENGHT + 1, (strands + replaced_file_count * _2_POW_23));
    strands_replaced[UK_LENGHT] = '\n';

    /*                                                                   */
    /*    Collect Logicical Op Methods for BUK generating                */
    /*                                                                   */
    char bukLogicMethods[8] = { 0 };
    collect_logic_op_methods(bukLogicMethods, uk);

    /*                                                                   */
    /*    Make XOR or XNOR and generate BUK files                        */
    /*                                                                   */
    do_logical_operation(buk, uk, strands_replaced, bukLogicMethods);

    /*                                                                   */
    /*    Collect Start&Jump points                                      */
    /*                                                                   */
    size_t startPoints[8] = { 0 };
    size_t jumpPoints[8] = { 0 };

    get_start_jump_points(buk, startPoints, jumpPoints);

    /*                                                                   */
    /*    Create MRS files                                               */
    /*                                                                   */
    create_MRS_file(mrs, strands_replaced, startPoints, jumpPoints);

    FREE(strands_replaced);
    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_uk_by_content_8(char* uk, char* buk, char* mrs, char** list, char* strands, size_t count, char* error_desc)
{
    merge_sequences_by_content(uk, list, 8);

    /*                                                                   */
    /*    Collect Logicical Op Methods for BUK generating                */
    /*                                                                   */
    char buk_logic_methods[8] = { 0 };
    collect_logic_op_methods(buk_logic_methods, uk);

    /*                                                                   */
    /*    Make XOR or XNOR and generate BUK files                        */
    /*                                                                   */
    do_logical_operation(buk, uk, strands, buk_logic_methods);

    /*                                                                   */
    /*    Collect Start&Jump points                                      */
    /*                                                                   */
    size_t start_points[8] = { 0 };
    size_t jump_points[8] = { 0 };

    get_start_jump_points(buk, start_points, jump_points);

    /*                                                                   */
    /*    Create MRS files                                               */
    /*                                                                   */
    create_MRS_file(mrs, strands, start_points, jump_points);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_uk_by_content_16(char* uk, char* buk, char* mrs, char** list, size_t count, char* error_desc)
{
    /*                                                                   */
    /*    Divide them into two equal arrays:						     */
    /*    First 8 will be our preMRS(strands)                            */
    /*    Second 8 will be our preBUK                                    */
    /*                                                                   */
    char* strands = CALLOC(sizeof(char) * UK_LENGHT + 1, 1);
    merge_sequences_by_content(strands, list, 8);

    /* Shift files list array and then make strands str*/
    //merge_sequences_by_content(uk, list + 8, 8);
    merge_sequences_by_content(uk, list, 16);

    /*                                                                   */
    /*    Collect Logicical Op Methods for BUK generating                */
    /*                                                                   */
    char buk_logic_methods[8] = { 0 };
    collect_logic_op_methods(buk_logic_methods, uk);

    /*                                                                   */
    /*    Make XOR or XNOR and generate BUK files                        */
    /*                                                                   */
    do_logical_operation(buk, uk, strands, buk_logic_methods);

    /*                                                                   */
    /*    Collect Start&Jump points                                      */
    /*                                                                   */
    size_t start_points[8] = { 0 };
    size_t jump_points[8] = { 0 };

    get_start_jump_points(buk, start_points, jump_points);

    /*                                                                   */
    /*    Create MRS files                                               */
    /*                                                                   */
    create_MRS_file(mrs, strands, start_points, jump_points);

    return PADS_ERROR_OK;
}


SPAE_DLL_EXPIMP char* SPAE_CALL file_to_binary_enc(char* file, size_t* req_bits_count, size_t* added_bits_count, wchar_t* error_desc)
{
    /*Crucial varibales whcih will be used when we call MPZ funictions in order to convert file to binary*/
    mpz_t c;
    mpz_init(c);

    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(file, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        wcscpy_s(error_desc, 256, L"\nError: When trying to open a file for encryption.\n");
        return NULL;
    }

    // Get the encrypted file size
    size_t enc_file_size = fsize(f);

    // File size in bin
    size_t bin_file_size = enc_file_size * 8;

    // We are accepting files less than 500Mb currently
    if (enc_file_size > MB500)
    {
        wcscpy_s(error_desc, 256, L"\nError: We are accepting files less than 500Mb currently.\n");

        fclose(f);
        return NULL;
    }

    // Check if bin size is divisible by six and needed for additional bits
    size_t addedBitsCount = divisible_by_six(bin_file_size);

    /* Allocate enough memory */
    char* bin_content = ALLOC(sizeof(char) * (bin_file_size + 1 + addedBitsCount));

    size_t bytesRead = 0;
    size_t offset = 0;

    char* buffer = ALLOC(sizeof(char) * READ_CHUNK_SZIE + 1); // allocate memory

    char* tmp_buffer = ALLOC(sizeof(char) * READ_CHUNK_SZIE * 8 + 1); // allocate memory

    while ((bytesRead = fread(buffer, 1, READ_CHUNK_SZIE, f)) > 0)
    {

        buffer[bytesRead * 1] = '\0';
        mpz_import(c, bytesRead, 1, sizeof(buffer[0]), 0, 0, buffer);
        mpz_get_str(tmp_buffer, 2, c);

        const size_t len = strlen(tmp_buffer);

        if (len >= bytesRead * 8)
        {
            memcpy(bin_content + addedBitsCount + offset, tmp_buffer, len);
            offset = offset + len;
        }
        else
        {
            char* tmp_bin_result = ALLOC(sizeof(char) * ((bytesRead * 8) + (bytesRead * 8 - len) + 1));

            sprintf_s(tmp_bin_result, (bytesRead * 8) + (int)(bytesRead * 8 - len), "%0*d%s", (int)(bytesRead * 8 - len), 0, tmp_buffer);

            memcpy(bin_content + addedBitsCount + offset, tmp_bin_result, bytesRead * 8);
            offset = offset + bytesRead * 8;

            FREE(tmp_bin_result);
        }

        memset(buffer, 0, sizeof(buffer));
    }
    bin_content[addedBitsCount + offset] = '\0';

    fclose(f);
    FREE(tmp_buffer);

    // return requested bits count too
    *req_bits_count = bin_file_size + addedBitsCount;
    *added_bits_count = addedBitsCount;

    return bin_content;
}

SPAE_DLL_EXPIMP size_t SPAE_CALL get_member_total_pads_count(size_t m_id, char* pad_path, size_t mem_count, char* error_desc)
{
    size_t padCount = 0;
    size_t total_pads_count = 0;

    //TODO check for 0
    dirlist(pad_path, "txt", &padCount);
    /* Since dirlist returned not ordered list - 1.txt, 10.txt, 9.txt, .... */
    /* so we need to do natural sort algorithm on it!!!                     */
    /* BUTTTTTTTTTTT !!!                                                    */
    /* Because we just counting it does not matter order                    */

    if (padCount <= 0)
    {
        strcpy_s(error_desc, 256, "\nThere is no any pads found for the circle.\n");
        return total_pads_count;
    }

    size_t i = m_id;
    for (; i <= padCount; )
    {
        total_pads_count++;
        i += mem_count;
    }

    return total_pads_count;
}

SPAE_DLL_EXPIMP size_t SPAE_CALL get_circle_pads_count(char* pad_path, char* error_desc)
{
    size_t padCount = 0;
    size_t total_pads_count = 0;

    //TODO check for 0
    dirlist(pad_path, "txt", &padCount);
    /* Since dirlist returned not ordered list - 1.txt, 10.txt, 9.txt, .... */
    /* so we need to do natural sort algorithm on it!!!                     */
    /* BUTTTTTTTTTTT !!!                                                    */
    /* Because we just counting it does not matter order                    */

    if (padCount <= 0)
    {
        strcpy_s(error_desc, 256, "\nThere is no any pads found for the circle.\n");
        return total_pads_count;
    }

    total_pads_count = padCount;

    return total_pads_count;
}

SPAE_DLL_EXPIMP int SPAE_CALL get_member_fully_avail_pads_count(size_t m_id, char* enc_cfg_f_path, size_t mem_count, char* error_desc)
{
    int count = 0;
    // Check if cfg file exists
    if (0 != is_file_exists(enc_cfg_f_path))
    {
        return -1;
    }

    size_t avail_bits_count = get_option_from_enc_cfg(enc_cfg_f_path, "usedBitsCount", error_desc).int_value;
    count = (int)avail_bits_count / PAD_LEN; // How many full pad is it

    return count;
}

SPAE_DLL_EXPIMP enc_error_t SPAE_CALL create_64_prog_files(char* padContent, char*** tbl, char* pps_insert_point, char* logic, const char* dir, char* error_desc)
{
    const size_t contentLen    = 64 * 6 + PPS_STRUCT_RAW_LEN + 3 + 1 + 1; /* 64 spec chars six-bits representation + PPS data + added_bits + XOR bit + null end */
    char* content              = ALLOC((long)(sizeof(char) * contentLen));
    char* addedBits            = ALLOC(3 * sizeof(char)); // Why exactly 3?? Because 3255/6 = 3. 3255 is const and it is len of prog string
    wchar_t* circle_prog_dir_w = ALLOC(sizeof(wchar_t) * (long)(_MAX_DIR + 1));
    wchar_t* prog_f_name       = ALLOC(sizeof(wchar_t) * 7);
    wchar_t* prog_files_dir    = ALLOC(sizeof(wchar_t) * _MAX_PATH);

    int open_status;

    for (size_t i = 0; i < PROG_FILES_COUNT; i++)
    {
        // Start to build the contetn of every Prog file
        for (size_t j = 0; j < 64; j++)
        {
            memcpy(content + j * 6, tbl[i][j], 6);
        }
        content[64 * 6] = '\0';

        memcpy(content + 64 * 6, pps_insert_point, PPS_STRUCT_RAW_LEN); // pps_i_p must be a dec value but here we need its bin form
        content[64 * 6 + PPS_STRUCT_RAW_LEN] = '\0';

        // For the last (PPS) file we always use first bit val as a log op method
        if (i == 64)
        {
            char vIn = logic[0];
            char vOut[2] = { vIn,0 };
            memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN, vOut, 1);
            content[64 * 6 + PPS_STRUCT_RAW_LEN + 1] = '\0';
        }
        else
        {
            char vIn = logic[i];
            char vOut[2] = { vIn,0 };
            memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN, vOut, 1);
            content[64 * 6 + PPS_STRUCT_RAW_LEN + 1] = '\0';
        }

        memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN + 1, logic, 3);
        content[64 * 6 + PPS_STRUCT_RAW_LEN + 1 + 3] = '\0';

        // Encrypt content
        wchar_t* cipher_txt = encrypt_string(content, padContent, error_desc);

        /* Convert to wide string and pass as an argument */

        mbstowcs_s(NULL, circle_prog_dir_w, _MAX_DIR + 1, dir, _MAX_DIR);

        _ui64tow_s(i, prog_f_name, 7, 10);
        wcscat_s(prog_f_name, 7, L".txt");
        wcscpy_s(prog_files_dir, _MAX_PATH, circle_prog_dir_w);
        wcscat_s(prog_files_dir, _MAX_PATH, prog_f_name);

        // Write to file
        FILE* f = NULL;
        /*Trying to open the file*/
        f = w_open_file(prog_files_dir, FILE_MODE_WRITE, &open_status);

        if (open_status != 0)
        {
            strcpy_s(error_desc, 256, "\nError: When trying to open a file for Prog File.\n");
            //return NULL;
        }

        /* Fail to set mode to UTF */
        if (-1 == set_file_mode_to_utf(&f))
        {
            strcpy_s(error_desc, 256, "\nError: When trying to set file mode to UTF.\n");
            //return NULL;
        }

        fwrite(cipher_txt, 2, wcslen(cipher_txt), f);
        fclose(f);

        FREE(cipher_txt);
    }

    FREE(content);
    FREE(circle_prog_dir_w);
    FREE(prog_f_name);
    FREE(prog_files_dir);

    return ENC_ERROR_OK;
}

SPAE_DLL_EXPIMP enc_error_t SPAE_CALL encrypt_file(char* f_name, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* where_to_save, wchar_t* encrypted_f_name, wchar_t* error_msg)
{
    size_t requested_bits_count = 0;
    size_t added_bits_count     = 0;
    size_t* requested_pads_list = NULL;

    struct circle circle_s         = { 0 };
    struct bitsInfo bitsInfo_s     = { 0 };
    struct encryptionCfg enc_cfg_s = { 0 };

    char* used_pads_content = NULL;

    char* error_desc = ALLOC(sizeof(char) * 256);

    // Get some info about the circle
    get_circle_data_by_name(&circle_s, circle, error_desc);

    // Convert to binary
    char* binary_content = file_to_binary_enc(f_name, &requested_bits_count, &added_bits_count, error_msg);

    if (binary_content == NULL)
    {
        wcscpy_s(error_msg, 256, L"\nFile too large. 500mb file size limit for encryption.\n");
        return ENC_ERROR_HUGEFILE;
    }

    /* Get members bits info */
    bitsInfo_s = compute_bits_info(binary_content, circle, enc_cfg_f_path, member_id, is_first_usage, error_desc);

    // Check if there are enough bits for enc
    if (bitsInfo_s.availableBitsCount == 0 && bitsInfo_s.totalBitsCount == 0 && bitsInfo_s.usedBitsCount == 0 &&
        bitsInfo_s.requestedBitsCount > 0)
    {
        size_t _addit_P_count = bitsInfo_s.requestedBitsCount;
        wchar_t* how_many = int2wstr(_addit_P_count);
        wcscpy_s(error_msg, 256, how_many);
        return ENC_ERROR_FEWPADS;
    }

    // Check if there are enough bits for enc
    if (bitsInfo_s.availableBitsCount == 0 && bitsInfo_s.totalBitsCount == 0 && bitsInfo_s.usedBitsCount == 0 &&
        bitsInfo_s.requestedBitsCount == 0)
    {
        wcscpy_s(error_msg, 256, L"No Pads found for the circle.");
        return PADS_ERROR_NOPADS;
    }

    size_t r_p_c = 0; // requested pads count
    size_t enc_cfg_offset = 0; // requested pads count

    if (is_first_usage > 0)
    {
        requested_pads_list = get_list_of_requested_pads_ID(circle, member_id, requested_bits_count, &r_p_c, error_desc);

        // Prepare some data
        enc_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, 0, error_desc);
    }
    else
    {
        requested_pads_list = collect_list_of_requested_pads_ID(circle, member_id, requested_bits_count, bitsInfo_s.availableBitsCount, bitsInfo_s.usedBitsCount, &r_p_c, &enc_cfg_offset, error_desc);

        // Prepare some data
        enc_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, enc_cfg_offset, error_desc);
    }

    /* Now we should open each requested pad and merge thier content into one.        */
    if (r_p_c >= 1)
    {
        used_pads_content = CALLOC(sizeof(char) * r_p_c * PAD_LEN + 1, 1);
        int res = merge_requested_pads(used_pads_content, requested_pads_list, r_p_c, circle_s.pads_path, enc_cfg_offset, error_msg);
        if (res != 0)
        {
            //strcpy_s(error_desc, 256, "\nError: When merging Pads.\n");
            return ENC_ERROR_COMMON;
        }
    }
    else
    {
        wcscpy_s(error_msg, 256, L"\nWarning: There is no Pads to merge.\n");
        return ENC_ERROR_WRONGPADSCOUNT;
    }

    /* Adding additional bits using xor 6 bits  */
    memcpy(binary_content, enc_cfg_s.xorbits, added_bits_count);

    // Get Prog&PPS files raw content
    char* prog_pps_content = get_pps_and_prog_file_contents(circle, circle_s.pads_path, enc_cfg_s.programNumber, error_desc);

    /* Do logical operation                                                           */
    /* Get logical op method from program file content.It is a value of 3255-th bit.   */
    if ((*(prog_pps_content + 3254)) - '0' == 1) //3254=6*64+2870
    {
        // Do XOR
        fmakeXOR(binary_content, used_pads_content);
    }
    else
    {
        // Do XNOR
        fmakeXNOR(binary_content, used_pads_content);
    }

    /* Get PPS from config file content and convert it to spec chars.                 */
    wchar_t* spec_PPS = ALLOC(sizeof(wchar_t) * (2 * SPEC_PPS_LEN + 2));
    get_spec_PPS(enc_cfg_s, prog_pps_content, spec_PPS);
    //get_spec_PPS_simple(enc_cfg_s, prog_pps_content, spec_PPS);

    /* Convert plain text to their six-bits spec chars representation.                */
    wchar_t* plainSpec = ALLOC(sizeof(wchar_t) * (strlen(binary_content) / 3 + 2));
    get_spec_text(enc_cfg_s, binary_content, prog_pps_content, plainSpec);

    // Do PSP action.
    W_PSP(plainSpec, enc_cfg_s.startPoint, enc_cfg_s.jumpPoint);

    /* Insert special char into its position.	                 	                  */
    wchar_t* plain_spec_with_char = ALLOC(sizeof(wchar_t) * (wcslen(plainSpec) + 2));
    insert_spec_char(enc_cfg_s, plainSpec, plain_spec_with_char);

    /* Insert PPS into its position.	                 	                          */
    /* But first of all we need to get PPS insertion point from program content       */
    /* it starts from 385th bit with the len 26 bit                                   */
    wchar_t* plain_spec_with_char_and_PPS = ALLOC(sizeof(wchar_t) * (wcslen(plainSpec) + wcslen(spec_PPS) + 2));
    insert_pps(enc_cfg_s, plain_spec_with_char, spec_PPS, prog_pps_content, plain_spec_with_char_and_PPS);

    /* Build encrypted file name:  	                 	                              */
    /* First 7 chars of the file + added bits count + original ext + spae             */
    wchar_t* final_f_name = biuld_enc_file_name(plain_spec_with_char_and_PPS, added_bits_count, where_to_save, f_name);

    wmemcpy_s(encrypted_f_name, _MAX_FNAME, final_f_name, wcslen(final_f_name));
    encrypted_f_name[wcslen(final_f_name)] = '\0';
    //strcpy_s(encrypted_f_name, 256, "\nFile name si fuck\n");

    /* Write into file            	                 	                              */
    write_cipher_to_file(final_f_name, plain_spec_with_char_and_PPS, error_desc);

    enc_cfg_s.totalBitsCount = bitsInfo_s.totalBitsCount;
    enc_cfg_s.requestedBitsCount = bitsInfo_s.requestedBitsCount;
    enc_cfg_s.usedBitsCount = bitsInfo_s.usedBitsCount + bitsInfo_s.requestedBitsCount + SEEK_NUMBER;
    enc_cfg_s.availableBitsCount = bitsInfo_s.availableBitsCount - bitsInfo_s.requestedBitsCount;

    /*enc_cfg_s.usedBitsCount = bitsInfo_s.usedBitsCount;
    enc_cfg_s.availableBitsCount = bitsInfo_s.availableBitsCount;*/

    store_enc_cfg(enc_cfg_f_path, enc_cfg_s, error_desc);

    FREE(binary_content);
    FREE(used_pads_content);
    FREE(plain_spec_with_char_and_PPS);
    //FREE(final_f_name);

    //wcscpy_s(error_msg, 256, spec_PPS);
    return ENC_ERROR_OK;
}

SPAE_DLL_EXPIMP enc_error_t SPAE_CALL merge_requested_pads(char* result, size_t* list, size_t count, char* pads_dir, size_t offset, wchar_t* error_desc)
{
    char* padPath = ALLOC(sizeof(char) * _MAX_PATH);
    char* padName = ALLOC(sizeof(char) * 8 + 1);

    /*Read whole file content into memory*/
    /*Allocate enough heap size for file content*/
    char* fContent;
    size_t contentSize = 0;
    size_t shift = 0;

    int open_status;
    int readStatus;

    FILE* pd;
    for (size_t i = 0; i < count; i++)
    {
        _ui64toa_s(list[i], padName, 9, 10);
        strcat_s(padName, 9, ".txt");

        strcpy_s(padPath, _MAX_PATH, pads_dir);
        padPath[strlen(pads_dir)] = '\0';
        strcat_s(padPath, _MAX_PATH, "/");
        strcat_s(padPath, _MAX_PATH, padName);

        /*Accept the file and try to open it*/
        pd = open_file(padPath, FILE_MODE_READ, &open_status);
        if (open_status != 0)
        {
            wcscpy_s(error_desc, 256, L"\nError: When trying to open a Pad for merging.\n");
            return ENC_ERROR_OPENFILE;
        }

        if (i == 0)
        {
            /* if this is a first step of loop, so we need to seek from first pad used bits */
            fseek(pd, (long)(offset + SEEK_NUMBER), SEEK_SET);
        }

        fContent = c_read_file(pd, &readStatus, &contentSize);
        if (readStatus)
        {
            wcscpy_s(error_desc, 256, L"\nError: When trying to open Pad file for merging.\n");
            return ENC_ERROR_READFILE;
        }

        memcpy(result + shift, fContent, contentSize);
        shift += contentSize;

        FREE(fContent);

        memset(padPath, 0, sizeof(padPath));
        memset(padName, 0, sizeof(padName));

        fclose(pd);
    }
    result[shift] = '\0';

    return ENC_ERROR_OK;
}


/* Decryption item removed */


/* Decryption item removed */


SPAE_DLL_EXPIMP void SPAE_CALL create_file_with_name(char* content, char* name)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* fp1 = NULL;
    /*Trying to open the file*/
    fp1 = open_file(name, FILE_MODE_WRITE, &open_status);

    fwrite(content, 1, strlen(content), fp1);
}

SPAE_DLL_EXPIMP int SPAE_CALL get_last_used_pad_id_encr(char* enc_cfg_f_path, char* error_desc)
{
    int count = 0;
    // Check if cfg file exists
    if (0 != is_file_exists(enc_cfg_f_path))
    {
        return -1;
    }

    size_t used_bits_count = get_option_from_enc_cfg(enc_cfg_f_path, "usedBitsCount", error_desc).int_value;
    count = (int)used_bits_count / PAD_LEN + 1; // How many full pad is it + 1

    return count;
}

int inline is_wstring_empty(wchar_t* s)
{
    if (wcscmp(s, L"") == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

struct bitsInfo compute_bits_info(char* binContent, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_call, char* error_desc)
{
    struct bitsInfo bits_i = { 0 };
    struct circle circle_s = { 0 };

    const size_t c_len = strlen(binContent);

    // Set requested bits count. It does not matter is this first call for enc or not
    bits_i.requestedBitsCount = c_len;

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    // Get overall data about the Circle
    get_circle_data_by_name(&circle_s, circle, error_desc);

    // Get the member total Pads count
    size_t _member_pads_count = get_member_total_pads_count(member_id, circle_s.pads_path, members_count, error_desc);

    if (_member_pads_count == 0)
    {
        // Return error with all fileds set to 0 except requested filed set to needed pads count
        bits_i.availableBitsCount = 0;
        bits_i.requestedBitsCount = 0;
        bits_i.totalBitsCount = 0;
        bits_i.usedBitsCount = 0;

        return bits_i;
    }

    // Total bits for member
    size_t _member_total_bits_count = _member_pads_count * PAD_LEN;

    if (is_first_call > 0)
    {
        // It is a first call of enc

        // Set total bits count
        bits_i.totalBitsCount = _member_total_bits_count;

        // Check if there are enough bits for enc
        if ((_member_total_bits_count - SEEK_NUMBER) <= c_len)
        {
            size_t _addit_P_count = (c_len - _member_total_bits_count + SEEK_NUMBER) / PAD_LEN + 1;

            // Return error with all fileds set to 0 except requested filed set to needed pads count
            bits_i.availableBitsCount = 0;
            bits_i.requestedBitsCount = _addit_P_count * members_count;
            bits_i.totalBitsCount = 0;
            bits_i.usedBitsCount = 0;

            return bits_i;
        }

        // Set available bits count
        bits_i.availableBitsCount = _member_total_bits_count; // total - requestedbits

        // Set used bits
        bits_i.usedBitsCount = 0; // the same as requestedBitsCount
    }

    else
    {
        /* Since there is enc.cfg it means it is a not first enc process, so we need to   */
        /* get used bits count from the enc.cfg file.                                     */
        size_t used_Bits_Count = get_option_from_enc_cfg(enc_cfg_f_path, "usedBitsCount", error_desc).int_value;

        /* Get available bits from the config file                                        */
        size_t available_Bits = _member_total_bits_count - used_Bits_Count;

        // Check if there are enough bits for enc
        if ((available_Bits - SEEK_NUMBER) <= c_len)
        {
            size_t _addit_P_count = (c_len - available_Bits + SEEK_NUMBER) / PAD_LEN + 1;

            // Return error with all fileds set to 0 except requested filed set to needed pads count
            bits_i.availableBitsCount = 0;
            bits_i.requestedBitsCount = _addit_P_count * members_count;
            bits_i.totalBitsCount = 0;
            bits_i.usedBitsCount = 0;

            return bits_i;
        }

         // Set total bits count
        bits_i.totalBitsCount = _member_total_bits_count;

        // Set available bits count
        bits_i.availableBitsCount = available_Bits; // total - requestedbits

        // Set used bits
        bits_i.usedBitsCount = used_Bits_Count;

    }

    return bits_i;
}

size_t* get_list_of_requested_pads_ID(char* circle, size_t mID, size_t requestedBitsCount, size_t* requestPadsCount, char* error_desc)
{
    if (mID < 0)
    {
        strcpy_s(error_desc, 256, "\nWhy member ID is less than 0??? Pls, check!\n");
        return NULL;
    }

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    // Get overall data about the Circle
    struct circle circle_s = { 0 };
    get_circle_data_by_name(&circle_s, circle, error_desc);

    size_t member_pads_count = 0;
    size_t* _mem_p_list_id = get_member_pads_indexes(circle_s, mID, members_count, &member_pads_count);

    if (member_pads_count <= 0)
    {
        strcpy_s(error_desc, 256, "\nMember has no any Pad available. Pls, check.\n");
        return NULL;
    }

    /* How many full pad requested */
    size_t requestdFullPadsCount = howManyFullPadsIsIt(requestedBitsCount);
    *requestPadsCount = requestdFullPadsCount + 1; // When first usage always add +1 Pad

    // First usage, so we can just return diff of pads full list & available pads full list
    size_t* reqList = ALLOC(sizeof(size_t) * (*requestPadsCount));
    memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[0], *requestPadsCount * sizeof(*_mem_p_list_id));

    return reqList;
}

/* Decryption item removed */

size_t* get_requested_pads_list(char* circle, size_t mID, size_t requestedBitsCount, size_t usedBitsCount, size_t avBitsCount, size_t* requestPadsCount, char* error_desc)
{
    if (mID < 0)
    {
        strcpy_s(error_desc, 256, "\nWhy member ID is less than 0??? Pls, check!\n");
        return NULL;
    }

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    // Get overall data about the Circle
    struct circle circle_s = { 0 };
    get_circle_data_by_name(&circle_s, circle, error_desc);

    size_t member_pads_count = 0;
    size_t* _mem_p_list_id = get_member_pads_indexes(circle_s, mID, members_count, &member_pads_count);

    if (member_pads_count <= 0)
    {
        strcpy_s(error_desc, 256, "\nMember has no any Pad available. Pls, check.\n");
        return NULL;
    }

    /* How many full pad requested */
    size_t requestdFullPadsCount = howManyFullPadsIsIt(requestedBitsCount);
    int availablePartlyPadIndex = get_member_partially_available_Pad_index(_mem_p_list_id, member_pads_count, avBitsCount);
    size_t* availableFullPadsList = get_member_full_pad_IDs(_mem_p_list_id, member_pads_count, avBitsCount);

    if (requestdFullPadsCount == 0 && availablePartlyPadIndex > -1)
    {
        // So, requested bits count less than PAD_SIZE
        // Let's try to use partly available pad's bits if their count is enough for that
        size_t avBits = get_available_bits_count_of_part_pad(usedBitsCount);

        if (avBits > requestedBitsCount)
        {
            // There is enough bits in pivot pad. 
            // So we can use ONLY that partly pad.
            *requestPadsCount = 1;
            size_t* reqList = ALLOC(sizeof(size_t) * 1);
            memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[availablePartlyPadIndex], *requestPadsCount * sizeof(*_mem_p_list_id));
            return reqList;
        }
        else
        {
            // There is not enough bits ONLY in partly pad.
            // So, we should return 2 pads list starting from that
            *requestPadsCount = 2;
            size_t* reqList = ALLOC(sizeof(size_t) * 2);
            memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[availablePartlyPadIndex], *requestPadsCount * sizeof(*_mem_p_list_id));
            return reqList;
        }
    }

    if (requestdFullPadsCount == 0 && availablePartlyPadIndex == -1)
    {
        // There is no partly pad available but requested less than PAD_SIZE
        // So we can return next full pad
        *requestPadsCount = 1;
        size_t* reqList = ALLOC((long)(*requestPadsCount) * sizeof(size_t));
        memcpy_s(reqList, *requestPadsCount * sizeof(*availableFullPadsList), &availableFullPadsList[0], *requestPadsCount * sizeof(*availableFullPadsList));
        return reqList;

    }

    if (requestdFullPadsCount > 0 && availablePartlyPadIndex > -1)
    {
        // There is at least one full pad requested and we have partly pad available
        size_t avBits = get_available_bits_count_of_part_pad(usedBitsCount);
        // Trying to understand is there enough bits in partly pad so we can return
        // that pad and the next full pads requested Or we should return 
        // partly pad + requested full pads + 1 additional pad.
        if (avBits < (requestedBitsCount % PAD_LEN))
        {
            // There is not enough bits in part pad
            *requestPadsCount = requestdFullPadsCount + 1 + 1;
            size_t* reqList = ALLOC((long)(*requestPadsCount) * sizeof(size_t));
            memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[availablePartlyPadIndex], *requestPadsCount * sizeof(*_mem_p_list_id));
            return reqList;
        }
        else
        {
            *requestPadsCount = requestdFullPadsCount + 1;
            size_t* reqList = ALLOC((long)(*requestPadsCount) * sizeof(size_t));
            memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[availablePartlyPadIndex], *requestPadsCount * sizeof(*_mem_p_list_id));
            return reqList;
        }
    }

    if (requestdFullPadsCount > 0 && availablePartlyPadIndex == -1)
    {
        // There is at least one full pad requested and we have not partly pad available
        *requestPadsCount = requestdFullPadsCount;
        size_t* reqList = ALLOC((long)(*requestPadsCount) * sizeof(size_t));
        memcpy_s(reqList, *requestPadsCount * sizeof(*availableFullPadsList), &availableFullPadsList[0], *requestPadsCount * sizeof(*availableFullPadsList));
        return reqList;
    }

    return NULL;
}

size_t* collect_list_of_requested_pads_ID(char* circle, size_t mID, size_t requestedBitsCount, size_t availableBitsCount, size_t usedBitsCount, size_t* requestPadsCount, size_t* enc_cfg_offset, char* error_desc)
{
    /* Get completely available pad list.This is when we are excluding pads were used */
    if (mID < 0)
    {
        strcpy_s(error_desc, 256, "\nWhy member ID is less than 0??? Pls, check!\n");
        return NULL;
    }

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    // Get overall data about the Circle
    struct circle circle_s = { 0 };
    get_circle_data_by_name(&circle_s, circle, error_desc);

    size_t member_pads_count = 0;
    size_t* _mem_p_list_id = get_member_pads_indexes(circle_s, mID, members_count, &member_pads_count);

    if (member_pads_count <= 0)
    {
        strcpy_s(error_desc, 256, "\nMember has no any Pad available. Pls, check.\n");
        return NULL;
    }

    /* Get partially available pad list if there is.                                  */
    int partlyPadIndex = get_member_partially_available_Pad_index(_mem_p_list_id, member_pads_count, availableBitsCount);

    /* If there is partly pad so we need to get used bits count and use as an offset */
    if (_mem_p_list_id != NULL && partlyPadIndex > -1)
    {
        size_t availableBitsInPartlyPad = get_available_bits_count_of_part_pad(usedBitsCount);
        *enc_cfg_offset = get_used_bits_count_of_part_pad(usedBitsCount);

        if (availableBitsInPartlyPad <= 100)
        {
            // There are no enough count of bits for generating PPS and etc...
            // so we mark this pad as used and return next one.
            usedBitsCount += availableBitsInPartlyPad;
            *enc_cfg_offset = 0;

        }
    }

    size_t* list = get_requested_pads_list(circle, mID, requestedBitsCount, usedBitsCount, availableBitsCount, requestPadsCount, error_desc);

    return list;
}

size_t* get_member_pads_indexes(struct circle c_s, size_t m_ID, size_t membs_total_count, size_t* count)
{
    size_t pads_count = 0;

    dirlist(c_s.pads_path, "txt", &pads_count);

    size_t* member_pads_ID_list = ALLOC(sizeof(size_t) * pads_count);

    /* Due to array indexing starts from 0, so member ID should be (-1) */
    size_t memberID = m_ID - 1;

    for (size_t i = m_ID; i <= pads_count; i += membs_total_count)
    {
        member_pads_ID_list[*count] = i;
        (*count)++;
    }

    return member_pads_ID_list;
}