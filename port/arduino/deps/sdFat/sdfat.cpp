#include <Arduino.h>
#include <stdio.h>
#include <SdFat.h>
#include <SdFatConfig.h>
#include <sdios.h>
#include <SysCall.h>
#include "sdfat.h"


sdfat_t *_sd_holder = NULL;
sdfile_t *_file_holder = NULL;
// can't dynamically create this as it has no destructor
SdFile cred_file;

sdfat_t *sdfat_create()
{
    sdfat_t *sd_holder;
    SdFat *sd_ref;

    sd_holder = (typeof(sd_holder))malloc(sizeof(*sd_holder));
    sd_ref    = new SdFat();
    sd_holder->sd = sd_ref;
    return sd_holder;
}

sdfile_t *sdfile_create()
{
    sdfile_t *file_holder;
    file_holder = (typeof(file_holder))malloc(sizeof(*file_holder));
    file_holder->file = &cred_file;
    return file_holder;
}
// released sd fat holder and object reference
bool sdfat_destroy(sdfat_t *sd_holder)
{
    if (sd_holder== NULL)
        return 1;
    delete static_cast<SdFat *>(sd_holder->sd);
    free(sd_holder);
		return 0;
}
// release file object and reference
bool sdfile_destroy(sdfile_t *file_holder)
{
    if (file_holder == NULL)
        return 1;
    free(file_holder);
		return 0;
}

bool sdfat_begin(sdfat_t *sd_holder, uint8_t chip_select){

    SdFat *_sd;
    if (sd_holder == NULL)
        return 1;

    _sd = static_cast<SdFat *>(sd_holder->sd);
	/* Initialize at the highest speed supported by the board that is
		   not over 50 MHz. Try a lower speed if SPI errors occur.*/
    return _sd->begin(chip_select,  SPI_HALF_SPEED);
}

bool sdfat_initErrorHalt(sdfat_t *sd_holder){

    SdFat *_sd;
    if (sd_holder == NULL)
        return 1;
    _sd = static_cast<SdFat *>(sd_holder->sd);
    _sd->initErrorHalt();
		return 0;
}

bool sdfat_errorHalt(sdfat_t *sd_holder, const char* msg){

    SdFat *_sd;
    if (sd_holder == NULL)
        return 1;
    _sd = static_cast<SdFat *>(sd_holder->sd);
    _sd->errorHalt(msg);
		return 0;
}
/*See if the directory exists, create it if not.*/
bool sdfat_exists(sdfat_t *sd_holder, const char* path){

    SdFat *_sd;
    if (sd_holder == NULL)
        return 1;
    _sd = static_cast<SdFat *>(sd_holder->sd);
    return _sd->exists(path);
}
/**/
bool sdfat_mkdir(sdfat_t *sd_holder, const char* path){

    SdFat *_sd;
    if (sd_holder == NULL)
        return 1;
    _sd = static_cast<SdFat *>(sd_holder->sd);
    return _sd->mkdir(path);
}
/*SD file functions*/
bool sdfile_ls(sdfile_t *file_holder){

    SdFile *_file;
    if (file_holder == NULL)
        return 1;
    _file = static_cast<SdFile *>(file_holder->file);
    return _file->ls(LS_R | LS_DATE | LS_SIZE);
}
// file.open(fileName, O_CREAT | O_WRITE | O_EXCL)
bool sdfile_open_write(sdfile_t *file_holder, const char* path, oflag_t oflags){

    SdFile *_file;
    if (file_holder == NULL)
        return 1;
    _file = static_cast<SdFile *>(file_holder->file);
    return _file->open(path, oflags);
}

bool sdfile_open_read(sdfile_t *file_holder, const char* path, oflag_t oflags){

    SdFile *_file;
    if (file_holder == NULL)
        return 1;
    _file = static_cast<SdFile *>(file_holder->file);
    return _file->open(path, oflags);
}

bool sdfile_isOpen(sdfile_t *file_holder){

    SdFile *_file;
    if (file_holder == NULL)
        return 1;
    _file = static_cast<SdFile *>(file_holder->file);
    return _file->isOpen();
}

int sdfile_write(sdfile_t *file_holder, const void* buf, size_t nbyte){

    SdFile *_file;
    if (file_holder == NULL)
        return 1;
    _file = static_cast<SdFile *>(file_holder->file);
    return _file->write(buf, nbyte);
}

int sdfile_read(sdfile_t *file_holder, void* buf, size_t nbyte){

    SdFile *_file;
    if (file_holder == NULL)
        return 1;
    _file = static_cast<SdFile *>(file_holder->file);
    return _file->read(buf, nbyte);
}

bool sdfile_close(sdfile_t *file_holder){

    SdFile *_file;
    if (file_holder == NULL)
        return 1;
    _file = static_cast<SdFile *>(file_holder->file);
    return _file->close();
}

uint32_t sdfile_available(sdfile_t *file_holder){

    SdFile *_file;
    if (file_holder == NULL)
        return 1;
    _file = static_cast<SdFile *>(file_holder->file);
    return _file->available();
}


