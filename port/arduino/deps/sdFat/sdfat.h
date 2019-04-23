#ifndef __SDFAT_H__
#define __SDFAT_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdlib.h>
#include <FatApiConstants.h>
// holder for sd objects pointer
typedef struct _sdFat {
    void *sd;
}sdfat_t;
// holder for my_file object pointers
typedef struct _sdFile {
    void *file;
}sdfile_t;


extern sdfat_t *_sd_holder;
extern sdfile_t *_file_holder;


sdfat_t *sdfat_create();
bool sdfat_destroy(sdfat_t *sd_holder);

sdfile_t *sdfile_create();
bool sdfile_destroy(sdfile_t *file_holder);

/** Initialize the SD card.
 * \param[in] csPin SD chip select pin.
 * \param[in] sd_holder, pointer to sd object.
 * \return true for success else false.
*/
bool sdfat_begin(sdfat_t *sd_holder, uint8_t chipselect);
/** %Print any SD error code and halt. */
bool sdfat_initErrorHalt(sdfat_t *sd_holder);
/** %Print msg, any SD error code, and halt.
 *
 * \param[in] sd_holder, pointer to sd object.
 * \param[in] msg, error message to print.
*/
bool sdfat_errorHalt(sdfat_t *sd_holder, const char* msg);

/** Test for the existence of a file in a directory
 *
 * \param[in] sd_holder, pointer to the sd object.
 * \param[in] path Path of the file to be tested for.
 *
 * \return true if the file exists else false.
*/
bool sdfat_exists(sdfat_t *sd_holder, const char* path);
/** Make a new directory.
 *
 * \param[in] path A path with a valid 8.3 DOS name for the new directory.
 *
 * \param[in] sd_holder pointer to sd object.
 *
 * \return The value true is returned for success and
 * the value false is returned for failure.
*/
bool sdfat_mkdir(sdfat_t *sd_holder, const char* path);
/** List directory contents.
 *\param[in] sd_holder, pointer to the sd object.
*/
bool sdfile_ls(sdfile_t *file_holder);
/** Open a file in the current working directory for reading.
 * \param[in] sd_holder, pointer to the sd object
 * \param[in] path A path with a valid 8.3 DOS name for a file to be opened.
 *
 * \param[in] oflag bitwise-inclusive OR of open mode flags.
 *                  See see FatFile::open(FatFile*, const char*, oflag_t).
 *
 * \return The value true is returned for success and
 * the value false is returned for failure.
*/
bool sdfile_open_read(sdfile_t *file_holder, const char* path, oflag_t oflags);

/** Open a file in the current working directory for writing.
 * \param[in] sd_holder, pointer to the sd object
 * \param[in] path A path with a valid 8.3 DOS name for a file to be opened.
 * \param[in] oflag bitwise-inclusive OR of open mode flags.
 *                  See see FatFile::open(FatFile*, const char*, oflag_t).
 *
 * \return The value true is returned for success and
 * the value false is returned for failure.
*/

bool sdfile_open_write(sdfile_t *file_holder, const char* path, oflag_t oflags);

/** Check if file is open.
 * \param[in] sd_holder, pointer to the sd objet
*/
bool sdfile_isOpen(sdfile_t *file_holder);
/** Write data to an open file.
 * \param[in] file_holder, pointer to file object.
 * \param[in] buf Pointer to the location of the data to be written.
 *
 * \param[in] nbyte Number of bytes to write.
 *
 * \return For success write() returns the number of bytes written, always
 * \a nbyte.  If an error occurs, write() returns -1.  Possible errors
 * include write() is called before a file has been opened, write is called
 * for a read-only file, device is full, a corrupt file system or an I/O error.
 *
*/
int sdfile_write(sdfile_t *file_holder, const void* buf, size_t nbyte);
/** Read data from a file starting at the current position.
 * \param[in] file_holder, pointer to file object.
 * \param[in] buf Pointer to the location of the data to be written.
 * \param[out] nbyte Number of bytes read.
 * \return For success read() returns the number of bytes read.
 * A value less than \a nbyte, including zero, will be returned
 * if end of file is reached.
 * If an error occurs, read() returns -1.  Possible errors include
 * read() called before a file has been opened, corrupt file system
 * or an I/O error occurred.
*/
int sdfile_read(sdfile_t *file_holder, void* buf, size_t nbyte);
/** Close a file and force cached data and directory information
 *  to be written to the storage device.
 * \param[in] file_holder, pointer to file object.
 * \return The value true is returned for success and
 * the value false is returned for failure.
*/
bool sdfile_close(sdfile_t *file_holder);

/** \return The number of bytes available from the current position
 * \param[in] file_holder, pointer to file object.
 * to EOF for normal files.  Zero is returned for directory files.
*/
uint32_t sdfile_available(sdfile_t *file_holder);


#ifdef __cplusplus
}
#endif

#endif /* __SDFAT_H__ */
