#pragma once
#ifndef _MSC_VER
#define _GNU_SOURCE 1
#define _FILE_OFFSET_BITS 64
#endif
#define ARGC_MAX 8
#define ARGV_LEN 384

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h> // tolower
#include <math.h>
#include <time.h>

#ifndef LIBUSB_DETACH
/* detach the device from crappy kernel drivers */
#define LIBUSB_DETACH 1
#endif

#if _WIN32
#include <Windows.h>
#include <Dbt.h>
#include <tchar.h>
#define WM_RCV_CHANNEL_DATA WM_USER + 1

DWORD WINAPI ThrdFunc(LPVOID lpParam);
#if UNICODE
#define my_strstr wcsstr
#define my_strtoul wcstoul
#else
#define my_strstr strstr
#define my_strtoul strtoul
#endif
#else
#include <dirent.h>
#endif

#if USE_LIBUSB
#include <libusb-1.0/libusb.h>
#ifndef _MSC_VER
#include <pthread.h>
#include <unistd.h>
#endif
#else
#include <setupapi.h>
#include "Wrapper.h"
#endif

#ifdef _MSC_VER
void usleep(unsigned int us);
#define fseeko _fseeki64
#define ftello _ftelli64
#endif

#include "spd_cmd.h"

#define FLAGS_CRC16 1
#define FLAGS_TRANSCODE 2

#if _WIN32
#define ERR_EXIT(...) \
	do { fprintf(stderr, __VA_ARGS__); if (m_bOpened == 1) system("pause"); exit(1); } while (0)
#else
#define ERR_EXIT(...) \
	do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)
#endif

#define DBG_LOG(...) fprintf(stderr, __VA_ARGS__)

#define WRITE16_LE(p, a) do { \
	((uint8_t*)(p))[0] = (uint8_t)(a); \
	((uint8_t*)(p))[1] = (a) >> 8; \
} while (0)

#define WRITE32_LE(p, a) do { \
	((uint8_t*)(p))[0] = (uint8_t)(a); \
	((uint8_t*)(p))[1] = (a) >> 8; \
	((uint8_t*)(p))[2] = (a) >> 16; \
	((uint8_t*)(p))[3] = (a) >> 24; \
} while (0)

#define READ32_LE(p) ( \
	((uint8_t*)(p))[0] | \
	((uint8_t*)(p))[1] << 8 | \
	((uint8_t*)(p))[2] << 16 | \
	((uint8_t*)(p))[3] << 24)

#define WRITE16_BE(p, a) do { \
	((uint8_t*)(p))[0] = (a) >> 8; \
	((uint8_t*)(p))[1] = (uint8_t)(a); \
} while (0)

#define WRITE32_BE(p, a) do { \
	((uint8_t*)(p))[0] = (a) >> 24; \
	((uint8_t*)(p))[1] = (a) >> 16; \
	((uint8_t*)(p))[2] = (a) >> 8; \
	((uint8_t*)(p))[3] = (uint8_t)(a); \
} while (0)

#define READ16_BE(p) ( \
	((uint8_t*)(p))[0] << 8 | \
	((uint8_t*)(p))[1])

#define READ32_BE(p) ( \
	((uint8_t*)(p))[0] << 24 | \
	((uint8_t*)(p))[1] << 16 | \
	((uint8_t*)(p))[2] << 8 | \
	((uint8_t*)(p))[3])


typedef struct {
	char name[36];
	long long size;
} partition_t;

typedef struct {
	uint8_t *raw_buf, *enc_buf, *recv_buf, *temp_buf, *untranscode_buf, *send_buf;
#if USE_LIBUSB
	libusb_device_handle *dev_handle;
	int endp_in, endp_out;
	int m_dwRecvThreadID;
#else
	ClassHandle *handle;
	HANDLE m_hOprEvent;
	DWORD m_dwRecvThreadID;
	HANDLE m_hRecvThreadState;
	HANDLE m_hRecvThread;
#endif
#if _WIN32
	DWORD iThread;
	HANDLE hThread;
#endif
	int flags, recv_len, recv_pos;
	int raw_len, enc_len, verbose, timeout;
	partition_t *ptable;
	int part_count;
} spdio_t;

#pragma pack(1)
typedef struct {
	uint8_t signature[8];
	uint32_t revision;
	uint32_t header_size;
	uint32_t header_crc32;
	int32_t reserved;
	uint64_t current_lba;
	uint64_t backup_lba;
	uint64_t first_usable_lba;
	uint64_t last_usable_lba;
	uint8_t disk_guid[16];
	uint64_t partition_entry_lba;
	int32_t number_of_partition_entries;
	uint32_t size_of_partition_entry;
	uint32_t partition_entry_array_crc32;
} efi_header;

typedef struct {
	uint8_t partition_type_guid[16];
	uint8_t unique_partition_guid[16];
	uint64_t starting_lba;
	uint64_t ending_lba;
	int64_t attributes;
	uint8_t partition_name[72];
} efi_entry;

typedef struct {
	uint32_t dwVersion;
	uint32_t bDisableHDLC; //0: Enable hdl; 1:Disable hdl
	uint8_t bIsOldMemory;
	uint8_t bSupportRawData;
	uint8_t bReserve[2];
	uint32_t dwFlushSize; //unit KB
	uint32_t dwStorageType;
	uint32_t dwReserve[59]; //Reserve
} DA_INFO_T;

typedef struct {
	uint8_t priority : 4;
	uint8_t tries_remaining : 3;
	uint8_t successful_boot : 1;
	uint8_t verity_corrupted : 1;
	uint8_t reserved : 7;
} slot_metadata;

typedef struct {
	char slot_suffix[4];
	uint32_t magic;
	uint8_t version;
	uint8_t nb_slot : 3;
	uint8_t recovery_tries_remaining : 3;
	uint8_t merge_status : 3;
	uint8_t reserved0[1];
	slot_metadata slot_info[4];
	uint8_t reserved1[8];
	uint32_t crc32_le;
} bootloader_control;
#pragma pack()

#if USE_LIBUSB
libusb_device **FindPort(int pid);
void startUsbEventHandle(void);
void stopUsbEventHandle(void);
void find_endpoints(libusb_device_handle *dev_handle, int result[2]);
void call_Initialize_libusb(spdio_t *io);
#else
DWORD *FindPort(const char *USB_DL);
BOOL CreateRecvThread(spdio_t *io);
void DestroyRecvThread(spdio_t *io);
#endif

void print_string(FILE *f, const void *src, size_t n);
void ChangeMode(spdio_t *io, int ms, int bootmode, int at);

spdio_t *spdio_init(int flags);
void spdio_free(spdio_t *io);

void encode_msg(spdio_t *io, int type, const void *data, size_t len);
void encode_msg_nocpy(spdio_t *io, int type, size_t len);
int send_msg(spdio_t *io);
int recv_msg(spdio_t *io);
int recv_msg_timeout(spdio_t *io, int timeout);
unsigned recv_type(spdio_t *io);
int send_and_check(spdio_t *io);
int check_confirm(const char *name);
uint8_t *loadfile(const char *fn, size_t *num, size_t extra);
void send_buf(spdio_t *io, uint32_t start_addr, int end_data, unsigned step, uint8_t *mem, unsigned size);
size_t send_file(spdio_t *io, const char *fn, uint32_t start_addr, int end_data, unsigned step, unsigned src_offs, unsigned src_size);
FILE *my_fopen(const char *fn, const char *mode);
unsigned dump_flash(spdio_t *io, uint32_t addr, uint32_t start, uint32_t len, const char *fn, unsigned step);
unsigned dump_mem(spdio_t *io, uint32_t start, uint32_t len, const char *fn, unsigned step);
uint64_t dump_partition(spdio_t *io, const char *name, uint64_t start, uint64_t len, const char *fn, unsigned step);
void dump_partitions(spdio_t *io, const char *fn, int *nand_info, unsigned step);
uint64_t read_pactime(spdio_t *io);
partition_t *partition_list(spdio_t *io, const char *fn, int *part_count_ptr);
void repartition(spdio_t *io, const char *fn);
void erase_partition(spdio_t *io, const char *name);
void load_partition(spdio_t *io, const char *name, const char *fn, unsigned step);
void load_nv_partition(spdio_t *io, const char *name, const char *fn, unsigned step);
void load_partitions(spdio_t *io, const char *path, unsigned step, int force_ab);
void load_partition_force(spdio_t *io, const int id, const char *fn, unsigned step);
int load_partition_unify(spdio_t *io, const char *name, const char *fn, unsigned step);
uint64_t check_partition(spdio_t *io, const char *name, int need_size);
void get_partition_info(spdio_t *io, const char *name, int need_size);
uint64_t str_to_size(const char *str);
uint64_t str_to_size_ubi(const char *str, int *nand_info);
void get_Da_Info(spdio_t *io);
void select_ab(spdio_t *io);
void dm_disable(spdio_t *io, unsigned step);
void dm_enable(spdio_t *io, unsigned step);
void w_mem_to_part_offset(spdio_t *io, const char *name, size_t offset, uint8_t *mem, size_t length, unsigned step);
void set_active(spdio_t *io, char *arg);
