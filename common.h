#pragma once

#define _GNU_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h> // tolower
#include <math.h>

#ifndef LIBUSB_DETACH
/* detach the device from crappy kernel drivers */
#define LIBUSB_DETACH 1
#endif

#if USE_LIBUSB
#include <libusb-1.0/libusb.h>
#include <unistd.h>
#else
#include <Windows.h>
#include <setupapi.h>
#include "Wrapper.h"
#pragma comment(lib, "Setupapi.lib")
#define fseeko _fseeki64
#define ftello _ftelli64
BOOL FindPort(DWORD* pPort);
void usleep(unsigned int us);
#endif

#include "spd_cmd.h"

#define FLAGS_CRC16 1
#define FLAGS_TRANSCODE 2

#define ERR_EXIT(...) \
	do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)

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
	uint8_t* raw_buf, * enc_buf, * recv_buf, * temp_buf;
#if USE_LIBUSB
	libusb_device_handle* dev_handle;
	int endp_in, endp_out;
#else
	ClassHandle* handle;
#endif
	int flags, recv_len, recv_pos;
	int raw_len, enc_len, verbose, timeout;
} spdio_t;

typedef struct {
	uint32_t   dwVersion;
	uint32_t   bDisableHDLC;	//0: Enable hdl; 1:Disable hdl
	uint8_t    bIsOldMemory;
	uint8_t    bSupportRawData;
	uint8_t    bReserve[2];
	uint32_t   dwFlushSize;		//unit KB
	uint32_t   dwStorageType;
	uint32_t   dwReserve[59];	//Reserve
}DA_INFO_T;

void print_string(FILE* f, const void* src, size_t n);

#if USE_LIBUSB
void find_endpoints(libusb_device_handle* dev_handle, int result[2]);
#endif

spdio_t* spdio_init(int flags);
void spdio_free(spdio_t* io);

void encode_msg(spdio_t *io, int type, const void *data, size_t len);
int send_msg(spdio_t *io);
int recv_msg(spdio_t *io);
int recv_msg_timeout(spdio_t *io, int timeout);
unsigned recv_type(spdio_t *io);
void send_and_check(spdio_t *io);
void check_confirm(const char* name);
void send_file(spdio_t *io, const char *fn, uint32_t start_addr, int end_data, unsigned step);
unsigned dump_flash(spdio_t *io, uint32_t addr, uint32_t start, uint32_t len, const char *fn, unsigned step);
unsigned dump_mem(spdio_t *io, uint32_t start, uint32_t len, const char *fn, unsigned step);
uint64_t dump_partition(spdio_t *io, const char *name, uint64_t start, uint64_t len, const char *fn, unsigned step);
void dump_partitions(spdio_t* io, const char* fn, int* nand_info, int blk_size);
uint64_t read_pactime(spdio_t *io);
void partition_list(spdio_t *io, const char *fn);
void repartition(spdio_t *io, const char *fn);
void erase_partition(spdio_t *io, const char *name);
void load_partition(spdio_t *io, const char *name, const char *fn, unsigned step);
void load_nv_partition(spdio_t* io, const char* name, const char* fn, unsigned step);
int64_t find_partition_size(spdio_t *io, const char *name);
uint64_t str_to_size(const char *str);
uint64_t str_to_size_ubi(const char* str, int* nand_info);
void get_Da_Info(spdio_t* io);
