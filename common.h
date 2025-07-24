#pragma once
#define ARGC_MAX 8
#define ARGV_LEN 384

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h> // tolower
#include <math.h>
#include <time.h>

#include <Windows.h>
#include <Dbt.h>
#include <tchar.h>
#include <setupapi.h>
#include "Wrapper.h"
#define WM_RCV_CHANNEL_DATA WM_USER + 1


void usleep(unsigned int us);
#define fseeko _fseeki64
#define ftello _ftelli64
#define my_strstr wcsstr
#define my_strtoul wcstoul

#include "spd_cmd.h"

#define FLAGS_CRC16 1
#define FLAGS_TRANSCODE 2

#define ERR_EXIT(...) \
	do { fprintf(stderr, __VA_ARGS__); if (m_bOpened == 1) system("pause"); exit(1); } while (0)

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

typedef struct Packet {
	int msg_type;
	int length;
	uint8_t *data;
	int is_decoded; // for kick
	int allow_empty_reply; // always set when manually packing !
	int timeout; // always set when manually packing !
	unsigned rw_pack_len; //for dump_part/load_part
	struct Packet *next;
} Packet;

typedef struct {
	Packet *phead;
	Packet *ptail;
	int closed;
	CRITICAL_SECTION lock;
	CONDITION_VARIABLE not_empty;
} Queue;

typedef struct {
	ClassHandle *handle;
	HANDLE m_hOprEvent;
	DWORD m_dwRecvThreadID;
	HANDLE m_hRecvThreadState;
	HANDLE m_hRecvThread;
	DWORD iThread;
	HANDLE hThread;
	HANDLE m_hEncodeThread;
	HANDLE m_hSendRecvThread;
	int flags;
	int verbose, timeout, pack_timeout;
	partition_t *ptable;
	int part_count;
	Queue raw, encoded, decoded;
	Packet *cur_encoded_packet;
	Packet *last_encoded_packet;
	Packet *cur_decoded_packet;
	Packet *last_decoded_packet;
	int not_exit_w;
	uint8_t *raw_buf,*temp_buf;
	//below for dump_part/load_part
	HANDLE rw_hCountEvent;
	int rw_stop, rw_error, rw_count;
	uint64_t rw_start;
	uint64_t rw_len;
	uint64_t rw_done;
	FILE *rw_fptr;
	unsigned rw_step;
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

DWORD *FindPort(const char *USB_DL);
BOOL CreateRecvThread(spdio_t *io);
void DestroyRecvThread(spdio_t *io);
void print_string(FILE *f, const void *src, size_t n);
void ChangeMode(spdio_t *io, int ms, int bootmode, int at);

spdio_t *spdio_init(int flags);
void spdio_free(spdio_t *io);

void encode_msg(spdio_t *io, int type, const void *data, size_t len);
int recv_msg(spdio_t *io);
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

DWORD WINAPI ThrdFunc(LPVOID lpParam);
DWORD WINAPI EncodeThread(LPVOID lpParam);
DWORD WINAPI SendRecvThread(LPVOID lpParam);

void QueueInit(Queue *pq);
void QueueDestroy(Queue *pq);
void QueuePush(Queue *pq, Packet *in);
Packet *QueuePop(Queue *pq);
void QueueClose(Queue *pq);
