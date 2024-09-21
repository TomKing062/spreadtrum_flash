/*
// Spreadtrum SC6531E/SC6531DA firmware dumper for Linux.
//
// sudo modprobe ftdi_sio
// echo 1782 4d00 | sudo tee /sys/bus/usb-serial/drivers/generic/new_id
// make && sudo ./spd_dump [options] commands...
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
*/
#ifdef INTERACTIVE
#include "common.h"
#include "GITVER.h"
#define REOPEN_FREQ 2
extern char savepath[ARGC_LEN];
extern DA_INFO_T Da_Info;
int gpt_failed = 1;
int m_bOpened = 0;
int fdl2_executed = 0;
int selected_ab = -1;
int main(int argc, char **argv) {
	spdio_t *io = NULL; int ret, i, in_quote;
	int wait = 30 * REOPEN_FREQ;
	int fdl1_loaded = 0, argcount = 0, exec_addr = 0, stage = -1, nand_id = DEFAULT_NAND_ID;
	int nand_info[3];
	int keep_charge = 1, end_data = 1, blk_size = 0, skip_confirm = 1, baudrate = 0, highspeed = 0;
	char *temp;
	char str1[ARGC_MAX * ARGC_LEN];
	char str2[ARGC_MAX][ARGC_LEN];
	char execfile[40];
	int bootmode = -1;
	int part_count = 0;
	partition_t* ptable = NULL;
#if !USE_LIBUSB
	extern DWORD curPort;
#endif

	io = spdio_init(0);
#if USE_LIBUSB
	ret = libusb_init(NULL);
	if (ret < 0)
		ERR_EXIT("libusb_init failed: %s\n", libusb_error_name(ret));
#else
	io->handle = createClass();
	call_Initialize(io->handle);
#endif
	DBG_LOG("branch:%s, sha1:%s\n", GIT_VER, GIT_SHA1);
	while (argc > 1) {
		if (!strcmp(argv[1], "--wait")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			wait = atoi(argv[2]) * REOPEN_FREQ;
			argc -= 2; argv += 2;
		} else if (!strcmp(argv[1], "--verbose")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			io->verbose = atoi(argv[2]);
			argc -= 2; argv += 2;
		} else if (!strcmp(argv[1], "--stage")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			stage = atoi(argv[2]);
			argc -= 2; argv += 2;
#if !USE_LIBUSB
		} else if (!strcmp(argv[1], "--kick")) {
			if (argc <= 1) ERR_EXIT("bad option\n");
			bootmode = 2;
			argc -= 1; argv += 1;
		} else if (!strcmp(argv[1], "--kickto")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			bootmode = atoi(argv[2]);
			argc -= 2; argv += 2;
#endif
		} else break;
	}

#if _WIN32
	io->hThread = CreateThread(NULL, 0, ThrdFunc, NULL, 0, &io->iThread);
	if (io->hThread == NULL) {
		return -1;
	}
#endif
#if !USE_LIBUSB
	if (!curPort) FindPort();
	if (bootmode >= 0)
	{
		if (curPort) ERR_EXIT("kick feature needs program running before connecting device to PC\n");
		else ChangeMode(io, wait / REOPEN_FREQ * 1000, bootmode);
		wait = 10 * REOPEN_FREQ;
	}
#endif
	DBG_LOG("Waiting for connection (%ds)\n", wait / REOPEN_FREQ);
	for (i = 0; ; i++) {
#if USE_LIBUSB
		io->dev_handle = libusb_open_device_with_vid_pid(NULL, 0x1782, 0x4d00);
		if (io->dev_handle) break;
		if (i >= wait)
			ERR_EXIT("libusb_open_device failed\n");
#else
		if (io->verbose) DBG_LOG("CurTime: %.1f, CurPort: %d\n", (float)i / REOPEN_FREQ, curPort);
		if (curPort) break;
		if (i >= wait)
			ERR_EXIT("find port failed\n");
#endif
		usleep(1000000 / REOPEN_FREQ);
	}

#if USE_LIBUSB
	int endpoints[2];
	find_endpoints(io->dev_handle, endpoints);
	io->endp_in = endpoints[0];
	io->endp_out = endpoints[1];
#else
	call_ConnectChannel(io->handle, curPort);
#endif
	io->flags |= FLAGS_TRANSCODE;

	// Required for smartphones.
	// Is there a way to do the same with usb-serial?
#if USE_LIBUSB
	ret = libusb_control_transfer(io->dev_handle,
			0x21, 34, 0x601, 0, NULL, 0, io->timeout);
	if (ret < 0)
		ERR_EXIT("libusb_control_transfer failed : %s\n",
				libusb_error_name(ret));
	DBG_LOG("libusb_control_transfer ok\n");
#endif
	/* Bootloader (chk = crc16) */
	io->flags |= FLAGS_CRC16;

	switch (stage) {
	case 0:
		encode_msg(io, BSL_CMD_CONNECT, NULL, 0);
		if (send_and_check(io)) exit(1);
		DBG_LOG("CMD_CONNECT bootrom\n");
		break;
	case 1:
		io->flags &= ~FLAGS_CRC16;
		encode_msg(io, BSL_CMD_CONNECT, NULL, 0);
		if (send_and_check(io)) exit(1);
		DBG_LOG("CMD_CONNECT FDL1\n");
		fdl1_loaded = 1;
		break;
	case 2:
		io->flags &= ~FLAGS_CRC16;
		encode_msg(io, BSL_CMD_DISABLE_TRANSCODE, NULL, 0);
		if (!send_and_check(io)) {
			io->flags &= ~FLAGS_TRANSCODE;
			DBG_LOG("DISABLE_TRANSCODE\n");
		}
		fdl1_loaded = 1;
		fdl2_executed = 1;
		break;
	default:
		encode_msg(io, BSL_CMD_CHECK_BAUD, NULL, 1);
		send_msg(io);
		recv_msg(io);
		if (recv_type(io) != BSL_REP_VER)
			ERR_EXIT("wrong command or wrong mode detected, reboot your phone by pressing POWER and VOL_UP for 7-10 seconds.\n");
		DBG_LOG("CHECK_BAUD bootrom\n");

		DBG_LOG("BSL_REP_VER: ");
		print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
		if (!memcmp(io->raw_buf + 4, "SPRD4", 5)) { exec_addr = 0; fdl1_loaded = -1; fdl2_executed = -1; }

		encode_msg(io, BSL_CMD_CONNECT, NULL, 0);
		if (send_and_check(io)) exit(1);
		DBG_LOG("CMD_CONNECT bootrom\n");
		break;
	}

	while (1) {
		memset(str1, 0, sizeof(str1));
		memset(str2, 0, sizeof(str2));
		argcount = 1;
		in_quote = 0;

		if (fdl2_executed > 0)
			DBG_LOG("FDL2 >");
		else if (fdl1_loaded > 0)
			DBG_LOG("FDL1 >");
		else
			DBG_LOG("BROM >");
		ret = scanf( "%[^\n]", str1);
		while('\n' != getchar());

		temp = strtok(str1," ");
		while(temp)
		{
			if (temp[0] == '"')
			{
				in_quote = 1;
				temp += 1;
			}
			else if (in_quote)
			{
				strcat(str2[argcount], " ");
			}

			if (temp[strlen(temp) - 1] == '"')
			{
				in_quote = 0;
				temp[strlen(temp) - 1] = 0;
			}

			strcat(str2[argcount], temp);
			if (!in_quote) {
				argcount++;
				if (argcount == ARGC_MAX) break;
			}
			temp = strtok(NULL, " ");
		}

		if (!strncmp(str2[1], "sendloop", 8)) {
			const char* fn; uint32_t addr = 0; FILE* fi;
			if (argcount <= 3) { DBG_LOG("send FILE addr\n"); continue; }

			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); continue; }
			else fclose(fi);
			addr = strtoll(str2[3], NULL, 0);
			while (1) {
				send_file(io, fn, addr, 0, 528);
				addr -= 8;
			}
		}
		else if (!strncmp(str2[1], "send", 4)) {
			const char* fn; uint32_t addr = 0; FILE* fi;
			if (argcount <= 3) { DBG_LOG("send FILE addr\n"); continue; }

			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); continue; }
			else fclose(fi);
			addr = strtoll(str2[3], NULL, 0);
			send_file(io, fn, addr, 0, 528);
		}
		else if (!strncmp(str2[1], "fdl", 3)) {
			const char *fn; uint32_t addr = 0; FILE *fi;
			if (argcount <= 3) { DBG_LOG("fdl FILE addr\n");continue; }

			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n");continue; }
			else fclose(fi);

			addr = strtoll(str2[3], NULL, 0);

			if (fdl2_executed > 0) {
				DBG_LOG("FDL2 ALREADY EXECUTED, SKIP\n");
				continue;
			} else if (fdl1_loaded > 0) {
				send_file(io, fn, addr, end_data,
					blk_size ? blk_size : 528);
			} else {
				send_file(io, fn, addr, end_data, 528);
				if (addr == 0x5500 || addr == 0x65000800) highspeed = 1;

				i = 0;
				if (exec_addr) {
					send_file(io, execfile, exec_addr, 0, 528);
				} else {
					encode_msg(io, BSL_CMD_EXEC_DATA, NULL, 0);
					if (send_and_check(io)) exit(1);
				}
				DBG_LOG("EXEC FDL1\n");

				/* FDL1 (chk = sum) */
				io->flags &= ~FLAGS_CRC16;

				encode_msg(io, BSL_CMD_CHECK_BAUD, NULL, 1);
				while (1) {
					send_msg(io);
					recv_msg(io);
					if (recv_type(io) == BSL_REP_VER) break;
					DBG_LOG("CHECK_BAUD FAIL\n");
					if (i == 2) ERR_EXIT("wrong command or wrong mode detected, reboot your phone by pressing POWER and VOL_UP for 7-10 seconds.\n");
					usleep(500000);
					i++;
				}
				DBG_LOG("CHECK_BAUD FDL1\n");

				DBG_LOG("BSL_REP_VER: ");
				print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));

#if FDL1_DUMP_MEM
				//read dump mem
				int pagecount = 0;
				char* pdump;
				char chdump;
				FILE* fdump;
				fdump = fopen("ddd.bin", "wb");
				encode_msg(io, BSL_CMD_CHECK_BAUD, NULL, 1);
				while (1) {
					send_msg(io);
					ret = recv_msg(io);
					if (!ret) ERR_EXIT("timeout reached\n");
					if (recv_type(io) == BSL_CMD_READ_END) break;
					pdump = (char*)(io->raw_buf + 4);
					for (i = 0; i < 512; i++)
					{
						chdump = *(pdump++);
						if (chdump == 0x7d)
						{
							if (*pdump == 0x5d || *pdump == 0x5e) chdump = *(pdump++) + 0x20;
						}
						fputc(chdump, fdump);
					}
					DBG_LOG("dump page count %d\n", ++pagecount);
				}
				fclose(fdump);
				DBG_LOG("dump mem end\n");
				//end
#endif

				encode_msg(io, BSL_CMD_CONNECT, NULL, 0);
				if (send_and_check(io)) exit(1);
				DBG_LOG("CMD_CONNECT FDL1\n");
#if !USE_LIBUSB
				if (baudrate)
				{
					uint8_t data[4];
					WRITE32_BE(data, baudrate);
					encode_msg(io, BSL_CMD_CHANGE_BAUD, data, 4);
					if (!send_and_check(io)) {
						DBG_LOG("CHANGE_BAUD FDL1 to %d\n", baudrate);
						call_SetProperty(io->handle, 0, 100, (LPCVOID)&baudrate);
					}
				}
#endif
				if (keep_charge) {
					encode_msg(io, BSL_CMD_KEEP_CHARGE, NULL, 0);
					if (!send_and_check(io)) DBG_LOG("KEEP_CHARGE FDL1\n");
				}
				fdl1_loaded = 1;
			}

		} else if (!strcmp(str2[1], "exec")) {
			if (fdl2_executed > 0) {
				DBG_LOG("FDL2 ALREADY EXECUTED, SKIP\n");
				continue;
			} else if (fdl1_loaded > 0) {
				memset(&Da_Info, 0, sizeof(Da_Info));
				encode_msg(io, BSL_CMD_EXEC_DATA, NULL, 0);
				send_msg(io);
				// Feature phones respond immediately,
				// but it may take a second for a smartphone to respond.
				ret = recv_msg_timeout(io, 15000);
				if (!ret) ERR_EXIT("timeout reached\n");
				ret = recv_type(io);
				// Is it always bullshit?
				if (ret == BSL_REP_INCOMPATIBLE_PARTITION)
					get_Da_Info(io);
				else if (ret != BSL_REP_ACK)
					ERR_EXIT("unexpected response (0x%04x)\n", ret);
				DBG_LOG("EXEC FDL2\n");
				if (Da_Info.bDisableHDLC) {
					encode_msg(io, BSL_CMD_DISABLE_TRANSCODE, NULL, 0);
					if (!send_and_check(io)) {
						io->flags &= ~FLAGS_TRANSCODE;
						DBG_LOG("DISABLE_TRANSCODE\n");
					}
				}
				if (Da_Info.bSupportRawData == 2) {
					encode_msg(io, BSL_CMD_WRITE_RAW_DATA_ENABLE, NULL, 0);
					if (!send_and_check(io)) DBG_LOG("ENABLE_WRITE_RAW_DATA\n");
				}
				if (highspeed || Da_Info.dwStorageType == 0x103) {
					blk_size = 0xff00;
					ptable = partition_list(io, "partition.xml", &part_count);
				}
				else if (Da_Info.dwStorageType == 0x102) {
					ptable = partition_list(io, "partition.xml", &part_count);
				}
				if (nand_id == DEFAULT_NAND_ID) {
					nand_info[0] = (uint8_t)pow(2, nand_id & 3); //page size
					nand_info[1] = 32 / (uint8_t)pow(2, (nand_id >> 2) & 3); //spare area size
					nand_info[2] = 64 * (uint8_t)pow(2, (nand_id >> 4) & 3); //block size
				}
				fdl2_executed = 1;
			}
#if !USE_LIBUSB
		} else if (!strcmp(str2[1], "baudrate")) {
			if (argcount > 2)
			{
				baudrate = strtol(str2[2], NULL, 0);
				if (fdl2_executed) call_SetProperty(io->handle, 0, 100, (LPCVOID)&baudrate);
			}
			DBG_LOG("baudrate is %d\n", baudrate);
#endif
		} else if (!strcmp(str2[1], "path")) {
			if (argcount > 2) strcpy(savepath, str2[2]);
			DBG_LOG("save dir is %s\n", savepath);

		} else if (!strcmp(str2[1], "exec_addr")) {
			FILE* fi;
			if (0 == fdl1_loaded && argcount > 2) {
				exec_addr = strtol(str2[2], NULL, 0);
				memset(execfile, 0, sizeof(execfile));
				sprintf(execfile, "custom_exec_no_verify_%x.bin", exec_addr);
				fi = fopen(execfile, "r");
				if (fi == NULL) { DBG_LOG("%s does not exist\n", execfile);exec_addr = 0; }
				else fclose(fi);
			}
			DBG_LOG("current exec_addr is 0x%x\n", exec_addr);

		} else if (!strcmp(str2[1], "nand_id")) {
			if (argcount > 2) {
				nand_id = strtol(str2[2], NULL, 0);
				nand_info[0] = (uint8_t)pow(2, nand_id & 3); //page size
				nand_info[1] = 32 / (uint8_t)pow(2, (nand_id >> 2) & 3); //spare area size
				nand_info[2] = 64 * (uint8_t)pow(2, (nand_id >> 4) & 3); //block size
			}
			DBG_LOG("current nand_id is 0x%x\n", nand_id);

		} else if (!strcmp(str2[1], "read_flash")) {
			const char *fn; uint64_t addr, offset, size;
			if (argcount <= 5) { DBG_LOG("bad command\n");continue; }

			addr = str_to_size(str2[2]);
			offset = str_to_size(str2[3]);
			size = str_to_size(str2[4]);
			fn = str2[5];
			if ((addr | size | offset | (addr + offset + size)) >> 32)
				{ DBG_LOG("32-bit limit reached\n");continue; }
			dump_flash(io, addr, offset, size, fn,
					blk_size ? blk_size : 1024);

		} else if (!strcmp(str2[1], "read_mem")) {
			const char *fn; uint64_t addr, size;
			if (argcount <= 4) { DBG_LOG("bad command\n");continue; }

			addr = str_to_size(str2[2]);
			size = str_to_size(str2[3]);
			fn = str2[4];
			if ((addr | size | (addr + size)) >> 32)
				{ DBG_LOG("32-bit limit reached\n");continue; }
			dump_mem(io, addr, size, fn,
					blk_size ? blk_size : 1024);

		} else if (!strcmp(str2[1], "part_size")) {
			const char *name;
			if (argcount <= 2) { DBG_LOG("bad command\n");continue; }

			name = str2[2];
			find_partition_size(io, name);

		} else if (!strcmp(str2[1], "p") || !strcmp(str2[1], "print")) {
			if (part_count) {
				DBG_LOG("  0 %36s 256KB\n", "splloader");
				for (i = 0; i < part_count; i++) {
					DBG_LOG("%3d %36s %lldMB\n", i + 1, (*(ptable + i)).name, ((*(ptable + i)).size >> 20));
				}
			}

		} else if (!strcmp(str2[1], "read_part")) {
			const char *name, *fn; uint64_t offset, size;
			uint64_t realsize = 0;
			char name_ab[36];
			int verbose = io->verbose;
			if (argcount <= 5) { DBG_LOG("read_part part_name offset size FILE\n(read ubi on nand) read_part system 0 ubi40m system.bin\n");continue; }

			name = str2[2];
			if (selected_ab < 0) select_ab(io);
			io->verbose = 0;
			realsize = check_partition(io, name);
			if (!realsize) {
				if (selected_ab > 0) {
					sprintf(name_ab, "%s_%c", name, 96 + selected_ab);
					realsize = check_partition(io, name_ab);
					name = name_ab;
				}
				if (!realsize) {
					DBG_LOG("part not exist\n");
					io->verbose = verbose;
					argc -= 5; argv += 5;
					continue;
				}
			}
			offset = str_to_size_ubi(str2[3], nand_info);
			size = str_to_size_ubi(str2[4], nand_info);
			if (0xffffffff == size) size = find_partition_size(io, name);
			fn = str2[5];
			if (offset + size < offset)
				{ DBG_LOG("64-bit limit reached\n");continue; }
			io->verbose = verbose;
			dump_partition(io, name, offset, size, fn, blk_size ? blk_size : DEFAULT_BLK_SIZE);

		} else if (!strcmp(str2[1], "r")) {
			uint64_t realsize = 0;
			const char* name = str2[2];
			char name_ab[36];
			if (argcount <= 2) { DBG_LOG("r all/part_name/part_id\n"); continue; }
			if (gpt_failed == 1) ptable = partition_list(io, "partition.xml", &part_count);
			if (selected_ab > 0) sprintf(name_ab, "%s_%c", name, 96 + selected_ab);
			if (!memcmp(name, "splloader", 9)) {
				realsize = 256 * 1024;
			}
			else if (!part_count) {
				realsize = check_partition(io, name);
				if (!realsize) {
					if (selected_ab > 0) {
						realsize = check_partition(io, name_ab);
						name = name_ab;
					}
					if (!realsize) {
						DBG_LOG("part not exist\n");
						continue;
					}
				}
				realsize = find_partition_size(io, name);
			}
			else
			{
				if (isdigit(name[0])) {
					i = atoi(name);
					if (i > part_count) { DBG_LOG("part not exist\n"); continue; }
					if (i == 0) {
						name = "splloader";
						realsize = 256 * 1024;
					}
					else {
						name = (*(ptable + i - 1)).name;
						realsize = (*(ptable + i - 1)).size;
					}
				}
				else if (!strcmp(name, "preset_modem")) {
					for (i = 0; i < part_count; i++)
						if (0 == strncmp("l_", (*(ptable + i)).name, 2) || 0 == strncmp("nr_", (*(ptable + i)).name, 3)) {
							char dfile[40];
							sprintf(dfile, "%s.bin", (*(ptable + i)).name);
							dump_partition(io, (*(ptable + i)).name, 0, (*(ptable + i)).size, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
						}
					continue;
				}
				else if (!strcmp(name, "all")) {
					dump_partition(io, "splloader", 0, 256 * 1024, "splloader.bin", blk_size ? blk_size : DEFAULT_BLK_SIZE);
					for (i = 0; i < part_count; i++)
					{
						char dfile[40];
						if (!memcmp((*(ptable + i)).name, "blackbox", 8)) continue;
						else if (!memcmp((*(ptable + i)).name, "cache", 5)) continue;
						else if (!memcmp((*(ptable + i)).name, "userdata", 8)) continue;
						sprintf(dfile, "%s.bin", (*(ptable + i)).name);
						dump_partition(io, (*(ptable + i)).name, 0, (*(ptable + i)).size, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
					}
					continue;
				}
				else if (!strcmp(name, "all_lite")) {
					dump_partition(io, "splloader", 0, 256 * 1024, "splloader.bin", blk_size ? blk_size : DEFAULT_BLK_SIZE);
					for (i = 0; i < part_count; i++)
					{
						char dfile[40];
						size_t namelen = strlen((*(ptable + i)).name);
						if (!memcmp((*(ptable + i)).name, "blackbox", 8)) continue;
						else if (!memcmp((*(ptable + i)).name, "cache", 5)) continue;
						else if (!memcmp((*(ptable + i)).name, "userdata", 8)) continue;
						if (selected_ab == 1 && namelen > 2 && 0 == strcmp((*(ptable + i)).name + namelen - 2, "_b")) continue;
						else if (selected_ab == 2 && namelen > 2 && 0 == strcmp((*(ptable + i)).name + namelen - 2, "_a")) continue;
						sprintf(dfile, "%s.bin", (*(ptable + i)).name);
						dump_partition(io, (*(ptable + i)).name, 0, (*(ptable + i)).size, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
					}
					continue;
				}
				else {
					for (i = 0; i < part_count; i++) {
						if (!strcmp(name, (*(ptable + i)).name)) {
							realsize = (*(ptable + i)).size;
							break;
						}
						if (!strcmp(name_ab, (*(ptable + i)).name)) {
							realsize = (*(ptable + i)).size;
							name = name_ab;
							break;
						}
					}
					if (i == part_count) { DBG_LOG("part not exist\n"); continue; }
				}
			}
			char dfile[40];
			sprintf(dfile, "%s.bin", name);
			dump_partition(io, name, 0, realsize, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);

		} else if (!strcmp(str2[1], "read_parts")) {
			const char* fn; FILE* fi;
			if (argcount <= 2) { DBG_LOG("read_parts partition_list_file\n\t(ufs/emmc) read_parts part.xml\n\t(ubi) read_parts ubipart.xml\n"); continue; }
			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); continue; }
			else fclose(fi);
			dump_partitions(io, fn, nand_info, blk_size ? blk_size : DEFAULT_BLK_SIZE);

		} else if (!strcmp(str2[1], "partition_list")) {
			if (argcount <= 2) { DBG_LOG("partition_list FILE\n");continue; }
			if (gpt_failed < 1) { DBG_LOG("partition_list shouldn't run twice\n"); continue; }
			ptable = partition_list(io, str2[2], &part_count);

		} else if (!strcmp(str2[1], "repartition")) {
			const char *fn;FILE *fi;
			if (argcount <= 2) { DBG_LOG("repartition FILE\n");continue; }
			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n");continue; }
			else fclose(fi);
			if (skip_confirm) repartition(io, str2[2]);
			else if (check_confirm("repartition")) repartition(io, str2[2]);

		} else if (!strcmp(str2[1], "erase_part") || !strcmp(str2[1], "e")) {
			uint64_t realsize = 0;
			const char* name = str2[2];
			char name_ab[36];
			int verbose = io->verbose;
			if (argcount <= 2) { DBG_LOG("erase_part part_name/part_id\n");continue; }
			if (selected_ab < 0) select_ab(io);
			i = -1;
			if (isdigit(name[0])) {
				if (part_count) i = atoi(name);
				else { DBG_LOG("gpt table is empty\n"); continue; }
				if (i > part_count) { DBG_LOG("part not exist\n"); continue; }
			}
			if (!skip_confirm)
				if (!check_confirm("erase partition"))
					continue;
			if (i == 0) erase_partition(io, "splloader");
			else if (i > 0) erase_partition(io, (*(ptable + i - 1)).name);
			else {
				io->verbose = 0;
				realsize = check_partition(io, name);
				if (!realsize) {
					if (selected_ab > 0) {
						sprintf(name_ab, "%s_%c", name, 96 + selected_ab);
						realsize = check_partition(io, name_ab);
						name = name_ab;
					}
					if (!realsize) { DBG_LOG("part not exist\n"); io->verbose = verbose; continue; }
				}
				io->verbose = verbose;
				erase_partition(io, name);
			}

		} else if (!strcmp(str2[1], "write_part") || !strcmp(str2[1], "w")) {
			const char *fn;FILE *fi;
			uint64_t realsize = 0;
			const char* name = str2[2];
			char name_ab[36];
			int verbose = io->verbose;
			if (argcount <= 3) { DBG_LOG("write_part part_name/part_id FILE\n");continue; }
			fn = str2[3];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n");continue; }
			else fclose(fi);
			if (selected_ab < 0) select_ab(io);
			i = -1;
			if (isdigit(name[0])) {
				if (part_count) i = atoi(name);
				else { DBG_LOG("gpt table is empty\n"); continue; }
				if (i > part_count) { DBG_LOG("part not exist\n"); continue; }
			}
			if (!skip_confirm)
				if (!check_confirm("write partition"))
					continue;
			if (i == 0) load_partition(io, "splloader", str2[3], 4096);
			else if (i > 0) {
				if (strstr((*(ptable + i)).name, "nv1")) load_nv_partition(io, (*(ptable + i)).name, str2[3], 4096);
				else load_partition(io, (*(ptable + i)).name, str2[3], blk_size ? blk_size : DEFAULT_BLK_SIZE);
			}
			else {
				io->verbose = 0;
				realsize = check_partition(io, name);
				if (!realsize) {
					if (selected_ab > 0) {
						sprintf(name_ab, "%s_%c", name, 96 + selected_ab);
						realsize = check_partition(io, name_ab);
						name = name_ab;
					}
					if (!realsize) { DBG_LOG("part not exist\n"); io->verbose = verbose; continue; }
				}
				io->verbose = verbose;
				if (strstr(name, "nv1")) load_nv_partition(io, name, str2[3], 4096);
				else load_partition(io, name, str2[3], blk_size ? blk_size : DEFAULT_BLK_SIZE);
			}

		} else if (!strcmp(str2[1], "write_parts")) {
			if (argcount <= 2) { DBG_LOG("write_parts save_location\n");continue; }
			if (skip_confirm) load_partitions(io, str2[2], blk_size ? blk_size : DEFAULT_BLK_SIZE);
			else if (check_confirm("write all partitions")) load_partitions(io, str2[2], blk_size ? blk_size : DEFAULT_BLK_SIZE);

		} else if (!strcmp(str2[1], "read_pactime")) {
			read_pactime(io);

		} else if (!strcmp(str2[1], "blk_size")) {
			if (argcount <= 2) { DBG_LOG("blk_size byte\n\tmax is 65535\n");continue; }
			blk_size = strtol(str2[2], NULL, 0);
			blk_size = blk_size < 0 ? 0 :
					blk_size > 0xffff ? 0xffff : blk_size;

		} else if (!strcmp(str2[1], "verity")) {
			if (argcount <= 2) { DBG_LOG("verity {0,1}\n"); continue; }
			if (atoi(str2[2])) dm_enable(io, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			else
			{
				DBG_LOG("Warning: disable dm-verity needs a write-verification-disabled FDL2\n");
				if (!skip_confirm)
					if (!check_confirm("disable dm-verity"))
						continue;
				dm_disable(io, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			}

		} else if (!strcmp(str2[1], "skip_confirm")) {
			if (argcount <= 2) { DBG_LOG("skip_confirm {0,1}\n"); continue; }
			skip_confirm = atoi(str2[2]);

		} else if (!strcmp(str2[1], "rawdata")) {
			if (argcount <= 2) { DBG_LOG("rawdata {0,1,2}\n"); continue; }
			Da_Info.bSupportRawData = atoi(str2[2]);

		} else if (!strcmp(str2[1], "chip_uid")) {
			encode_msg(io, BSL_CMD_READ_CHIP_UID, NULL, 0);
			send_msg(io);
			ret = recv_msg(io);
			if (!ret) ERR_EXIT("timeout reached\n");
			if ((ret = recv_type(io)) != BSL_REP_READ_CHIP_UID)
				{ DBG_LOG("unexpected response (0x%04x)\n", ret);continue; }

			DBG_LOG("BSL_REP_READ_CHIP_UID: ");
			print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));

		} else if (!strcmp(str2[1], "disable_transcode")) {
			encode_msg(io, BSL_CMD_DISABLE_TRANSCODE, NULL, 0);
			if (!send_and_check(io)) io->flags &= ~FLAGS_TRANSCODE;

		} else if (!strcmp(str2[1], "transcode")) {
			unsigned a, f;
			if (argcount <= 2) { DBG_LOG("bad command\n");continue; }
			a = atoi(str2[2]);
			if (a >> 1) { DBG_LOG("bad command\n");continue; }
			f = (io->flags & ~FLAGS_TRANSCODE);
			io->flags = f | (a ? FLAGS_TRANSCODE : 0);

		} else if (!strcmp(str2[1], "keep_charge")) {
			if (argcount <= 2) { DBG_LOG("keep_charge {0,1}\n");continue; }
			keep_charge = atoi(str2[2]);

		} else if (!strcmp(str2[1], "timeout")) {
			if (argcount <= 2) { DBG_LOG("timeout ms\n");continue; }
			io->timeout = atoi(str2[2]);

		} else if (!strcmp(str2[1], "end_data")) {
			if (argcount <= 2) { DBG_LOG("end_data {0,1}\n");continue; }
			end_data = atoi(str2[2]);

		} else if (!strcmp(str2[1], "reset")) {
			if (!fdl1_loaded) {
				DBG_LOG("FDL NOT READY\n");
				continue;
			}
			encode_msg(io, BSL_CMD_NORMAL_RESET, NULL, 0);
			if (!send_and_check(io)) break;

		} else if (!strcmp(str2[1], "poweroff")) {
			if (!fdl1_loaded) {
				DBG_LOG("FDL NOT READY\n");
				continue;
			}
			encode_msg(io, BSL_CMD_POWER_OFF, NULL, 0);
			if (!send_and_check(io)) break;

		} else if (!strcmp(str2[1], "verbose")) {
			if (argcount <= 2) { DBG_LOG("verbose {0,1,2}\n");continue; }
			io->verbose = atoi(str2[2]);

		} else if (strlen(str2[1])){
#if !USE_LIBUSB
			DBG_LOG("baudrate [rate]\n");
#endif
			DBG_LOG("exec_addr [addr]\n\tbrom stage only\n");
			DBG_LOG("fdl FILE addr\n");
			DBG_LOG("exec\n");
			DBG_LOG("path [save_location]\n\tfor r/read_part(s)/read_flash/read_mem\n");
			DBG_LOG("r all/part_name/part_id\n");
			DBG_LOG("w part_name/part_id FILE\n");
			DBG_LOG("e part_name/part_id\n");
			DBG_LOG("read_part part_name offset size FILE\n");
			DBG_LOG("(read ubi on nand) read_part system 0 ubi40m system.bin\n");
			DBG_LOG("read_parts partition_list_file\n\t(ufs/emmc) read_parts part.xml\n\t(ubi) read_parts ubipart.xml\n");
			DBG_LOG("write_part part_name/part_id FILE\n");
			DBG_LOG("write_parts save_location\n\twrite all partitions dumped by read_parts\n");
			DBG_LOG("erase_part part_name/part_id\n");
			DBG_LOG("partition_list FILE\n");
			DBG_LOG("repartition FILE\n");
			DBG_LOG("reset\n");
			DBG_LOG("poweroff\n");
			DBG_LOG("timeout ms\n");
			DBG_LOG("verity {0,1}\n\tdisable/enable dm-verity\n");
			DBG_LOG("skip_confirm {0,1}\n");
			DBG_LOG("rawdata {0,1,2}\n\tfdl2 stage only\n");
			DBG_LOG("blk_size byte\n\tfdl2 stage only, max is 65535\n");
			DBG_LOG("nand_id [id]\n");
			DBG_LOG("disable_transcode\n");
			DBG_LOG("keep_charge {0,1}\n");
			DBG_LOG("end_data {0,1}\n");
			DBG_LOG("verbose {0,1,2}\n");
		}
#if _WIN32
		if (m_bOpened == -1) {
			DBG_LOG("device removed, exiting...\n");
			break;
		}
#endif
	}
	free(ptable);
	spdio_free(io);
	return 0;
}
#endif
