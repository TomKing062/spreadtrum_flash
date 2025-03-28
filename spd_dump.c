/*
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
*/
#include "common.h"
#include "GITVER.h"

void print_help(void)
{
	DBG_LOG(
		"Usage\n"
		"\tspd_dump [OPTIONS] [COMMANDS] [EXIT COMMANDS]\n"
		"\nExamples\n"
		"\tOne-line mode\n"
		"\t\tspd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec path savepath r all_lite reset\n"
		"\tInteractive mode\n"
		"\t\tspd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec\n"
		"\tThen the prompt should display FDL2>.\n"
		"\nOptions\n"
		"\t--wait <seconds>\n"
		"\t\tSpecifies the time to wait for the device to connect.\n"
		"\t--stage <number>|-r|--reconnect\n"
		"\t\tTry to reconnect device in brom/fdl1/fdl2 stage. Any number behaves the same way.\n"
		"\t\t(unstable, a device in brom/fdl1 stage can be reconnected infinite times, but only once in fdl2 stage)\n"
		"\t--verbose <level>\n"
		"\t\tSets the verbosity level of the output (supports 0, 1, or 2).\n"
		"\t--kick\n"
		"\t\tConnects the device using the route boot_diag -> cali_diag -> dl_diag.\n"
		"\t--kickto <mode>\n"
		"\t\tConnects the device using a custom route boot_diag -> custom_diag. Supported modes are 0-127.\n"
		"\t\t(mode 0 is `kickto 2` on ums9621, mode 1 = cali_diag, mode 2 = dl_diag; not all devices support mode 2).\n"
		"\t-?|-h|--help\n"
		"\t\tShow help and usage information\n"
		"\nRuntime Commands\n"
		"\tverbose level\n"
		"\t\tSets the verbosity level of the output (supports 0, 1, or 2).\n"
		"\ttimeout ms\n"
		"\t\tSets the command timeout in milliseconds.\n"
		"\tbaudrate [rate]\n\t\t(Windows SPRD driver only, and brom/fdl2 stage only)\n"
		"\t\tSupported baudrates are 57600, 115200, 230400, 460800, 921600, 1000000, 2000000, 3250000, and 4000000.\n"
		"\t\tWhile in u-boot/littlekernel source code, only 115200, 230400, 460800, and 921600 are listed.\n"
		"\texec_addr [addr]\n\t\t(brom stage only)\n"
		"\t\tSends custom_exec_no_verify_addr.bin to the specified memory address to bypass the signature verification by brom for splloader/fdl1.\n"
		"\t\tUsed for CVE-2022-38694.\n"
		"\tfdl FILE addr\n"
		"\t\tSends a file (splloader, fdl1, fdl2, sml, trustos, teecfg) to the specified memory address.\n"
		"\texec\n"
		"\t\tExecutes a sent file in the fdl1 stage. Typically used with sml or fdl2 (also known as uboot/lk).\n"
		"\tpath [save_location]\n"
		"\t\tChanges the save directory for commands like r, read_part(s), read_flash, and read_mem.\n"
		"\tnand_id [id]\n"
		"\t\tSpecifies the 4th NAND ID, affecting read_part(s) size calculation, default value is 0x15.\n"
		"\trawdata {0,1,2}\n\t\t(fdl2 stage only)\n"
		"\t\tRawdata protocol helps speed up `w` and `write_part(s)` commands, when rawdata > 0, `blk_size` will not effect write speed.\n"
		"\t\t(rawdata relays on u-boot/lk, so don't set it manually.\n"
		"\tblk_size byte\n\t\t(fdl2 stage only)\n"
		"\t\tSets the block size, with a maximum of 65535 bytes. This option helps speed up `r`, `w`,`read_part(s)` and `write_part(s)` commands.\n"
		"\tr all|part_name|part_id\n"
		"\t\tWhen the partition table is available:\n"
		"\t\t\tr all: full backup (excludes blackbox, cache, userdata)\n"
		"\t\t\tr all_lite: full backup (excludes inactive slot partitions, blackbox, cache, and userdata)\n"
		"\t\tWhen the partition table is unavailable:\n"
		"\t\t\tr will auto-calculate part size (supports all partitions on emmc/ufs and only ubipac on NAND).\n"
		"\tread_part part_name|part_id offset size FILE\n"
		"\t\tReads a specific partition to a file at the given offset and size.\n"
		"\t\t(read ubi on nand) read_part system 0 ubi40m system.bin\n"
		"\tread_parts partition_list_file\n"
		"\t\tReads partitions from a list file (If the file name starts with \"ubi\", the size will be calculated using the NAND ID).\n"
		"\tw|write_part part_name|part_id FILE\n"
		"\t\tWrites the specified file to a partition.\n"
		"\twrite_parts save_location\n"
		"\t\tWrites all partitions dumped by read_parts.\n"
		"\te|erase_part part_name|part_id\n"
		"\t\tErases the specified partition.\n"
		"\tpartition_list FILE\n"
		"\t\tRead the partition list on emmc/ufs, not all fdl2 supports this command.\n"
		"\trepartition partition_list_xml\n"
		"\t\tRepartitions based on partition list XML.\n"
		"\tp|print\n"
		"\t\tPrints partition_list\n"
		"\tverity {0,1}\n"
		"\t\tEnables or disables dm-verity on android 10(+).\n"
		"\nExit Commands\n"
		"\t(Usable mainly in FDL2 stage; only new FDL1 supports exit)\n"
		"\treset\n"
		"\tpoweroff\n"
	);
}

#define REOPEN_FREQ 2
extern char savepath[ARGV_LEN];
extern DA_INFO_T Da_Info;
int bListenLibusb = -1;
int gpt_failed = 1;
int m_bOpened = 0;
int fdl1_loaded = 0;
int fdl2_executed = 0;
int selected_ab = -1;
uint64_t fblk_size = 0;
int main(int argc, char **argv) {
	spdio_t *io = NULL; int ret, i, in_quote;
	int wait = 30 * REOPEN_FREQ;
	int argcount = 0, stage = -1, nand_id = DEFAULT_NAND_ID;
	int nand_info[3];
	int keep_charge = 1, end_data = 1, blk_size = 0, skip_confirm = 1, highspeed = 0;
	unsigned exec_addr = 0, baudrate = 0;
	char *temp;
	char str1[(ARGC_MAX - 1) * ARGV_LEN];
	char **str2;
	char *execfile;
	char fn_partlist[40];
	int bootmode = -1, at = 0;
	int part_count = 0;
	partition_t* ptable = NULL;
#if !USE_LIBUSB
	extern DWORD curPort;
	extern DWORD* ports;
#else
	extern libusb_device* curPort;
	extern libusb_device** ports;
#endif
	execfile = malloc(ARGV_LEN);
	if (!execfile) ERR_EXIT("malloc failed\n");

	io = spdio_init(0);
#if USE_LIBUSB
#ifdef __ANDROID__
	int xfd = -1; // This store termux gived fd
	//libusb_device_handle *handle; // Use spdio_t.dev_handle
	//libusb_device* device; //use curPort
	struct libusb_device_descriptor desc;
	libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
#endif
	ret = libusb_init(NULL);
	if (ret < 0)
		ERR_EXIT("libusb_init failed: %s\n", libusb_error_name(ret));
#else
	io->handle = createClass();
	call_Initialize(io->handle);
#endif
	DBG_LOG("branch:%s, sha1:%s\n", GIT_VER, GIT_SHA1);
	sprintf(fn_partlist, "partition_%lld.xml", (long long)time(NULL));
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
			stage = 99;
			argc -= 2; argv += 2;
		} else if (strstr(argv[1], "-r")) {
			if (argc <= 1) ERR_EXIT("bad option\n");
			stage = 99;
			argc -= 1; argv += 1;
		} else if (strstr(argv[1], "help") || strstr(argv[1], "-h") || strstr(argv[1], "-?")) {
			if (argc <= 1) ERR_EXIT("bad option\n");
			print_help();
			return 0;
#ifdef __ANDROID__
		} else if (!strcmp(argv[1], "--usb-fd")) { // Termux spec
			if (argc <= 2) ERR_EXIT("bad option\n");
			xfd = atoi(argv[argc - 1]);
			argc -= 2; argv += 1;
#endif
		} else if (!strcmp(argv[1], "--kick")) {
			if (argc <= 1) ERR_EXIT("bad option\n");
			at = 1;
			argc -= 1; argv += 1;
		} else if (!strcmp(argv[1], "--kickto")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			bootmode = atoi(argv[2]); at = 0;
			argc -= 2; argv += 2;
		} else break;
	}
#if defined(_DEBUG) && defined(USE_LIBUSB)
	io->verbose = 2;
#endif
	if (stage == 99) { bootmode = -1; at = 0; }
#ifdef __ANDROID__
	bListenLibusb = 0;
	DBG_LOG("Try to convert termux transfered usb port fd.\n");
	// handle
	if (xfd < 0)
		ERR_EXIT("Example: termux-usb -e \"./spd_dump --usb-fd\" /dev/bus/usb/xxx/xxx\n"
			"run on android need provide --usb-fd\n");

	if (libusb_wrap_sys_device(NULL, (intptr_t)xfd, &io->dev_handle))
		ERR_EXIT("libusb_wrap_sys_device exit unconditionally!\n");

	curPort = libusb_get_device(io->dev_handle);
	if (libusb_get_device_descriptor(curPort, &desc))
		ERR_EXIT("libusb_get_device exit unconditionally!");

	DBG_LOG("Vendor ID: %04x\nProduct ID: %04x\n", desc.idVendor, desc.idProduct);
	if (desc.idVendor != 0x1782 || desc.idProduct != 0x4d00) {
		ERR_EXIT("It seems spec device not a spd device!\n");
	}
	call_Initialize_libusb(io);
#else
#if !USE_LIBUSB
	bListenLibusb = 0;
	if (at || bootmode >= 0)
	{
		io->hThread = CreateThread(NULL, 0, ThrdFunc, NULL, 0, &io->iThread);
		if (io->hThread == NULL) return -1;
		ChangeMode(io, wait / REOPEN_FREQ * 1000, bootmode, at);
		wait = 30 * REOPEN_FREQ;
		stage = -1;
	}
	else
	{
		curPort = FindPort("SPRD U2S Diag");
		if (curPort)
		{
			for (DWORD* port = ports; *port != 0; port++)
			{
				if (call_ConnectChannel(io->handle, *port))
				{
					curPort = *port;
					break;
				}
			}
			if (!m_bOpened) curPort = 0;
			free(ports);
			ports = NULL;
		}
	}
#else
	if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) { DBG_LOG("hotplug unsupported on this platform\n"); bListenLibusb = 0; bootmode = -1; at = 0; }
	if (at || bootmode >= 0)
	{
		startUsbEventHandle();
		ChangeMode(io, wait / REOPEN_FREQ * 1000, bootmode, at);
		wait = 30 * REOPEN_FREQ;
		stage = -1;
	}
	else
	{
		curPort = FindPort();
		if (curPort != NULL)
		{
			for (libusb_device** port = ports; *port != NULL; port++)
			{
				if (libusb_open(*port, &io->dev_handle) >= 0) {
					call_Initialize_libusb(io);
					curPort = *port;
					break;
				}
			}
			if (!m_bOpened) curPort = 0;
			free(ports);
			ports = NULL;
		}
	}
	if (bListenLibusb < 0) startUsbEventHandle();
#endif
#if _WIN32
	if (!bListenLibusb) {
		if (io->hThread == NULL) io->hThread = CreateThread(NULL, 0, ThrdFunc, NULL, 0, &io->iThread);
		if (io->hThread == NULL) return -1;
	}
#endif
	if (!m_bOpened) {
		DBG_LOG("Waiting for dl_diag connection (%ds)\n", wait / REOPEN_FREQ);
		for (i = 0; ; i++) {
#if USE_LIBUSB
			if (bListenLibusb) {
				if (curPort) {
					if (libusb_open(curPort, &io->dev_handle) >= 0) call_Initialize_libusb(io);
					else ERR_EXIT("Connection failed\n");
					break;
				}
			}
			else {
				io->dev_handle = libusb_open_device_with_vid_pid(NULL, 0x1782, 0x4d00);
				if (io->dev_handle) {
					curPort = libusb_get_device(io->dev_handle);
					call_Initialize_libusb(io);
					break;
				}
			}
			if (i >= wait)
				ERR_EXIT("libusb_open_device failed\n");
#else
			if (io->verbose) DBG_LOG("CurTime: %.1f, CurPort: %d\n", (float)i / REOPEN_FREQ, curPort);
			if (curPort) {
				if (!call_ConnectChannel(io->handle, curPort)) ERR_EXIT("Connection failed\n");
				break;
			}
			if (i >= wait)
				ERR_EXIT("find port failed\n");
#endif
			usleep(1000000 / REOPEN_FREQ);
		}
	}
#endif
	io->flags |= FLAGS_TRANSCODE;
	io->flags &= ~FLAGS_CRC16;
	if (stage != -1) encode_msg(io, BSL_CMD_CONNECT, NULL, 0);
	else encode_msg(io, BSL_CMD_CHECK_BAUD, NULL, 1);
	for (i = 0; ; i++) {
		if (io->recv_buf[2] == BSL_REP_VER)
		{
			ret = BSL_REP_VER;
			io->flags |= FLAGS_CRC16;
			memcpy(io->raw_buf + 4, io->recv_buf + 5, 5);
			io->raw_buf[2] = 0;
			io->raw_buf[3] = 5;
		} else {
			send_msg(io);
			recv_msg(io);
			ret = recv_type(io);
		}
		if (ret == BSL_REP_ACK || ret == BSL_REP_VER || ret == BSL_REP_VERIFY_ERROR)
		{
			if (ret == BSL_REP_VER)
			{
				if (fdl1_loaded == 1)
				{
					DBG_LOG("CHECK_BAUD FDL1\n");
					if (!memcmp(io->raw_buf + 4, "SPRD4", 5)) fdl2_executed = -1;
				}
				else
				{
					DBG_LOG("CHECK_BAUD bootrom\n");
					if (!memcmp(io->raw_buf + 4, "SPRD4", 5)) { fdl1_loaded = -1; fdl2_executed = -1; }
				}
				DBG_LOG("BSL_REP_VER: ");
				print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));

				encode_msg(io, BSL_CMD_CONNECT, NULL, 0);
				if (send_and_check(io)) exit(1);
			}
			else if (ret == BSL_REP_VERIFY_ERROR)
			{
				encode_msg(io, BSL_CMD_CONNECT, NULL, 0);
				if (fdl1_loaded != 1)
				{
					if (send_and_check(io)) exit(1);
				}
				else { i = -1; continue; }
			}

			if (fdl1_loaded == 1)
			{
				DBG_LOG("CMD_CONNECT FDL1\n");
				if (keep_charge) {
					encode_msg(io, BSL_CMD_KEEP_CHARGE, NULL, 0);
					if (!send_and_check(io)) DBG_LOG("KEEP_CHARGE FDL1\n");
				}
			}
			else DBG_LOG("CMD_CONNECT bootrom\n");
			break;
		}
		else if (ret == BSL_REP_UNSUPPORTED_COMMAND)
		{
			encode_msg(io, BSL_CMD_DISABLE_TRANSCODE, NULL, 0);
			if (!send_and_check(io)) {
				io->flags &= ~FLAGS_TRANSCODE;
				DBG_LOG("DISABLE_TRANSCODE\n");
			}
			fdl2_executed = 1;
			break;
		}
		else if (i == 4)
		{
			if (stage != -1) ERR_EXIT("wrong command or wrong mode detected, reboot your phone by pressing POWER and VOL_UP for 7-10 seconds.\n");
			else { encode_msg(io, BSL_CMD_CONNECT, NULL, 0); stage++; i = -1; }
		}
	}

	char** save_argv = NULL;
	if (fdl1_loaded == -1) argc += 2;
	if (fdl2_executed == -1) argc += 1;
	while (1) {
		if (argc > 1)
		{
			str2 = (char**)malloc(argc * sizeof(char*));
			if (fdl1_loaded == -1) {
				save_argv = argv;
				str2[1] = "loadfdl";
				str2[2] = "0x0";
			}
			else if (fdl2_executed == -1) {
				if (!save_argv) save_argv = argv;
				str2[1] = "exec";
			}
			else {
				if (save_argv) { argv = save_argv; save_argv = NULL; }
				for (i = 1; i < argc; i++) str2[i] = argv[i];
			}
			argcount = argc;
			in_quote = -1;
		}
		else
		{
			char ifs = '"';
			str2 = (char**)malloc(ARGC_MAX * sizeof(char*));
			memset(str1, 0, sizeof(str1));
			argcount = 0;
			in_quote = 0;

			if (fdl2_executed > 0)
				DBG_LOG("FDL2 >");
			else if (fdl1_loaded > 0)
				DBG_LOG("FDL1 >");
			else
				DBG_LOG("BROM >");
			ret = scanf("%[^\n]", str1);
			while ('\n' != getchar());

			temp = strtok(str1, " ");
			while (temp)
			{
				if (!in_quote) {
					argcount++;
					if (argcount == ARGC_MAX) break;
					str2[argcount] = (char*)malloc(ARGV_LEN);
					if (!str2[argcount]) ERR_EXIT("malloc failed\n");
					memset(str2[argcount], 0, ARGV_LEN);
				}
				if (temp[0] == '\'') ifs = '\'';
				if (temp[0] == ifs)
				{
					in_quote = 1;
					temp += 1;
				}
				else if (in_quote)
				{
					strcat(str2[argcount], " ");
				}

				if (temp[strlen(temp) - 1] == ifs)
				{
					in_quote = 0;
					temp[strlen(temp) - 1] = 0;
				}

				strcat(str2[argcount], temp);
				temp = strtok(NULL, " ");
			}
			argcount++;
		}
		if (argcount == 1)
		{
			str2[1] = malloc(1);
			if (str2[1]) str2[1][0] = '\0';
			else ERR_EXIT("malloc failed\n");
			argcount++;
		}

		if (!strcmp(str2[1], "sendloop")) {
			const char* fn; uint32_t addr = 0; FILE* fi;
			if (argcount <= 3) { DBG_LOG("sendloop FILE addr\n"); argc -= 3; argv += 3; continue; }

			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 3; argv += 3; continue; }
			else fclose(fi);
			addr = strtoul(str2[3], NULL, 0);
			while (1) {
				send_file(io, fn, addr, 0, 528);
				addr -= 8;
			}
			argc -= 3; argv += 3;
		}
		else if (!strcmp(str2[1], "send")) {
			const char* fn; uint32_t addr = 0; FILE* fi;
			if (argcount <= 3) { DBG_LOG("send FILE addr\n"); argc -= 3; argv += 3; continue; }

			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 3; argv += 3; continue; }
			else fclose(fi);
			addr = strtoul(str2[3], NULL, 0);
			send_file(io, fn, addr, 0, 528);
			argc -= 3; argv += 3;
		}
		else if (!strncmp(str2[1], "fdl", 3) || !strncmp(str2[1], "loadfdl", 7)) {
			const char *fn; uint32_t addr = 0; FILE *fi;
			int addr_in_name = !strncmp(str2[1], "loadfdl", 7);
			int argchange;

			fn = str2[2];
			if (addr_in_name) {
				argchange = 2;
				if (argcount <= argchange) { DBG_LOG("loadfdl FILE\n"); argc -= argchange; argv += argchange; continue; }
				char* pos = NULL, * last_pos = NULL;

				pos = strstr(fn, "0X");
				while (pos) {
					last_pos = pos;
					pos = strstr(pos + 2, "0X");
				}
				if (last_pos == NULL) {
					pos = strstr(fn, "0x");
					while (pos) {
						last_pos = pos;
						pos = strstr(pos + 2, "0x");
					}
				}
				if (last_pos) addr = strtoul(last_pos, NULL, 16);
				else { DBG_LOG("\"0x\" not found in name.\n"); argc -= argchange; argv += argchange; continue; }
			}
			else {
				argchange = 3;
				if (argcount <= argchange) { DBG_LOG("fdl FILE addr\n"); argc -= argchange; argv += argchange; continue; }
				addr = strtoul(str2[3], NULL, 0);
			}

			if (fdl2_executed > 0) {
				DBG_LOG("FDL2 ALREADY EXECUTED, SKIP\n");
				argc -= argchange; argv += argchange;
				continue;
			} else if (fdl1_loaded > 0) {
				if (fdl2_executed != -1)
				{
					fi = fopen(fn, "r");
					if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= argchange; argv += argchange; continue; }
					else fclose(fi);
					send_file(io, fn, addr, end_data, blk_size ? blk_size : 528);
				}
			} else {
				if (fdl1_loaded != -1)
				{
					fi = fopen(fn, "r");
					if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= argchange; argv += argchange; continue; }
					else fclose(fi);
					send_file(io, fn, addr, end_data, 528);
					if (exec_addr) {
						send_file(io, execfile, exec_addr, 0, 528);
						free(execfile);
					} else {
						encode_msg(io, BSL_CMD_EXEC_DATA, NULL, 0);
						if (send_and_check(io)) exit(1);
					}
				}
				else
				{
					encode_msg(io, BSL_CMD_EXEC_DATA, NULL, 0);
					if (send_and_check(io)) exit(1);
				}
				DBG_LOG("EXEC FDL1\n");
				if (addr == 0x5500 || addr == 0x65000800)
				{
					highspeed = 1;
					if (!baudrate) baudrate = 921600;
				}

				/* FDL1 (chk = sum) */
				io->flags &= ~FLAGS_CRC16;

				encode_msg(io, BSL_CMD_CHECK_BAUD, NULL, 1);
				for (i = 0; ; i++) {
					send_msg(io);
					recv_msg(io);
					if (recv_type(io) == BSL_REP_VER) break;
					DBG_LOG("CHECK_BAUD FAIL\n");
					if (i == 4) ERR_EXIT("wrong command or wrong mode detected, reboot your phone by pressing POWER and VOL_UP for 7-10 seconds.\n");
					usleep(500000);
				}
				DBG_LOG("CHECK_BAUD FDL1\n");

				DBG_LOG("BSL_REP_VER: ");
				print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
				if (!memcmp(io->raw_buf + 4, "SPRD4", 5)) fdl2_executed = -1;

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
			argc -= argchange; argv += argchange;

		} else if (!strcmp(str2[1], "exec")) {
			if (fdl2_executed > 0) {
				DBG_LOG("FDL2 ALREADY EXECUTED, SKIP\n");
				argc -= 1; argv += 1;
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
				if (Da_Info.bSupportRawData) {
					if (fdl2_executed) {
						Da_Info.bSupportRawData = 0;
						DBG_LOG("DISABLE_WRITE_RAW_DATA in SPRD4\n");
					}
					else {
						encode_msg(io, BSL_CMD_WRITE_RAW_DATA_ENABLE, NULL, 0);
						if (!send_and_check(io)) DBG_LOG("ENABLE_WRITE_RAW_DATA\n");
					}
					blk_size = 0xff00;
					ptable = partition_list(io, fn_partlist, &part_count);
				}
				else if (highspeed || Da_Info.dwStorageType == 0x103) {
					blk_size = 0xff00;
					ptable = partition_list(io, fn_partlist, &part_count);
				}
				else if (Da_Info.dwStorageType == 0x102) {
					ptable = partition_list(io, fn_partlist, &part_count);
				}
				else if (Da_Info.dwStorageType == 0x101) DBG_LOG("Storage is nand\n");
				if (gpt_failed != 1) {
					if (selected_ab == 2) DBG_LOG("Device is using slot b\n");
					else if (selected_ab == 1) DBG_LOG("Device is using slot a\n");
					else DBG_LOG("Device is not using VAB\n");
				}
				if (nand_id == DEFAULT_NAND_ID) {
					nand_info[0] = (uint8_t)pow(2, nand_id & 3); //page size
					nand_info[1] = 32 / (uint8_t)pow(2, (nand_id >> 2) & 3); //spare area size
					nand_info[2] = 64 * (uint8_t)pow(2, (nand_id >> 4) & 3); //block size
				}
				fdl2_executed = 1;
			}
			argc -= 1; argv += 1;
#if !USE_LIBUSB
		} else if (!strcmp(str2[1], "baudrate")) {
			if (argcount > 2)
			{
				baudrate = strtoul(str2[2], NULL, 0);
				if (fdl2_executed) call_SetProperty(io->handle, 0, 100, (LPCVOID)&baudrate);
			}
			DBG_LOG("baudrate is %u\n", baudrate);
			argc -= 2; argv += 2;
#endif
		} else if (!strcmp(str2[1], "path")) {
			if (argcount > 2) strcpy(savepath, str2[2]);
			DBG_LOG("save dir is %s\n", savepath);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "exec_addr")) {
			FILE* fi;
			if (0 == fdl1_loaded && argcount > 2) {
				exec_addr = strtoul(str2[2], NULL, 0);
				sprintf(execfile, "custom_exec_no_verify_%x.bin", exec_addr);
				fi = fopen(execfile, "r");
				if (fi == NULL) { DBG_LOG("%s does not exist\n", execfile); exec_addr = 0; }
				else fclose(fi);
			}
			DBG_LOG("current exec_addr is 0x%x\n", exec_addr);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "loadexec")) {
			const char* fn; char* ch; FILE* fi;
			if (argcount <= 2) { DBG_LOG("loadexec FILE\n"); argc -= 2; argv += 2; continue; }
			if (0 == fdl1_loaded) {
				strcpy(execfile, str2[2]);

				if ((ch = strrchr(execfile, '/'))) fn = ch + 1;
				else if ((ch = strrchr(execfile, '\\'))) fn = ch + 1;
				else fn = execfile;
				char straddr[9] = { 0 };
				ret = sscanf(fn, "custom_exec_no_verify_%[0-9a-fA-F]", straddr);
				exec_addr = strtoul(straddr, NULL, 16);
				fi = fopen(execfile, "r");
				if (fi == NULL) { DBG_LOG("%s does not exist\n", execfile); exec_addr = 0; }
				else fclose(fi);
			}
			DBG_LOG("current exec_addr is 0x%x\n", exec_addr);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "nand_id")) {
			if (argcount > 2) {
				nand_id = strtol(str2[2], NULL, 0);
				nand_info[0] = (uint8_t)pow(2, nand_id & 3); //page size
				nand_info[1] = 32 / (uint8_t)pow(2, (nand_id >> 2) & 3); //spare area size
				nand_info[2] = 64 * (uint8_t)pow(2, (nand_id >> 4) & 3); //block size
			}
			DBG_LOG("current nand_id is 0x%x\n", nand_id);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "read_flash")) {
			const char *fn; uint64_t addr, offset, size;
			if (argcount <= 5) { DBG_LOG("bad command\n"); argc -= 5; argv += 5; continue; }

			addr = str_to_size(str2[2]);
			offset = str_to_size(str2[3]);
			size = str_to_size(str2[4]);
			fn = str2[5];
			if ((addr | size | offset | (addr + offset + size)) >> 32) { DBG_LOG("32-bit limit reached\n"); argc -= 5; argv += 5; continue; }
			dump_flash(io, addr, offset, size, fn, blk_size ? blk_size : 1024);
			argc -= 5; argv += 5;

		} else if (!strcmp(str2[1], "read_mem")) {
			const char *fn; uint64_t addr, size;
			if (argcount <= 4) { DBG_LOG("bad command\n"); argc -= 4; argv += 4; continue; }

			addr = str_to_size(str2[2]);
			size = str_to_size(str2[3]);
			fn = str2[4];
			if ((addr | size | (addr + size)) >> 32) { DBG_LOG("32-bit limit reached\n"); argc -= 4; argv += 4; continue; }
			dump_mem(io, addr, size, fn, blk_size ? blk_size : 1024);
			argc -= 4; argv += 4;

		} else if (!strcmp(str2[1], "part_size") || !strcmp(str2[1], "size_part")) {
			const char *name;
			if (argcount <= 2) { DBG_LOG("size_part part_name\n"); argc -= 2; argv += 2; continue; }

			name = str2[2];
			if (selected_ab < 0) select_ab(io);
			find_partition_size(io, name);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "p") || !strcmp(str2[1], "print")) {
			if (part_count) {
				DBG_LOG("  0 %36s     256KB\n", "splloader");
				for (i = 0; i < part_count; i++) {
					DBG_LOG("%3d %36s %7lldMB\n", i + 1, (*(ptable + i)).name, ((*(ptable + i)).size >> 20));
				}
			}
			argc -= 1; argv += 1;

		} else if (!strcmp(str2[1], "check_part")) {
			const char *name;
			if (argcount <= 2) { DBG_LOG("check_part part_name\n"); argc -= 2; argv += 2; continue; }

			name = str2[2];
			if (selected_ab < 0) select_ab(io);
			DBG_LOG("%d\n", check_partition(io, name));
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "read_part")) {
			const char *name, *fn; uint64_t offset, size;
			uint64_t realsize = 0;
			char name_ab[36];
			int verbose = io->verbose;
			if (argcount <= 5) { DBG_LOG("read_part part_name offset size FILE\n(read ubi on nand) read_part system 0 ubi40m system.bin\n"); argc -= 5; argv += 5; continue; }

			name = str2[2];
			io->verbose = 0;
			if (isdigit(name[0])) {
				if (gpt_failed == 1) ptable = partition_list(io, fn_partlist, &part_count);
				i = atoi(name);
				if (i > part_count) { DBG_LOG("part not exist\n"); argc -= 5; argv += 5; continue; }
				if (i == 0) name = "splloader";
				else name = (*(ptable + i - 1)).name;
			}
			else
			{
				if (selected_ab < 0) select_ab(io);
				realsize = check_partition(io, name);
				if (!realsize) {
					if (selected_ab > 0) {
						snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
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
			}
			offset = str_to_size_ubi(str2[3], nand_info);
			size = str_to_size_ubi(str2[4], nand_info);
			if (0xffffffff == size) size = find_partition_size(io, name);
			fn = str2[5];
			if (offset + size < offset) { DBG_LOG("64-bit limit reached\n"); argc -= 5; argv += 5; continue; }
			io->verbose = verbose;
			dump_partition(io, name, offset, size, fn, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			argc -= 5; argv += 5;

		} else if (!strcmp(str2[1], "r")) {
			uint64_t realsize = 0;
			const char* name = str2[2];
			char name_ab[36];
			int loop_count = 0, in_loop = 0;
			const char* list[] = { "vbmeta", "splloader", "uboot", "sml", "trustos", "teecfg", "boot", "recovery" };
			if (argcount <= 2) { DBG_LOG("r all/all_lite/part_name/part_id\n"); argc -= 2; argv += 2; continue; }
			if (isdigit(name[0])) {
				if (gpt_failed == 1) ptable = partition_list(io, fn_partlist, &part_count);
				i = atoi(name);
				if (i > part_count) { DBG_LOG("part not exist\n"); argc -= 2; argv += 2; continue; }
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
				if (gpt_failed == 1) ptable = partition_list(io, fn_partlist, &part_count);
				if (!part_count) { DBG_LOG("Partition table not available\n"); argc -= 2; argv += 2; continue; }
				if (selected_ab > 0) { DBG_LOG("saving slot info\n"); dump_partition(io, "misc", 0, 1048576, "misc.bin", blk_size); }
				for (i = 0; i < part_count; i++)
					if (0 == strncmp("l_", (*(ptable + i)).name, 2) || 0 == strncmp("nr_", (*(ptable + i)).name, 3)) {
						char dfile[40];
						snprintf(dfile, sizeof(dfile), "%s.bin", (*(ptable + i)).name);
						dump_partition(io, (*(ptable + i)).name, 0, (*(ptable + i)).size, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
					}
				argc -= 2; argv += 2;
				continue;
			}
			else if (!strcmp(name, "all")) {
				if (gpt_failed == 1) ptable = partition_list(io, fn_partlist, &part_count);
				if (!part_count) { DBG_LOG("Partition table not available\n"); argc -= 2; argv += 2; continue; }
				dump_partition(io, "splloader", 0, 256 * 1024, "splloader.bin", blk_size ? blk_size : DEFAULT_BLK_SIZE);
				for (i = 0; i < part_count; i++)
				{
					char dfile[40];
					if (!memcmp((*(ptable + i)).name, "blackbox", 8)) continue;
					else if (!memcmp((*(ptable + i)).name, "cache", 5)) continue;
					else if (!memcmp((*(ptable + i)).name, "userdata", 8)) continue;
					snprintf(dfile, sizeof(dfile), "%s.bin", (*(ptable + i)).name);
					dump_partition(io, (*(ptable + i)).name, 0, (*(ptable + i)).size, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
				}
				argc -= 2; argv += 2;
				continue;
			}
			else if (!strcmp(name, "all_lite")) {
				if (gpt_failed == 1) ptable = partition_list(io, fn_partlist, &part_count);
				if (!part_count) { DBG_LOG("Partition table not available\n"); argc -= 2; argv += 2; continue; }
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
					snprintf(dfile, sizeof(dfile), "%s.bin", (*(ptable + i)).name);
					dump_partition(io, (*(ptable + i)).name, 0, (*(ptable + i)).size, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
				}
				argc -= 2; argv += 2;
				continue;
			}
			else {
				if (!strcmp(name, "preset_resign")) { loop_count = 7; name = list[loop_count]; in_loop = 1; }
rloop:
				if (!memcmp(name, "splloader", 9)) realsize = 256 * 1024;
				else if (part_count) {
					if (selected_ab > 0) snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
					for (i = 0; i < part_count; i++) {
						if (!strcmp(name, (*(ptable + i)).name)) {
							realsize = (*(ptable + i)).size;
							break;
						}
						if (selected_ab > 0 && !strcmp(name_ab, (*(ptable + i)).name)) {
							realsize = (*(ptable + i)).size;
							name = name_ab;
							break;
						}
					}
					if (i == part_count) {
						DBG_LOG("part not exist\n");
						if (loop_count) { name = list[--loop_count]; goto rloop; }
						argc -= 2; argv += 2;
						continue;
					}
				}
				else
				{
					if (selected_ab < 0) select_ab(io);
					realsize = check_partition(io, name);
					if (!realsize) {
						if (selected_ab > 0) {
							snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
							realsize = check_partition(io, name_ab);
							name = name_ab;
						}
						if (!realsize) {
							DBG_LOG("part not exist\n");
							if (loop_count) { name = list[--loop_count]; goto rloop; }
							argc -= 2; argv += 2;
							continue;
						}
					}
					realsize = find_partition_size(io, name);
				}
			}
			char dfile[40];
			if (isdigit(str2[2][0])) snprintf(dfile, sizeof(dfile), "%s.bin", name);
			else if (in_loop) snprintf(dfile, sizeof(dfile), "%s.bin", list[loop_count]);
			else snprintf(dfile, sizeof(dfile), "%s.bin", str2[2]);
			dump_partition(io, name, 0, realsize, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			if (loop_count--) { name = list[loop_count]; goto rloop; }
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "read_parts")) {
			const char* fn; FILE* fi;
			if (argcount <= 2) { DBG_LOG("read_parts partition_list_file\n"); argc -= 2; argv += 2; continue; }
			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 2; argv += 2; continue; }
			else fclose(fi);
			dump_partitions(io, fn, nand_info, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "partition_list")) {
			if (argcount <= 2) { DBG_LOG("partition_list FILE\n"); argc -= 2; argv += 2; continue; }
			if (gpt_failed < 1) { DBG_LOG("partition_list shouldn't run twice\n"); argc -= 2; argv += 2; continue; }
			ptable = partition_list(io, str2[2], &part_count);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "repartition")) {
			const char *fn; FILE *fi;
			if (argcount <= 2) { DBG_LOG("repartition FILE\n"); argc -= 2; argv += 2; continue; }
			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 2; argv += 2; continue; }
			else fclose(fi);
			if (skip_confirm) repartition(io, str2[2]);
			else if (check_confirm("repartition")) repartition(io, str2[2]);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "erase_part") || !strcmp(str2[1], "e")) {
			uint64_t realsize = 0;
			const char* name = str2[2];
			char name_ab[36];
			int verbose = io->verbose;
			if (argcount <= 2) { DBG_LOG("erase_part part_name/part_id\n"); argc -= 2; argv += 2; continue; }
			if (selected_ab < 0) select_ab(io);
			if (!skip_confirm)
				if (!check_confirm("erase partition"))
				{
					argc -= 2; argv += 2;
					continue;
				}
			i = -1;
			if (isdigit(name[0])) {
				if (part_count) i = atoi(name);
				else { DBG_LOG("gpt table is empty\n"); argc -= 2; argv += 2; continue; }
				if (i > part_count) { DBG_LOG("part not exist\n"); argc -= 2; argv += 2; continue; }
			}
			if (i == 0) erase_partition(io, "splloader");
			else if (i > 0) erase_partition(io, (*(ptable + i - 1)).name);
			else {
				io->verbose = 0;
				realsize = check_partition(io, name);
				if (!realsize) {
					if (selected_ab > 0) {
						snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
						realsize = check_partition(io, name_ab);
						name = name_ab;
					}
					if (!realsize) {
						DBG_LOG("part not exist\n");
						io->verbose = verbose;
						argc -= 2; argv += 2;
						continue;
					}
				}
				io->verbose = verbose;
				erase_partition(io, name);
			}
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "write_part") || !strcmp(str2[1], "w")) {
			const char *fn; FILE *fi;
			uint64_t realsize = 0;
			const char* name = str2[2];
			char name_ab[36];
			int verbose = io->verbose;
			if (argcount <= 3) { DBG_LOG("write_part part_name/part_id FILE\n"); argc -= 3; argv += 3; continue; }
			fn = str2[3];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 3; argv += 3; continue; }
			else fclose(fi);
			if (selected_ab < 0) select_ab(io);
			if (!skip_confirm)
				if (!check_confirm("write partition"))
				{
					argc -= 3; argv += 3;
					continue;
				}
			i = -1;
			if (isdigit(name[0])) {
				if (part_count) i = atoi(name);
				else { DBG_LOG("gpt table is empty\n"); argc -= 3; argv += 3; continue; }
				if (i > part_count) { DBG_LOG("part not exist\n"); argc -= 3; argv += 3; continue; }
			}
			if (i == 0) load_partition(io, "splloader", str2[3], 4096);
			else if (i > 0) {
				if (strstr((*(ptable + i)).name, "fixnv1")) load_nv_partition(io, (*(ptable + i)).name, str2[3], 4096);
				else load_partition(io, (*(ptable + i)).name, str2[3], blk_size ? blk_size : DEFAULT_BLK_SIZE);
			}
			else {
				io->verbose = 0;
				realsize = check_partition(io, name);
				if (!realsize) {
					if (selected_ab > 0) {
						snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
						realsize = check_partition(io, name_ab);
						name = name_ab;
					}
					if (!realsize) {
						DBG_LOG("part not exist\n");
						io->verbose = verbose;
						argc -= 3; argv += 3;
						continue;
					}
				}
				io->verbose = verbose;
				if (strstr(name, "fixnv1")) load_nv_partition(io, name, str2[3], 4096);
				else load_partition(io, name, str2[3], blk_size ? blk_size : DEFAULT_BLK_SIZE);
			}
			argc -= 3; argv += 3;

		} else if (!strcmp(str2[1], "write_parts")) {
			if (argcount <= 2) { DBG_LOG("write_parts save_location\n"); argc -= 2; argv += 2; continue; }
			if (skip_confirm) load_partitions(io, str2[2], blk_size ? blk_size : DEFAULT_BLK_SIZE);
			else if (check_confirm("write all partitions")) load_partitions(io, str2[2], blk_size ? blk_size : DEFAULT_BLK_SIZE);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "wof") || !strcmp(str2[1], "wov")) {
			const char* fn;	FILE* fi;
			uint64_t offset;
			uint32_t value, isValue = 0;
			uint64_t realsize = 0;
			const char* name = str2[2];
			char name_ab[36];
			int verbose = io->verbose;
			if (argcount <= 4) { DBG_LOG("wof part_name offset FILE\nwov part_name offset Value(max is 0xFFFFFFFF)\n"); argc -= 4; argv += 4; continue; }

			if (isdigit(name[0])) {
				if (gpt_failed == 1) ptable = partition_list(io, fn_partlist, &part_count);
				i = atoi(name);
				if (i > part_count) { DBG_LOG("part not exist\n"); argc -= 4; argv += 4; continue; }
				if (i == 0) {
					name = "splloader";
					realsize = 256 * 1024;
				}
				else {
					name = (*(ptable + i - 1)).name;
					realsize = (*(ptable + i - 1)).size;
				}
			}
			else {
				if (!memcmp(name, "splloader", 9)) realsize = 256 * 1024;
				else if (part_count) {
					if (selected_ab > 0) snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
					for (i = 0; i < part_count; i++) {
						if (!strcmp(name, (*(ptable + i)).name)) {
							realsize = (*(ptable + i)).size;
							break;
						}
						if (selected_ab > 0 && !strcmp(name_ab, (*(ptable + i)).name)) {
							realsize = (*(ptable + i)).size;
							name = name_ab;
							break;
						}
					}
					if (i == part_count) { DBG_LOG("part not exist\n"); argc -= 4; argv += 4; continue; }
				}
				else
				{
					if (selected_ab < 0) select_ab(io);
					io->verbose = 0;
					realsize = check_partition(io, name);
					if (!realsize) {
						if (selected_ab > 0) {
							snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
							realsize = check_partition(io, name_ab);
							name = name_ab;
						}
						if (!realsize) {
							DBG_LOG("part not exist\n");
							io->verbose = verbose;
							argc -= 4; argv += 4;
							continue;
						}
					}
					realsize = find_partition_size(io, name);
					io->verbose = verbose;
				}
			}
			char dfile[40];
			if (isdigit(str2[2][0])) snprintf(dfile, sizeof(dfile), "%s.bin", name);
			snprintf(dfile, sizeof(dfile), "%s.bin", str2[2]);
			if (realsize != dump_partition(io, name, 0, realsize, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE)) {
				remove(dfile);
				argc -= 4; argv += 4;
				continue;
			}

			char fix_fn[1024];
			if (savepath[0]) {
				sprintf(fix_fn, "%s/%s", savepath, dfile);
				fi = fopen(fix_fn, "rb+");
			}
			else fi = fopen(dfile, "rb+");
			if (!fi) ERR_EXIT("fopen %s failed\n", dfile);
			offset = str_to_size_ubi(str2[3], nand_info);

			size_t leng = 1;
			uint8_t* src;
			uint8_t data[4] = { 0 };
			if (!strcmp(str2[1], "wov")) {
				isValue = 1;
				value = strtoul(str2[4], NULL, 0);
				if (value > 0xFFFFFF) leng = 4;
				else if (value > 0xFFFF) leng = 3;
				else if (value > 0xFF) leng = 2;
				memcpy(data, &value, 4);
				src = data;
			}
			else
			{
				fn = str2[4];
				src = loadfile(fn, &leng, 0);
				if (!src) { DBG_LOG("fopen %s failed\n", fn); argc -= 4; argv += 4; continue; }
			}
			if (offset + leng > realsize) {
				DBG_LOG("out of range\n");
				fclose(fi);
				if(!isValue) free(src);
				argc -= 4; argv += 4;
				continue;
			}
			if (fseek(fi, offset, SEEK_SET) != 0) ERR_EXIT("fseek failed\n");
			if (fwrite(src, 1, leng, fi) != leng) ERR_EXIT("fwrite failed\n");
			fclose(fi);
			if (!isValue) free(src);

			if (savepath[0]) load_partition(io, name, fix_fn, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			else load_partition(io, name, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			argc -= 4; argv += 4;

		} else if (!strcmp(str2[1], "read_pactime")) {
			read_pactime(io);
			argc -= 1; argv += 1;

		} else if (!strcmp(str2[1], "blk_size") || !strcmp(str2[1], "bs")) {
			if (argcount <= 2) { DBG_LOG("blk_size byte\n\tmax is 65535\n"); argc -= 2; argv += 2; continue; }
			blk_size = strtol(str2[2], NULL, 0);
			blk_size = blk_size < 0 ? 0 :
					blk_size > 0xffff ? 0xffff : blk_size;
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "fblk_size") || !strcmp(str2[1], "fbs")) {
			if (argcount <= 2) { DBG_LOG("fblk_size mb\n"); argc -= 2; argv += 2; continue; }
			fblk_size = strtoull(str2[2], NULL, 0) * 1024 * 1024;
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "verity")) {
			if (argcount <= 2) { DBG_LOG("verity {0,1}\n"); argc -= 2; argv += 2; continue; }
			if (atoi(str2[2])) dm_enable(io, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			else
			{
				DBG_LOG("Warning: disable dm-verity needs a write-verification-disabled FDL2\n");
				if (!skip_confirm)
					if (!check_confirm("disable dm-verity"))
					{
						argc -= 2; argv += 2;
						continue;
					}
				dm_disable(io, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			}
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "set_active")) {
			if (argcount <= 2) { DBG_LOG("set_active {a,b}\n"); argc -= 2; argv += 2; continue; }
			set_active(io, str2[2]);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "skip_confirm")) {
			if (argcount <= 2) { DBG_LOG("skip_confirm {0,1}\n"); argc -= 2; argv += 2; continue; }
			skip_confirm = atoi(str2[2]);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "rawdata")) {
			if (argcount <= 2) { DBG_LOG("rawdata {0,1,2}\n"); argc -= 2; argv += 2; continue; }
			Da_Info.bSupportRawData = atoi(str2[2]);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "chip_uid")) {
			encode_msg(io, BSL_CMD_READ_CHIP_UID, NULL, 0);
			send_msg(io);
			ret = recv_msg(io);
			if (!ret) ERR_EXIT("timeout reached\n");
			if ((ret = recv_type(io)) != BSL_REP_READ_CHIP_UID)
				{ DBG_LOG("unexpected response (0x%04x)\n", ret); argc -= 1; argv += 1; continue; }

			DBG_LOG("BSL_REP_READ_CHIP_UID: ");
			print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			argc -= 1; argv += 1;

		} else if (!strcmp(str2[1], "disable_transcode")) {
			encode_msg(io, BSL_CMD_DISABLE_TRANSCODE, NULL, 0);
			if (!send_and_check(io)) io->flags &= ~FLAGS_TRANSCODE;
			argc -= 1; argv += 1;

		} else if (!strcmp(str2[1], "transcode")) {
			unsigned a, f;
			if (argcount <= 2) { DBG_LOG("bad command\n"); argc -= 2; argv += 2; continue; }
			a = atoi(str2[2]);
			if (a >> 1) { DBG_LOG("bad command\n"); argc -= 2; argv += 2; continue; }
			f = (io->flags & ~FLAGS_TRANSCODE);
			io->flags = f | (a ? FLAGS_TRANSCODE : 0);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "keep_charge")) {
			if (argcount <= 2) { DBG_LOG("keep_charge {0,1}\n"); argc -= 2; argv += 2; continue; }
			keep_charge = atoi(str2[2]);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "timeout")) {
			if (argcount <= 2) { DBG_LOG("timeout ms\n"); argc -= 2; argv += 2; continue; }
			io->timeout = atoi(str2[2]);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "end_data")) {
			if (argcount <= 2) { DBG_LOG("end_data {0,1}\n"); argc -= 2; argv += 2; continue; }
			end_data = atoi(str2[2]);
			argc -= 2; argv += 2;

		} else if (!strcmp(str2[1], "reset")) {
			if (!fdl1_loaded) {
				DBG_LOG("FDL NOT READY\n");
				argc -= 1; argv += 1;
				continue;
			}
			encode_msg(io, BSL_CMD_NORMAL_RESET, NULL, 0);
			if (!send_and_check(io)) break;

		} else if (!strcmp(str2[1], "poweroff")) {
			if (!fdl1_loaded) {
				DBG_LOG("FDL NOT READY\n");
				argc -= 1; argv += 1;
				continue;
			}
			encode_msg(io, BSL_CMD_POWER_OFF, NULL, 0);
			if (!send_and_check(io)) break;

		} else if (!strcmp(str2[1], "verbose")) {
			if (argcount <= 2) { DBG_LOG("verbose {0,1,2}\n"); argc -= 2; argv += 2; continue; }
			io->verbose = atoi(str2[2]);
			argc -= 2; argv += 2;

		} else if (strlen(str2[1])) {
			print_help();
			argc = 1;
		}
		if (in_quote != -1)
			for (i = 1; i < argcount; i++)
				free(str2[i]);
		free(str2);
		if (m_bOpened == -1) {
			DBG_LOG("device removed, exiting...\n");
			break;
		}
	}
	free(ptable);
	spdio_free(io);
	return 0;
}
