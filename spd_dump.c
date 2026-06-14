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

void print_help(void) {
	DBG_LOG(
		"Usage\n"
		"\tspd_dump [OPTIONS] [COMMANDS] [EXIT COMMANDS]\n"
		"\nExamples\n"
		"\tOne-line mode\n"
		"\t\tspd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec path savepath r all_lite reset\n"
		"\tInteractive mode\n"
		"\t\tspd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec\n"
		"\tThen the prompt should display FDL2>.\n"
	);
	DBG_LOG(
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
	);
	DBG_LOG(
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
		"\tloadexec FILE(addr_in_name)\n"
		"\t\tSet exec_addr with the address encoded in filename and save exec_file path.\n"
		"\tloadfdl FILE(addr_in_name)\n"
		"\t\tLoad FDL file to the address encoded in filename.\n"
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
		"\t\t\tall/all_lite is not usable on NAND\n"
		"\t\tWhen the partition table is unavailable:\n"
		"\t\t\tr will auto-calculate part size (supports emmc/ufs and NAND).\n"
		"\tread_part part_name|part_id offset size FILE\n"
		"\t\tReads a specific partition to a file at the given offset and size.\n"
		"\t\t(read ubi on nand) read_part system 0 ubi40m system.bin\n"
		"\tread_parts partition_list_file\n"
		"\t\tReads partitions from a list file (If the file name starts with \"ubi\", the size will be calculated using the NAND ID).\n"
		"\tw|write_part part_name|part_id FILE\n"
		"\t\tWrites the specified file to a partition.\n"
		"\twrite_parts|write_parts_a|write_parts_b save_location\n"
		"\t\tWrites all partitions dumped by read_parts.\n"
		"\tw_force part_name|part_id FILE\n"
		"\t\tForce-writes a partition file bypassing size/name checks.\n"
		"\tg_w_force {0,1,2}\n"
		"\t\tSets the global write-force flag.\n"
		"\t\t0 = disable force write feature\n"
		"\t\t1 = non-AB partitions written normally, AB-slot partitions force-written\n"
		"\t\t2 = Force all partitions\n"
		"\twof part_name offset FILE\n"
		"\t\tWrites the specified file to a partition at the given offset.\n"
		"\twov part_name offset VALUE\n"
		"\t\tWrites the specified value (max is 0xFFFFFFFF) to a partition at the given offset.\n"
		"\te|erase_part part_name|part_id\n"
		"\t\tErases the specified partition.\n"
		"\terase_all\n"
		"\t\tErases all partitions. Use with caution!\n"
		"\tpartition_list FILE\n"
		"\t\tRead the partition list on emmc/ufs, not all fdl2 supports this command.\n"
		"\trepartition partition_list_xml\n"
		"\t\tRepartitions based on partition list XML.\n"
		"\tp|print\n"
		"\t\tPrints partition_list\n"
		"\tsize_part|part_size part_name\n"
		"\t\tDisplays the size of the specified partition.\n"
		"\tcheck_part part_name\n"
		"\t\tChecks if the specified partition exists.\n"
		"\tverity {0,1}\n"
		"\t\tEnables or disables dm-verity on android 10(+).\n"
		"\tset_active {a,b}\n"
		"\t\tSets the active slot on VAB devices.\n"
		"\tfirstmode mode_id\n"
		"\t\tSets the mode the device will enter after reboot.\n"
	);
	DBG_LOG(
		"\tskip_confirm {0,1}\n"
		"\t\tSets whether to skip confirmation prompts.\n"
		"\tkeep_charge {0,1}\n"
		"\t\tSets whether to send keep-charge command during FDL1 init.\n"
		"\tdis_avb\n"
		"\t\tDisables Android Verified Boot (AVB) via CVE.\n"
		"\tdis_avb_ex sml_or_teecfg tos\n"
		"\t\tDisables AVB externally by patching partition images.\n"
		"\tmergenv-xml xml new_nv\n"
		"\t\tMerges NV changes from XML list and writes back to device.\n"
		"\tmergenv-cfg cfg new_nv\n"
		"\t\tMerges NV changes from CFG list and writes back to device.\n"
		"\tmergenv-xml-ex xml old_nv new_nv\n"
		"\t\tMerges NV from XML list on two files externally (no device write).\n"
		"\tmergenv-cfg-ex cfg old_nv new_nv\n"
		"\t\tMerges NV from CFG list on two files externally (no device write).\n"
	);
	DBG_LOG(
		"\nLegacy Commands\n"
		"\tsend|write_flash FILE addr\n"
		"\t\tSends a file to flash at the given address.\n"
		"\tread_flash addr offset size FILE\n"
		"\t\tReads a region of flash memory to a file.\n"
		"\terase_flash addr size\n"
		"\t\tErases a region of flash.\n"
		"\tread_mem addr size FILE\n"
		"\t\tReads device memory to a file.\n"
		"\tread_pactime\n"
		"\t\tReads and prints packet timing information.\n"
		"\tchip_uid\n"
		"\t\tReads and prints the chip UID.\n"
		"\tdisable_transcode\n"
		"\t\tSends command to disable HDLC transcoding on the device.\n"
	);
	DBG_LOG(
		"\nDebug Commands\n"
		"\tsendloop addr\n"
		"\t\tDebug: repeatedly sends 4 zero bytes to decrementing addresses.\n"
		"\tsendloopadd addr\n"
		"\t\tDebug: repeatedly sends zero-byte packets to incrementing addresses.\n"
		"\tsendcmd type file\n"
		"\t\tSends raw command with given type from file.\n"
		"\tsendcmdv type value(max is 0xFFFFFFFF)\n"
		"\t\tSends raw command with given type and 8-byte value.\n"
		"\tsendcmdvl type value(max is 0xFFFFFFFF)\n"
		"\t\tSends looped raw command from value to 0x100000000, saves each response.\n"
		"\tsendpack file\n"
		"\t\tSends a pre-formatted 7E-packed packet from file.\n"
		"\trawpack file\n"
		"\t\tSends raw file as a packet (CRC and transcode added automatically).\n"
		"\twrite_word addr VALUE(max is 0xFFFFFFFF)\n"
		"\t\tWrites a 32-bit value to a memory address.\n"
		"\ttranscode {0,1}\n"
		"\t\tLocally enables or disables HDLC transcoding.\n"
		"\tend_data {0,1}\n"
		"\t\tSets whether to append end-of-data markers when writing to flash.\n"
		"\tfblk_size|fbs mb\n"
		"\t\tSets the flash block size in megabytes.\n"
		"\tslot {0,1,2}\n"
		"\t\tSets the A/B slot selection (0=auto, 1=a, 2=b).\n"
	);
	DBG_LOG(
		"\nEXTENDED Commands (need special loaders)\n"
		"\te_readmem addr length FILE\n"
		"\t\tReads memory at addr for length bytes and saves to FILE.\n"
		"\te_bl\n"
		"\t\tSends e_bl command.\n"
		"\te_rpmb_pagecount\n"
		"\t\tQueries RPMB page count.\n"
		"\te_rpmb_counter\n"
		"\t\tQueries RPMB write counter.\n"
		"\te_rpmb_read page_start page_count FILE\n"
		"\t\tReads RPMB pages starting at page_start and saves to FILE.\n"
		"\te_rpmb_write page_start FILE\n"
		"\t\tWrites FILE data to RPMB starting at page_start.\n"
		"\te_rpmb_read_auto\n"
		"\t\tAutomatically reads all RPMB pages to file rpmb_dump.\n"
		"\te_pwn\n"
		"\t\tpwn trustos (bypass verification in modem).\n"
		"\te_checkpwn\n"
		"\t\tChecks if device's trustos is pwned.\n"
	);
	DBG_LOG(
		"\nExit Commands\n"
		"\treboot-recovery\n\t\tFDL2 only\n"
		"\treboot-fastboot\n\t\tFDL2 only\n"
		"\treset\n\t\tFDL2 and new FDL1\n"
		"\tpoweroff\n\t\tFDL2 and new FDL1\n"
	);
}

#define REOPEN_FREQ 2
extern char fn_partlist[80];
extern char savepath[ARGV_LEN];
extern DA_INFO_T Da_Info;
extern partition_t gPartInfo;
int bListenLibusb = -1;
int gpt_failed = 1;
int m_bOpened = 0;
int fdl1_loaded = 0;
int fdl2_executed = 0;
int selected_ab = -1;
uint64_t fblk_size = 0;
int g_spl_size = 0;
int g_w_force = 0;
int main(int argc, char **argv) {
	spdio_t *io = NULL; int ret, i, in_quote;
	int wait = 30 * REOPEN_FREQ;
	int argcount = 0, stage = -1, nand_id = DEFAULT_NAND_ID;
	int nand_info[3];
	int keep_charge = 1, end_data = 1, blk_size = 0, skip_confirm = 1, highspeed = 0, exec_addr_v2 = 0;
	unsigned exec_addr = 0, baudrate = 0;
	char *temp;
	char str1[(ARGC_MAX - 1) * ARGV_LEN];
	char **str2;
	char *execfile;
	int bootmode = -1, async = 1;
#if !USE_LIBUSB
	extern DWORD curPort;
	DWORD *ports;
#else
	extern libusb_device *curPort;
	libusb_device **ports;
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
	DBG_LOG("ver:%s, sha1:%s\n", GIT_VER, GIT_SHA1);
	sprintf(fn_partlist, "partition_%lld.xml", (long long)time(NULL));
	if (atexit(clean_tmpdir)) ERR_EXIT("Failed to register cleanup function.\n");
	signal(SIGINT, signal_exit);
	signal(SIGTERM, signal_exit);
#if _WIN32
	if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) ERR_EXIT("Failed to register cleanup function.\n");;
#endif
	while (argc > 1) {
		if (!strcmp(argv[1], "--wait")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			wait = atoi(argv[2]) * REOPEN_FREQ;
			argc -= 2; argv += 2;
		}
		else if (!strcmp(argv[1], "--verbose")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			io->verbose = atoi(argv[2]);
			argc -= 2; argv += 2;
		}
		else if (!strcmp(argv[1], "--stage")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			stage = 99;
			argc -= 2; argv += 2;
		}
		else if (strstr(argv[1], "-r")) {
			stage = 99;
			argc -= 1; argv += 1;
		}
		else if (strstr(argv[1], "help") || strstr(argv[1], "-h") || strstr(argv[1], "-?")) {
			print_help();
			return 0;
#ifdef __ANDROID__
		}
		else if (!strcmp(argv[1], "--usb-fd")) { // Termux spec
			if (argc <= 2) ERR_EXIT("bad option\n");
			xfd = atoi(argv[argc - 1]);
			argc -= 2; argv += 1;
#endif
		}
		else if (!strcmp(argv[1], "--kick")) {
			bootmode = 2;
			argc -= 1; argv += 1;
		}
		else if (!strcmp(argv[1], "--kickto")) {
			if (argc <= 2) ERR_EXIT("bad option\n");
			bootmode = strtol(argv[2], NULL, 0);
			argc -= 2; argv += 2;
		}
		else if (!strcmp(argv[1], "--sync")) {
			async = 0;
			argc -= 1; argv += 1;
		}
		else break;
	}
#if defined(_MYDEBUG) && defined(USE_LIBUSB)
	io->verbose = 2;
#endif
	if (stage == 99) bootmode = -1;
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
	if (async) {
		if (FALSE == CreateRecvThread(io)) {
			io->m_dwRecvThreadID = 0;
			DBG_LOG("Create Receive Thread Fail.\n");
		}
	}
	if (bootmode >= 0) {
		io->hThread = CreateThread(NULL, 0, ThrdFunc, NULL, 0, &io->iThread);
		if (io->hThread == NULL) return -1;
		ChangeMode(io, wait / REOPEN_FREQ * 1000, bootmode);
		wait = 30 * REOPEN_FREQ;
		stage = -1;
	}
#else
	if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) { DBG_LOG("hotplug unsupported on this platform\n"); bListenLibusb = 0; bootmode = -1; }
	if (bootmode >= 0) {
		startUsbEventHandle();
		ChangeMode(io, wait / REOPEN_FREQ * 1000, bootmode);
		wait = 30 * REOPEN_FREQ;
		stage = -1;
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
			if (!(i % 4)) {
				if ((ports = FindPort(0x4d00))) {
					for (libusb_device **port = ports; *port != NULL; port++) {
						if (libusb_open(*port, &io->dev_handle) >= 0) {
							call_Initialize_libusb(io);
							curPort = *port;
							break;
						}
					}
					libusb_free_device_list(ports, 1);
					ports = NULL;
					if (m_bOpened) break;
				}
			}
			if (i >= wait)
				ERR_EXIT("libusb_open_device failed\n");
#else
			if (io->verbose) DBG_LOG("CurTime: %.1f, CurPort: %d\n", (float)i / REOPEN_FREQ, curPort);
			if (curPort) {
				if (!call_ConnectChannel(io->handle, curPort, WM_RCV_CHANNEL_DATA, io->m_dwRecvThreadID)) ERR_EXIT("Connection failed\n");
				break;
			}
			if (!(i % 4)) {
				if ((ports = FindPort("SPRD U2S Diag"))) {
					for (DWORD *port = ports; *port != 0; port++) {
						if (call_ConnectChannel(io->handle, *port, WM_RCV_CHANNEL_DATA, io->m_dwRecvThreadID)) {
							curPort = *port;
							break;
						}
					}
					free(ports);
					ports = NULL;
					if (m_bOpened) break;
				}
			}
			if (i >= wait)
				ERR_EXIT("find port failed\n");
#endif
			usleep(1000000 / REOPEN_FREQ);
		}
	}
#endif
	io->flags |= FLAGS_TRANSCODE;
	if (stage != -1) {
		io->flags &= ~FLAGS_CRC16;
		encode_msg_nocpy(io, BSL_CMD_CONNECT, 0);
	}
	else encode_msg(io, BSL_CMD_CHECK_BAUD, NULL, 1);
	for (i = 0; ; i++) {
		ret = recv_type(io);
		if (ret == BSL_REP_VER) {}
		else if (ret == BSL_REP_VERIFY_ERROR ||
			ret == BSL_REP_UNSUPPORTED_COMMAND) {
			if (fdl1_loaded) ERR_EXIT("wrong command or wrong mode detected, reboot your phone by pressing POWER and VOL_UP for 7-10 seconds.\n"); // when fdl1/fdl2 recv kick_msg, device won't reply next packet.
		}
		else {
			send_msg(io);
			recv_msg(io);
			ret = recv_type(io);
		}
		if (ret == BSL_REP_ACK || ret == BSL_REP_VER || ret == BSL_REP_VERIFY_ERROR) {
			if (ret == BSL_REP_VER) {
				if (fdl1_loaded == 1) {
					DBG_LOG("CHECK_BAUD FDL1\n");
					if (!memcmp(io->raw_buf + 4, "SPRD4", 5)) fdl2_executed = -1;
				}
				else {
					DBG_LOG("CHECK_BAUD bootrom\n");
					if (!memcmp(io->raw_buf + 4, "SPRD4", 5)) fdl1_loaded = -1;
				}
				DBG_LOG("BSL_REP_VER: ");
				print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));

				encode_msg_nocpy(io, BSL_CMD_CONNECT, 0);
				if (send_and_check(io)) exit(1);
			}
			else if (ret == BSL_REP_VERIFY_ERROR) {
				encode_msg_nocpy(io, BSL_CMD_CONNECT, 0);
				if (fdl1_loaded != 1) {
					if (send_and_check(io)) exit(1);
				}
				else { i = -1; continue; }
			}

			if (fdl1_loaded == 1) {
				DBG_LOG("CMD_CONNECT FDL1\n");
				if (keep_charge) {
					encode_msg_nocpy(io, BSL_CMD_KEEP_CHARGE, 0);
					if (!send_and_check(io)) DBG_LOG("KEEP_CHARGE FDL1\n");
				}
			}
			else DBG_LOG("CMD_CONNECT bootrom\n");
			break;
		}
		else if (ret == BSL_REP_UNSUPPORTED_COMMAND) {
			encode_msg_nocpy(io, BSL_CMD_DISABLE_TRANSCODE, 0);
			if (!send_and_check(io)) {
				io->flags &= ~FLAGS_TRANSCODE;
				DBG_LOG("DISABLE_TRANSCODE\n");
			}
			g_spl_size = check_partition(io, "splloader", 1);
			fdl2_executed = 1;
			break;
		}
		else if (i == 4) {
			if (stage != -1) ERR_EXIT("wrong command or wrong mode detected, reboot your phone by pressing POWER and VOL_UP for 7-10 seconds.\n");
			else { encode_msg_nocpy(io, BSL_CMD_CONNECT, 0); stage++; i = -1; }
		}
	}

	char **save_argv = NULL;
	if (argc < 1) argc = 1;
	if (fdl1_loaded == -1) argc += 2;
	else if (fdl2_executed == -1) argc += 1;
	while (1) {
		if (argc > 1) {
			int str2_len = (argc > 2) ? argc : 3;
			str2 = (char **)malloc(str2_len * sizeof(char *));
			if (!str2) ERR_EXIT("malloc failed\n");
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
		else {
			char ifs = '"';
			str2 = (char **)malloc(ARGC_MAX * sizeof(char *));
			if (!str2) ERR_EXIT("malloc failed\n");
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
			while (temp) {
				if (!in_quote) {
					argcount++;
					if (argcount == ARGC_MAX) break;
					str2[argcount] = (char *)calloc(ARGV_LEN, 1);
					if (!str2[argcount]) ERR_EXIT("malloc failed\n");
				}
				if (temp[0] == '\'') ifs = '\'';
				if (temp[0] == ifs) {
					in_quote = 1;
					temp += 1;
				}
				else if (in_quote) {
					strcat(str2[argcount], " ");
				}

				if (temp[strlen(temp) - 1] == ifs) {
					in_quote = 0;
					temp[strlen(temp) - 1] = 0;
				}

				strcat(str2[argcount], temp);
				temp = strtok(NULL, " ");
			}
			argcount++;
		}
		if (argcount == 1) {
			str2[1] = malloc(1);
			if (str2[1]) str2[1][0] = '\0';
			else ERR_EXIT("malloc failed\n");
			argcount++;
		}

		if (!strcmp(str2[1], "sendloop")) {
			uint32_t addr = 0;
			if (argcount <= 2) { DBG_LOG("sendloop addr\n"); argc = 1; continue; }

			uint8_t data[4] = { 0 };
			addr = strtoul(str2[2], NULL, 0);
			while (1) {
				send_buf(io, addr, 0, 528, data, 4);
				DBG_LOG("SEND 4 bytes to 0x%x\n", addr);
				addr -= 8;
			}
			argc -= 2; argv += 2;
		}
		else if (!strcmp(str2[1], "sendloopadd")) {
			uint32_t addr = 0;
			if (argcount <= 2) { DBG_LOG("sendloopadd addr\n"); argc = 1; continue; }

			addr = strtoul(str2[2], NULL, 0);
			uint32_t *data = (uint32_t *)io->temp_buf;

			WRITE32_BE(data, addr);
			WRITE32_BE(data + 1, 4);
			encode_msg_nocpy(io, BSL_CMD_START_DATA, 8);
			if (send_and_check(io)) exit(1);

			WRITE32_BE(data, 0);
			WRITE32_BE(data + 1, 0);
			while (1) {
				encode_msg_nocpy(io, BSL_CMD_MIDST_DATA, 8);
				if (send_and_check(io)) exit(1);
				DBG_LOG("SEND 8 bytes to 0x%x\n", addr);
				addr += 8;
			}
			argc -= 2; argv += 2;
		}
		else if (!strcmp(str2[1], "sendcmd")) {
			if (argcount <= 3) { DBG_LOG("sendcmd type file\n"); argc = 1; continue; }
			size_t length = 0;
			FILE *fi = fopen(str2[3], "rb");
			if (fi) {
				fseek(fi, 0, SEEK_END);
				length = ftell(fi);
				if (length) {
					fseek(fi, 0, SEEK_SET);
					ret = fread(io->temp_buf, 1, length, fi);
				}
				fclose(fi);
			}
			encode_msg_nocpy(io, strtoul(str2[2], NULL, 0), length);
			if (send_and_check(io)) print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			argc -= 3; argv += 3;
		}
		else if (!strcmp(str2[1], "sendcmdv")) {
			if (argcount <= 3) { DBG_LOG("sendcmdv type value(max is 0xFFFFFFFF)\n"); argc = 1; continue; }
			uint64_t send_value = strtoull(str2[3], NULL, 0);
			memcpy(io->temp_buf, &send_value, 8);
			encode_msg_nocpy(io, strtoul(str2[2], NULL, 0), 8);
			if (send_and_check(io)) print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			argc -= 3; argv += 3;
		}
		else if (!strcmp(str2[1], "sendcmdvl")) {
			if (argcount <= 3) { DBG_LOG("sendcmdvl type value(max is 0xFFFFFFFF)\n"); argc = 1; continue; }
			uint64_t send_value = strtoull(str2[3], NULL, 0);;
			char filename[64];
			snprintf(filename, sizeof(filename), "0x%08llX", (unsigned long long)send_value);
			FILE *output_file = fopen(filename, "wb");
			if (!output_file) { DBG_LOG("Failed to open output file: %s\n", filename); argc = 1; continue; }
			for (; send_value < 0x100000000; send_value += 0x200) {
				memcpy(io->temp_buf, &send_value, 8);
				encode_msg_nocpy(io, strtoul(str2[2], NULL, 0), 8);
				DBG_LOG("current 0x%08llX\n", (unsigned long long)send_value);
				if (send_and_check(io)) {
					print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
					fwrite(io->raw_buf + 4, 1, READ16_BE(io->raw_buf + 2), output_file);
					fflush(output_file);
				}
			}
			fclose(output_file);
			argc -= 3; argv += 3;
		}
		else if (!strcmp(str2[1], "e_readmem")) {
			if (argcount <= 4) { DBG_LOG("e_readmem addr length FILE\n"); argc = 1; continue; }
			uint32_t addr = strtoull(str2[2], NULL, 0);
			uint32_t length = strtoull(str2[3], NULL, 0);
			const char *fn = str2[4];
			uint32_t total_read = 0;
			FILE *fo = my_fopen(fn, "wb");
			if (!fo) ERR_EXIT("fopen(e_readmem) failed\n");
			while (total_read < length) {
				uint32_t chunk = length - total_read;
				if (chunk > (uint32_t)(blk_size ? blk_size : DEFAULT_BLK_SIZE)) chunk = (blk_size ? blk_size : DEFAULT_BLK_SIZE);
				WRITE32_LE(io->temp_buf, addr + total_read);
				WRITE32_LE(io->temp_buf + 4, chunk);
				encode_msg_nocpy(io, BSL_CMD_E_READ_MEM, 8);
				send_msg(io);
				int ret = recv_msg(io);
				if (!ret) ERR_EXIT("timeout reached\n");
				if ((ret = recv_type(io)) != BSL_REP_E_READ_MEM) {
					DBG_LOG("unexpected response (0x%04x)\n", ret);
					break;
				}
				uint16_t nread = READ16_BE(io->raw_buf + 2);
				if (nread > chunk) { DBG_LOG("unexpected length\n"); break; }
				if (fwrite(io->raw_buf + 4, 1, nread, fo) != nread)
					ERR_EXIT("fwrite(e_readmem) failed\n");
				total_read += nread;
				if (nread != chunk) break;
			}
			fclose(fo);
			DBG_LOG("e_readmem Done: addr=0x%llx, target=0x%llx, read=0x%llx\n",
				(unsigned long long)addr, (unsigned long long)length, (unsigned long long)total_read);
			argc -= 4; argv += 4;
		}
		else if (!strcmp(str2[1], "e_bl")) {
			encode_msg_nocpy(io, BSL_CMD_E_BL, 0);
			send_msg(io);
			if (recv_msg(io)) {
				uint16_t n = READ16_BE(io->raw_buf + 2);
				if (recv_type(io) == BSL_REP_E_BL) {
					uint8_t *out = malloc(n);
					if (!out) ERR_EXIT("malloc failed\n");
					for (uint16_t i = 0; i < n; i++)
						out[i] = (io->raw_buf + 4)[i] ^ (0x55 + i);
					print_mem(stderr, io->raw_buf + 4, n);
					DBG_LOG("XOR(0x55+i):\n");
					print_mem(stderr, out, n);
					free(out);
				}
				else {
					print_mem(stderr, io->raw_buf + 4, n);
				}
			}
			else ERR_EXIT("timeout reached\n");
			argc -= 1; argv += 1;
		}
		else if (!strcmp(str2[1], "e_rpmb_pagecount")) {
			encode_msg_nocpy(io, BSL_CMD_E_RPMB_PAGECOUNT, 0);
			send_msg(io);
			if (recv_msg(io)) DBG_LOG("0x%x\n", *(uint32_t *)(io->raw_buf + 4));
			else ERR_EXIT("timeout reached\n");
			argc -= 1; argv += 1;
		}
		else if (!strcmp(str2[1], "e_rpmb_counter")) {
			encode_msg_nocpy(io, BSL_CMD_E_RPMB_COUNTER, 0);
			send_msg(io);
			if (recv_msg(io)) DBG_LOG("0x%x\n", *(uint32_t *)(io->raw_buf + 4));
			else ERR_EXIT("timeout reached\n");
			argc -= 1; argv += 1;
		}
		else if (!strcmp(str2[1], "e_rpmb_read")) {
			if (argcount <= 4) { DBG_LOG("e_rpmb_read page_start page_count FILE\n"); argc = 1; continue; }
			uint32_t page_start = strtoul(str2[2], NULL, 0);
			uint32_t page_count = strtoul(str2[3], NULL, 0);
			const char *fn = str2[4];
			uint32_t pages_per_chunk = (blk_size ? blk_size : DEFAULT_BLK_SIZE) >> 8;
			if (pages_per_chunk < 1) pages_per_chunk = 1;
			uint32_t pages_read = 0;
			FILE *fo = my_fopen(fn, "wb");
			if (!fo) ERR_EXIT("fopen(e_rpmb_read) failed\n");
			while (pages_read < page_count) {
				uint32_t chunk = page_count - pages_read;
				if (chunk > pages_per_chunk) chunk = pages_per_chunk;
				uint8_t *data = (uint8_t *)io->temp_buf;
				WRITE16_LE(data, page_start + pages_read);
				WRITE16_LE(data + 2, chunk);
				encode_msg_nocpy(io, BSL_CMD_E_RPMB_READ, 4);
				send_msg(io);
				ret = recv_msg(io);
				if (!ret) ERR_EXIT("timeout reached\n");
				if (recv_type(io) != BSL_REP_E_RPMB_READ) {
					DBG_LOG("unexpected response (0x%04x)\n", recv_type(io));
					break;
				}
				uint16_t n = READ16_BE(io->raw_buf + 2);
				if (fwrite(io->raw_buf + 4, 1, n, fo) != n)
					ERR_EXIT("fwrite(e_rpmb_read) failed\n");
				pages_read += chunk;
				if (n < chunk << 8) { DBG_LOG("short read\n"); break; }
			}
			fclose(fo);
			DBG_LOG("e_rpmb_read Done: start=0x%x, count=0x%x, read=%u pages\n",
				page_start, page_count, pages_read);
			argc -= 4; argv += 4;
		}
		else if (!strcmp(str2[1], "e_rpmb_read_auto")) {
			encode_msg_nocpy(io, BSL_CMD_E_RPMB_PAGECOUNT, 0);
			send_msg(io);
			if (!recv_msg(io)) ERR_EXIT("timeout reached\n");
			if (recv_type(io) != BSL_REP_E_RPMB_PAGECOUNT) {
				DBG_LOG("unexpected response (0x%04x)\n", recv_type(io));
				argc -= 1; argv += 1;
				continue;
			}
			uint32_t page_count = *(uint32_t *)(io->raw_buf + 4);
			uint32_t page_start = 0;
			const char *fn = "rpmb_dump";
			uint32_t pages_per_chunk = (blk_size ? blk_size : DEFAULT_BLK_SIZE) >> 8;
			if (pages_per_chunk < 1) pages_per_chunk = 1;
			uint32_t pages_read = 0;
			FILE *fo = my_fopen(fn, "wb");
			if (!fo) ERR_EXIT("fopen(e_rpmb_read_auto) failed\n");
			while (pages_read < page_count) {
				uint32_t chunk = page_count - pages_read;
				if (chunk > pages_per_chunk) chunk = pages_per_chunk;
				uint8_t *data = (uint8_t *)io->temp_buf;
				WRITE16_LE(data, page_start + pages_read);
				WRITE16_LE(data + 2, chunk);
				encode_msg_nocpy(io, BSL_CMD_E_RPMB_READ, 4);
				send_msg(io);
				ret = recv_msg(io);
				if (!ret) ERR_EXIT("timeout reached\n");
				if (recv_type(io) != BSL_REP_E_RPMB_READ) {
					DBG_LOG("unexpected response (0x%04x)\n", recv_type(io));
					break;
				}
				uint16_t n = READ16_BE(io->raw_buf + 2);
				if (fwrite(io->raw_buf + 4, 1, n, fo) != n)
					ERR_EXIT("fwrite(e_rpmb_read_auto) failed\n");
				pages_read += chunk;
				if (n < chunk << 8) { DBG_LOG("short read\n"); break; }
			}
			fclose(fo);
			DBG_LOG("e_rpmb_read_auto Done: start=0x%x, count=0x%x, read=%u pages\n",
				page_start, page_count, pages_read);
			argc -= 1; argv += 1;
		}
		else if (!strcmp(str2[1], "e_rpmb_write")) {
			if (argcount <= 3) { DBG_LOG("e_rpmb_write page_start FILE\n"); argc = 1; continue; }
			encode_msg_nocpy(io, BSL_CMD_E_RPMB_PAGECOUNT, 0);
			send_msg(io);
			if (!recv_msg(io)) ERR_EXIT("timeout reached\n");
			if (recv_type(io) != BSL_REP_E_RPMB_PAGECOUNT) {
				DBG_LOG("unexpected response (0x%04x)\n", recv_type(io));
				argc -= 3; argv += 3;
				continue;
			}
			uint32_t page_count_max = *(uint32_t *)(io->raw_buf + 4);
			uint32_t page_start = strtoul(str2[2], NULL, 0);
			const char *fn = str2[3];
			size_t file_size = 0;
			uint8_t *file_buf = loadfile(fn, &file_size, 0);
			if (!file_buf || !file_size) ERR_EXIT("loadfile failed\n");
			if (file_size & 0xFF) ERR_EXIT("file size must be multiple of 256\n");
			uint32_t page_count = file_size >> 8;
			if (page_start >= page_count_max) {
				page_count = 0;
			}
			else if (page_start + page_count > page_count_max || page_start + page_count < page_start) {
				page_count = page_count_max - page_start;
			}
			uint32_t pages_per_chunk = (blk_size ? blk_size : DEFAULT_BLK_SIZE) >> 8;
			if (pages_per_chunk < 1) pages_per_chunk = 1;
			uint32_t pages_done = 0;
			while (pages_done < page_count) {
				uint32_t chunk = page_count - pages_done;
				if (chunk > pages_per_chunk) chunk = pages_per_chunk;
				uint8_t *data = (uint8_t *)io->temp_buf;
				WRITE16_LE(data, 0);
				WRITE16_LE(data + 2, page_start + pages_done);
				WRITE16_LE(data + 4, chunk);
				encode_msg_nocpy(io, BSL_CMD_E_RPMB_WRITE, 6);
				if (send_and_check(io)) {
					DBG_LOG("e_rpmb_write init_config failed\n");
					break;
				}
				WRITE16_LE(data, 1);
				memcpy(data + 2, file_buf + (pages_done << 8), chunk << 8);
				encode_msg_nocpy(io, BSL_CMD_E_RPMB_WRITE, (chunk << 8) + 2);
				if (send_and_check(io)) {
					DBG_LOG("e_rpmb_write send_data failed\n");
					break;
				}
				WRITE16_LE(data, 2);
				encode_msg_nocpy(io, BSL_CMD_E_RPMB_WRITE, 2);
				if (send_and_check(io)) print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
				pages_done += chunk;
			}
			free(file_buf);
			DBG_LOG("e_rpmb_write Done: start=0x%x, count=0x%x pages\n", page_start, page_count);
			argc -= 3; argv += 3;
		}
		else if (!strcmp(str2[1], "e_pwn")) {
			uint8_t *data = (uint8_t *)io->temp_buf;
			memset(data, 0, 32);
			if (selected_ab > 0) {
				char name_ab[16];
				snprintf(name_ab, sizeof(name_ab), "trustos_%c", 96 + selected_ab);
				memcpy(data, name_ab, strlen(name_ab));
			}
			else {
				memcpy(data, "trustos", 7);
			}
			for (int i = 0; i < 32; i++)
				data[i] ^= (0x65 + i);
			encode_msg_nocpy(io, BSL_CMD_E_CHECKPWN, 32);
			if (send_and_check(io) && *(uint32_t *)(io->raw_buf + 4) == 7) {
				encode_msg_nocpy(io, BSL_CMD_E_PWN, 32);
				if (send_and_check(io))
					print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			}
			else print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			argc -= 1; argv += 1;
		}
		else if (!strcmp(str2[1], "e_checkpwn")) {
			uint8_t *data = (uint8_t *)io->temp_buf;
			memset(data, 0, 32);
			if (selected_ab > 0) {
				char name_ab[16];
				snprintf(name_ab, sizeof(name_ab), "trustos_%c", 96 + selected_ab);
				memcpy(data, name_ab, strlen(name_ab));
			}
			else {
				memcpy(data, "trustos", 7);
			}
			for (int i = 0; i < 32; i++)
				data[i] ^= (0x65 + i);
			encode_msg_nocpy(io, BSL_CMD_E_CHECKPWN, 32);
			if (send_and_check(io))
				print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			argc -= 1; argv += 1;
		}
		else if (!strcmp(str2[1], "sendpack")) { //this is pack (7e type length data crc 7e)
			if (argcount <= 2) { DBG_LOG("sendpack file\n"); argc = 1; continue; }
			size_t length = 0;
			FILE *fi = fopen(str2[2], "rb");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 2; argv += 2; continue; }
			fseek(fi, 0, SEEK_END);
			length = ftell(fi);
			if (!length) { DBG_LOG("File is empty.\n"); argc -= 2; argv += 2; continue; }
			fseek(fi, 0, SEEK_SET);
			ret = fread(io->untranscode_buf, 1, length, fi);
			fclose(fi);
			io->send_buf = io->untranscode_buf;
			io->enc_len = length;
			if (send_and_check(io)) print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			argc -= 2; argv += 2;
		}
		else if (!strcmp(str2[1], "rawpack")) { //this is pack (type length data [ignored-crc]), crc and transcode will be performed
			if (argcount <= 2) { DBG_LOG("rawpack file\n"); argc = 1; continue; }
			size_t length = 0, len = 0;
			FILE *fi = fopen(str2[2], "rb");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 2; argv += 2; continue; }
			fseek(fi, 0, SEEK_END);
			length = ftell(fi);
			if (!length) { DBG_LOG("File is empty.\n"); argc -= 2; argv += 2; continue; }
			fseek(fi, 0, SEEK_SET);
			ret = fread(io->untranscode_buf + 1, 1, length, fi);
			fclose(fi);
			encode_rawpack_nocpy(io);
			if (send_and_check(io)) print_mem(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			argc -= 2; argv += 2;
		}
		else if (!strcmp(str2[1], "write_word")) {
			uint32_t addr, data;
			if (argc <= 3) { DBG_LOG("write_word addr VALUE(max is 0xFFFFFFFF)\n"); argc = 1; continue; }

			addr = strtoul(str2[2], NULL, 0);
			data = strtoul(str2[3], NULL, 0);
			send_buf(io, addr, end_data, 528, (uint8_t *)&data, 4);
			argc -= 3; argv += 3;
		}
		else if (!strcmp(str2[1], "send") || !strcmp(str2[1], "write_flash")) {
			const char *fn; uint32_t addr = 0; FILE *fi;
			if (argcount <= 3) { DBG_LOG("send|write_flash FILE addr\n"); argc = 1; continue; }

			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 3; argv += 3; continue; }
			else fclose(fi);
			addr = strtoul(str2[3], NULL, 0);
			if (!strcmp(str2[1], "send")) send_file(io, fn, addr, 0, 528, 0, 0);
			else send_file(io, fn, addr, end_data, 528, 0, 0);
			argc -= 3; argv += 3;
		}
		else if (!strncmp(str2[1], "fdl", 3) || !strncmp(str2[1], "loadfdl", 7)) {
			const char *fn; uint32_t addr = 0; FILE *fi;
			int addr_in_name = !strncmp(str2[1], "loadfdl", 7);
			int argchange;

			fn = str2[2];
			if (addr_in_name) {
				argchange = 2;
				if (argcount <= argchange) { DBG_LOG("loadfdl FILE\n"); argc = 1; continue; }
				char *pos = NULL, *last_pos = NULL;

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
				if (argcount <= argchange) { DBG_LOG("fdl FILE addr\n"); argc = 1; continue; }
				addr = strtoul(str2[3], NULL, 0);
			}

			if (fdl2_executed > 0) {
				DBG_LOG("FDL2 ALREADY EXECUTED, SKIP\n");
				argc -= argchange; argv += argchange;
				continue;
			}
			else if (fdl1_loaded > 0) {
				if (fdl2_executed != -1) {
					fi = fopen(fn, "r");
					if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= argchange; argv += argchange; continue; }
					else fclose(fi);
					send_file(io, fn, addr, end_data, blk_size ? blk_size : 528, 0, 0);
				}
			}
			else {
				if (addr && fdl1_loaded != -1) {
					fi = fopen(fn, "r");
					if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= argchange; argv += argchange; continue; }
					else fclose(fi);
					if (exec_addr_v2) {
						size_t execsize = send_file(io, fn, addr, 0, 528, 0, 0);
						int n, gapsize = exec_addr - addr - execsize;
						for (i = 0; i < gapsize; i += n) {
							n = gapsize - i;
							if (n > 528) n = 528;
							encode_msg_nocpy(io, BSL_CMD_MIDST_DATA, n);
							if (send_and_check(io)) exit(1);
						}
						fi = fopen(execfile, "rb");
						if (fi) {
							fseek(fi, 0, SEEK_END);
							n = ftell(fi);
							fseek(fi, 0, SEEK_SET);
							execsize = fread(io->temp_buf, 1, n, fi);
							fclose(fi);
						}
						encode_msg_nocpy(io, BSL_CMD_MIDST_DATA, execsize);
						if (send_and_check(io)) exit(1);
						DBG_LOG("SEND %s to 0x%x\n", execfile, exec_addr);
						free(execfile);
					}
					else {
						send_file(io, fn, addr, end_data, 528, 0, 0);
						if (exec_addr) {
							send_file(io, execfile, exec_addr, 0, 528, 0, 0);
							free(execfile);
						}
						else {
							size_t size = 0;
							uint8_t *payload = loadfile(fn, &size, 0);
							if (*(uint32_t *)payload == 0x42544844) {
								sys_img_header *header = (sys_img_header *)payload;
								if (header->mImgSize) {
									if (header->mImgSize + 0x200 + sizeof(sprdsignedimageheader) < size) {
										sprdsignedimageheader *footer = (sprdsignedimageheader *)&payload[header->mImgSize + 0x200];
										if (footer->cert_offset) {
											uint32_t key_size = *(uint32_t *)(payload + footer->cert_offset + 4);
											if (key_size % 0x800) {
												exec_addr = 1;
												DBG_LOG("bypassing BROM verification with CVE-2022-38691 (key size 0x%0X)\n", key_size);
											}
										}
									}
								}
							}
							free(payload);
							encode_msg_nocpy(io, BSL_CMD_EXEC_DATA, 0);
							if (send_and_check(io)) exit(1);
						}
					}
				}
				else {
					encode_msg_nocpy(io, BSL_CMD_EXEC_DATA, 0);
					if (send_and_check(io)) exit(1);
				}
				DBG_LOG("EXEC FDL1\n");
				if (addr == 0x5500 || addr == 0x65000800 || addr == 0x65008000) {
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
				if (!memcmp(io->raw_buf + 4, "SPRD4", 5)) {
					fdl2_executed = -1;
					if (argc < 1) argc = 1;
					argc += 1;
				}

#if FDL1_DUMP_MEM
				//read dump mem
				int pagecount = 0;
				char *pdump;
				char chdump;
				FILE *fdump;
				fdump = fopen("memdump", "wb");
				encode_msg(io, BSL_CMD_CHECK_BAUD, NULL, 1);
				while (1) {
					send_msg(io);
					ret = recv_msg(io);
					if (!ret) ERR_EXIT("timeout reached\n");
					if (recv_type(io) == BSL_CMD_READ_END) break;
					pdump = (char *)(io->raw_buf + 4);
					for (i = 0; i < 512; i++) {
						chdump = *(pdump++);
						if (chdump == 0x7d) {
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

				encode_msg_nocpy(io, BSL_CMD_CONNECT, 0);
				if (send_and_check(io)) exit(1);
				DBG_LOG("CMD_CONNECT FDL1\n");
#if !USE_LIBUSB
				if (baudrate) {
					uint8_t *data = io->temp_buf;
					WRITE32_BE(data, baudrate);
					encode_msg_nocpy(io, BSL_CMD_CHANGE_BAUD, 4);
					if (!send_and_check(io)) {
						DBG_LOG("CHANGE_BAUD FDL1 to %d\n", baudrate);
						call_SetProperty(io->handle, 0, 100, (LPCVOID)&baudrate);
					}
				}
#endif
				if (keep_charge) {
					encode_msg_nocpy(io, BSL_CMD_KEEP_CHARGE, 0);
					if (!send_and_check(io)) DBG_LOG("KEEP_CHARGE FDL1\n");
				}
				fdl1_loaded = 1;
			}
			argc -= argchange; argv += argchange;

		}
		else if (!strcmp(str2[1], "exec")) {
			if (fdl2_executed > 0) {
				DBG_LOG("FDL2 ALREADY EXECUTED, SKIP\n");
				argc -= 1; argv += 1;
				continue;
			}
			else if (fdl1_loaded > 0) {
				memset(&Da_Info, 0, sizeof(Da_Info));
				encode_msg_nocpy(io, BSL_CMD_EXEC_DATA, 0);
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
					encode_msg_nocpy(io, BSL_CMD_DISABLE_TRANSCODE, 0);
					if (!send_and_check(io)) {
						io->flags &= ~FLAGS_TRANSCODE;
						DBG_LOG("DISABLE_TRANSCODE\n");
					}
				}
				g_spl_size = check_partition(io, "splloader", 1);
				if (Da_Info.bSupportRawData) {
					blk_size = 0xf800;
					io->ptable = partition_list(io, fn_partlist, &io->part_count);
					if (fdl2_executed) {
						Da_Info.bSupportRawData = 0;
						DBG_LOG("DISABLE_WRITE_RAW_DATA in SPRD4\n");
					}
					else {
						encode_msg_nocpy(io, BSL_CMD_ENABLE_RAW_DATA, 0);
						if (!send_and_check(io)) DBG_LOG("ENABLE_WRITE_RAW_DATA\n");
					}
				}
				else if (highspeed || Da_Info.dwStorageType == 0x103) {
					blk_size = 0xf800;
					io->ptable = partition_list(io, fn_partlist, &io->part_count);
				}
				else if (Da_Info.dwStorageType == 0x102) {
					io->ptable = partition_list(io, fn_partlist, &io->part_count);
				}
				else if (Da_Info.dwStorageType == 0x101) DBG_LOG("Storage is nand\n");
				if (gpt_failed != 1) {
					if (exec_addr) g_w_force = 1;
					if (selected_ab == 2) DBG_LOG("Device is using slot b\n");
					else if (selected_ab == 1) DBG_LOG("Device is using slot a\n");
					else {
						DBG_LOG("Device is not using VAB\n");
						if (Da_Info.bSupportRawData) {
							DBG_LOG("RAW_DATA level is %u, but DISABLED for stability, you can set it manually\n", (unsigned)Da_Info.bSupportRawData);
							Da_Info.bSupportRawData = 0;
						}
					}
				}
				if (nand_id == DEFAULT_NAND_ID) {
					nand_info[0] = (uint8_t)pow(2, nand_id & 3); //page size
					nand_info[1] = 32 / (uint8_t)pow(2, (nand_id >> 2) & 3); //spare area size
					nand_info[2] = 64 * (uint8_t)pow(2, (nand_id >> 4) & 3); //block size
				}
				io->timeout = 3000;
				fdl2_executed = 1;
			}
			argc -= 1; argv += 1;
#if !USE_LIBUSB
		}
		else if (!strcmp(str2[1], "baudrate")) {
			if (argcount > 2) {
				baudrate = strtoul(str2[2], NULL, 0);
				if (fdl2_executed) call_SetProperty(io->handle, 0, 100, (LPCVOID)&baudrate);
			}
			DBG_LOG("baudrate is %u\n", baudrate);
			argc -= 2; argv += 2;
#endif
		}
		else if (!strcmp(str2[1], "path")) {
			if (argcount > 2) strcpy(savepath, str2[2]);
			my_mkdir(savepath);
			DBG_LOG("save dir is %s\n", savepath);
			argc -= 2; argv += 2;

		}
		else if (!strncmp(str2[1], "exec_addr", 9)) {
			FILE *fi;
			if (0 == fdl1_loaded && argcount > 2) {
				exec_addr = strtoul(str2[2], NULL, 0);
				sprintf(execfile, "custom_exec_no_verify_%x.bin", exec_addr);
				fi = fopen(execfile, "r");
				if (fi == NULL) { DBG_LOG("%s does not exist\n", execfile); exec_addr = 0; }
				else fclose(fi);
			}
			DBG_LOG("current exec_addr is 0x%x\n", exec_addr);
			if (!strcmp(str2[1], "exec_addr2")) exec_addr_v2 = 1;
			argc -= 2; argv += 2;
		}
		else if (!strncmp(str2[1], "loadexec", 8)) {
			const char *fn; char *ch; FILE *fi;
			if (argcount <= 2) { DBG_LOG("loadexec FILE\n"); argc = 1; continue; }
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
			if (!strcmp(str2[1], "loadexec2")) exec_addr_v2 = 1;
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "nand_id")) {
			if (argcount > 2) {
				nand_id = strtol(str2[2], NULL, 0);
				nand_info[0] = (uint8_t)pow(2, nand_id & 3); //page size
				nand_info[1] = 32 / (uint8_t)pow(2, (nand_id >> 2) & 3); //spare area size
				nand_info[2] = 64 * (uint8_t)pow(2, (nand_id >> 4) & 3); //block size
			}
			DBG_LOG("current nand_id is 0x%x\n", nand_id);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "read_flash")) {
			const char *fn; uint64_t addr, offset, size;
			if (argcount <= 5) { DBG_LOG("read_flash addr offset size FILE\n"); argc = 1; continue; }

			addr = str_to_size(str2[2]);
			offset = str_to_size(str2[3]);
			size = str_to_size(str2[4]);
			fn = str2[5];
			if ((addr | size | offset | (addr + offset + size)) >> 32) { DBG_LOG("32-bit limit reached\n"); argc -= 5; argv += 5; continue; }
			dump_flash(io, addr, offset, size, fn, blk_size ? blk_size : 1024);
			argc -= 5; argv += 5;

		}
		else if (!strcmp(str2[1], "erase_flash")) {
			uint64_t addr, size;
			if (argc <= 3) { DBG_LOG("erase_flash addr size\n"); argc = 1; continue; }
			if (!skip_confirm)
				if (!check_confirm("erase flash")) {
					argc -= 3; argv += 3;
					continue;
				}
			addr = str_to_size(str2[2]);
			size = str_to_size(str2[3]);
			if ((addr | size | (addr + size)) >> 32)
				ERR_EXIT("32-bit limit reached\n");
			uint32_t *data = (uint32_t *)io->temp_buf;
			WRITE32_BE(data, addr);
			WRITE32_BE(data + 1, size);
			encode_msg_nocpy(io, BSL_CMD_ERASE_FLASH, 4 * 2);
			if (!send_and_check(io)) DBG_LOG("Erase Flash Done: 0x%08x\n", (int)addr);
			argc -= 3; argv += 3;

		}
		else if (!strcmp(str2[1], "read_mem")) {
			const char *fn; uint64_t addr, size;
			if (argcount <= 4) { DBG_LOG("read_mem addr size FILE\n"); argc = 1; continue; }

			addr = str_to_size(str2[2]);
			size = str_to_size(str2[3]);
			fn = str2[4];
			if ((addr | size | (addr + size)) >> 32) { DBG_LOG("32-bit limit reached\n"); argc -= 4; argv += 4; continue; }
			dump_mem(io, addr, size, fn, blk_size ? blk_size : 1024);
			argc -= 4; argv += 4;

		}
		else if (!strcmp(str2[1], "part_size") || !strcmp(str2[1], "size_part")) {
			const char *name;
			if (argcount <= 2) { DBG_LOG("size_part part_name\n"); argc = 1; continue; }

			name = str2[2];
			if (selected_ab < 0) select_ab(io);
			DBG_LOG("%lld\n", (long long)check_partition(io, name, 1));
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "p") || !strcmp(str2[1], "print")) {
			if (io->part_count) {
				DBG_LOG("  0 %36s     256KB\n", "splloader");
				for (i = 0; i < io->part_count; i++) {
					DBG_LOG("%3d %36s %7lldMB\n", i + 1, (*(io->ptable + i)).name, ((*(io->ptable + i)).size >> 20));
				}
			}
			argc -= 1; argv += 1;

		}
		else if (!strcmp(str2[1], "check_part")) {
			const char *name;
			if (argcount <= 2) { DBG_LOG("check_part part_name\n"); argc = 1; continue; }

			name = str2[2];
			if (selected_ab < 0) select_ab(io);
			DBG_LOG("%lld\n", (long long)check_partition(io, name, 0));
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "read_part")) {
			const char *name, *fn; uint64_t offset, size;
			uint64_t realsize = 0;
			if (argcount <= 5) { DBG_LOG("read_part part_name offset size FILE\n(read ubi on nand) read_part system 0 ubi40m system.bin\n"); argc = 1; continue; }

			offset = str_to_size_ubi(str2[3], nand_info);
			size = str_to_size_ubi(str2[4], nand_info);
			fn = str2[5];

			name = str2[2];
			get_partition_info(io, name, 0);
			if (!gPartInfo.size) { DBG_LOG("part not exist\n"); argc -= 5; argv += 5; continue; }

			if (0xffffffff == size) size = check_partition(io, gPartInfo.name, 1);
			if (offset + size < offset) { DBG_LOG("64-bit limit reached\n"); argc -= 5; argv += 5; continue; }
			dump_partition(io, gPartInfo.name, offset, size, fn, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			argc -= 5; argv += 5;

		}
		else if (!strcmp(str2[1], "r")) {
			const char *name = str2[2];
			int loop_count = 0, in_loop = 0;
			const char *list[] = { "vbmeta", "splloader", "uboot", "sml", "trustos", "teecfg", "boot", "recovery", "init_boot" };
			if (argcount <= 2) { DBG_LOG("r all/all_lite/part_name/part_id\n"); argc = 1; continue; }
			if (!strcmp(name, "preset_modem")) {
				if (gpt_failed == 1) io->ptable = partition_list(io, fn_partlist, &io->part_count);
				if (!io->part_count) { DBG_LOG("Partition table not available\n"); argc -= 2; argv += 2; continue; }
				if (selected_ab > 0) { DBG_LOG("saving slot info\n"); dump_partition(io, "misc", 0, 1048576, "misc", blk_size); }
				for (i = 0; i < io->part_count; i++)
					if (0 == strncmp("l_", (*(io->ptable + i)).name, 2) || 0 == strncmp("nr_", (*(io->ptable + i)).name, 3))
						dump_partition(io, (*(io->ptable + i)).name, 0, (*(io->ptable + i)).size, (*(io->ptable + i)).name, blk_size ? blk_size : DEFAULT_BLK_SIZE);
				argc -= 2; argv += 2;
				continue;
			}
			else if (!strcmp(name, "all")) {
				if (gpt_failed == 1) io->ptable = partition_list(io, fn_partlist, &io->part_count);
				if (!io->part_count) { DBG_LOG("Partition table not available\n"); argc -= 2; argv += 2; continue; }
				{ /* save partition.xml */
					FILE *fo = fopen("partition.xml", "wb");
					if (fo) {
						fprintf(fo, "<Partitions>\n");
						for (i = 0; i < io->part_count; i++) {
							fprintf(fo, "    <Partition id=\"%s\" size=\"", (*(io->ptable + i)).name);
							if (i + 1 == io->part_count) fprintf(fo, "0x%x\"/>\n", ~0);
							else fprintf(fo, "%lld\"/>\n", ((*(io->ptable + i)).size >> 20));
						}
						fprintf(fo, "</Partitions>\n");
						fclose(fo);
					}
					else DBG_LOG("create partition.xml failed, skipping.\n");
				}
				dump_partition(io, "splloader", 0, g_spl_size, "splloader", blk_size ? blk_size : DEFAULT_BLK_SIZE);
				for (i = 0; i < io->part_count; i++) {
					if (!strncmp((*(io->ptable + i)).name, "blackbox", 8)) continue;
					else if (!strncmp((*(io->ptable + i)).name, "cache", 5)) continue;
					else if (!strncmp((*(io->ptable + i)).name, "userdata", 8)) continue;
					dump_partition(io, (*(io->ptable + i)).name, 0, (*(io->ptable + i)).size, (*(io->ptable + i)).name, blk_size ? blk_size : DEFAULT_BLK_SIZE);
				}
				argc -= 2; argv += 2;
				continue;
			}
			else if (!strcmp(name, "all_lite")) {
				if (gpt_failed == 1) io->ptable = partition_list(io, fn_partlist, &io->part_count);
				if (!io->part_count) { DBG_LOG("Partition table not available\n"); argc -= 2; argv += 2; continue; }
				{ /* save partition.xml */
					FILE *fo = fopen("partition.xml", "wb");
					if (fo) {
						fprintf(fo, "<Partitions>\n");
						for (i = 0; i < io->part_count; i++) {
							fprintf(fo, "    <Partition id=\"%s\" size=\"", (*(io->ptable + i)).name);
							if (i + 1 == io->part_count) fprintf(fo, "0x%x\"/>\n", ~0);
							else fprintf(fo, "%lld\"/>\n", ((*(io->ptable + i)).size >> 20));
						}
						fprintf(fo, "</Partitions>\n");
						fclose(fo);
					}
					else DBG_LOG("create partition.xml failed, skipping.\n");
				}
				dump_partition(io, "splloader", 0, g_spl_size, "splloader", blk_size ? blk_size : DEFAULT_BLK_SIZE);
				for (i = 0; i < io->part_count; i++) {
					size_t namelen = strlen((*(io->ptable + i)).name);
					if (!strncmp((*(io->ptable + i)).name, "blackbox", 8)) continue;
					else if (!strncmp((*(io->ptable + i)).name, "cache", 5)) continue;
					else if (!strncmp((*(io->ptable + i)).name, "userdata", 8)) continue;
					if (selected_ab == 1 && namelen > 2 && 0 == strcmp((*(io->ptable + i)).name + namelen - 2, "_b")) continue;
					else if (selected_ab == 2 && namelen > 2 && 0 == strcmp((*(io->ptable + i)).name + namelen - 2, "_a")) continue;
					dump_partition(io, (*(io->ptable + i)).name, 0, (*(io->ptable + i)).size, (*(io->ptable + i)).name, blk_size ? blk_size : DEFAULT_BLK_SIZE);
				}
				argc -= 2; argv += 2;
				continue;
			}
			else {
				if (!strcmp(name, "preset_resign")) {
					loop_count = sizeof(list) / sizeof(list[0]); name = list[--loop_count]; in_loop = 1;
				}
rloop:
				get_partition_info(io, name, 1);
				if (!gPartInfo.size) {
					if (loop_count) { name = list[--loop_count]; goto rloop; }
					DBG_LOG("part not exist\n");
					argc -= 2; argv += 2;
					continue;
				}
			}
			char dfile[40];
			if (isdigit(str2[2][0])) snprintf(dfile, sizeof(dfile), "%s", gPartInfo.name);
			else if (in_loop) snprintf(dfile, sizeof(dfile), "%s", list[loop_count]);
			else snprintf(dfile, sizeof(dfile), "%s", name);
			dump_partition(io, gPartInfo.name, 0, gPartInfo.size, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			if (loop_count) { name = list[--loop_count]; goto rloop; }
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "read_parts")) {
			const char *fn; FILE *fi;
			if (argcount <= 2) { DBG_LOG("read_parts partition_list_file\n"); argc = 1; continue; }
			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 2; argv += 2; continue; }
			else fclose(fi);
			dump_partitions(io, fn, nand_info, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "partition_list")) {
			if (argcount <= 2) { DBG_LOG("partition_list FILE\n"); argc = 1; continue; }
			if (gpt_failed == 1) io->ptable = partition_list(io, str2[2], &io->part_count);
			if (!io->part_count) { DBG_LOG("Partition table not available\n"); argc -= 2; argv += 2; continue; }
			else {
				DBG_LOG("  0 %36s     256KB\n", "splloader");
				FILE *fo = fopen(str2[2], "wb");
				if (!fo) ERR_EXIT("fopen failed\n");
				fprintf(fo, "<Partitions>\n");
				for (i = 0; i < io->part_count; i++) {
					DBG_LOG("%3d %36s %7lldMB\n", i + 1, (*(io->ptable + i)).name, ((*(io->ptable + i)).size >> 20));
					fprintf(fo, "    <Partition id=\"%s\" size=\"", (*(io->ptable + i)).name);
					if (i + 1 == io->part_count) fprintf(fo, "0x%x\"/>\n", ~0);
					else fprintf(fo, "%lld\"/>\n", ((*(io->ptable + i)).size >> 20));
				}
				fprintf(fo, "</Partitions>");
				fclose(fo);
			}
			argc -= 2; argv += 2;

		}
		else if (!strncmp(str2[1], "repart", 6)) {
			const char *fn; FILE *fi;
			if (argcount <= 2) { DBG_LOG("repartition FILE\n"); argc = 1; continue; }
			fn = str2[2];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 2; argv += 2; continue; }
			else fclose(fi);
			if (skip_confirm) repartition(io, str2[2]);
			else if (check_confirm("repartition")) repartition(io, str2[2]);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "erase_part") || !strcmp(str2[1], "e")) {
			const char *name = str2[2];
			if (argcount <= 2) { DBG_LOG("erase_part part_name/part_id\n"); argc = 1; continue; }
			if (!strcmp(name, "all")) {
				if (!check_confirm("erase all")) {
					argc -= 2; argv += 2;
					continue;
				}
				strcpy(gPartInfo.name, "all");
			}
			else {
				if (!skip_confirm)
					if (!check_confirm("erase partition")) {
						argc -= 2; argv += 2;
						continue;
					}
				get_partition_info(io, name, 0);
			}
			if (!gPartInfo.size) { DBG_LOG("part not exist\n"); argc -= 2; argv += 2; continue; }
			erase_partition(io, gPartInfo.name);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "erase_all")) {
			if (!check_confirm("erase all")) {
				argc -= 1; argv += 1;
				continue;
			}
			erase_partition(io, "all");
			argc -= 1; argv += 1;

		}
		else if (!strcmp(str2[1], "write_part") || !strcmp(str2[1], "w")) {
			const char *fn; FILE *fi;
			const char *name = str2[2];
			if (argcount <= 3) { DBG_LOG("write_part part_name/part_id FILE\n"); argc = 1; continue; }
			fn = str2[3];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 3; argv += 3; continue; }
			else fclose(fi);
			if (!skip_confirm)
				if (!check_confirm("write partition")) {
					argc -= 3; argv += 3;
					continue;
				}
			get_partition_info(io, name, 0);
			if (!gPartInfo.size) { DBG_LOG("part not exist\n"); argc -= 3; argv += 3; continue; }

			load_partition_unify(io, gPartInfo.name, fn, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			argc -= 3; argv += 3;

		}
		else if (!strncmp(str2[1], "write_parts", 11)) {
			if (argcount <= 2) { DBG_LOG("write_parts|write_parts_a|write_parts_b save_location\n"); argc = 1; continue; }
			int force_ab = 0;
			if (!strcmp(str2[1], "write_parts_a")) force_ab = 1;
			else if (!strcmp(str2[1], "write_parts_b")) force_ab = 2;
			if (skip_confirm || check_confirm("write all partitions")) load_partitions(io, str2[2], blk_size ? blk_size : DEFAULT_BLK_SIZE, force_ab);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "g_w_force")) {
			if (argcount <= 2) { DBG_LOG("g_w_force {0,1,2}\n"); argc = 1; continue; }
			g_w_force = atoi(str2[2]);
			if (g_w_force < 0) g_w_force = 0;
			if (g_w_force > 2) g_w_force = 2;
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "w_force")) {
			const char *fn; FILE *fi;
			const char *name = str2[2];
			if (argcount <= 3) { DBG_LOG("w_force part_name/part_id FILE\n"); argc = 1; continue; }
			if (Da_Info.dwStorageType == 0x101) { DBG_LOG("w_force is not allowed on NAND(UBI) devices\n"); argc -= 3; argv += 3; continue; }
			if (!io->part_count) { DBG_LOG("Partition table not available\n"); argc -= 3; argv += 3; continue; }
			fn = str2[3];
			fi = fopen(fn, "r");
			if (fi == NULL) { DBG_LOG("File does not exist.\n"); argc -= 3; argv += 3; continue; }
			else fclose(fi);
			get_partition_info(io, name, 0);
			if (!gPartInfo.size) { DBG_LOG("part not exist\n"); argc -= 3; argv += 3; continue; }
			int g_force_backup = g_w_force;
			g_w_force = 2;

			if (!strncmp(gPartInfo.name, "splloader", 9)) { DBG_LOG("blacklist!\n"); g_w_force = g_force_backup; argc -= 3; argv += 3; continue; }
			else if (isdigit(str2[2][0])) load_partition_force(io, atoi(str2[2]) - 1, fn, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			else {
				for (i = 0; i < io->part_count; i++)
					if (!strcmp(gPartInfo.name, (*(io->ptable + i)).name)) {
						load_partition_force(io, i, fn, blk_size ? blk_size : DEFAULT_BLK_SIZE);
						break;
					}
			}
			g_w_force = g_force_backup;
			argc -= 3; argv += 3;

		}
		else if (!strcmp(str2[1], "wof") || !strcmp(str2[1], "wov")) {
			uint64_t offset;
			size_t length;
			uint8_t *src;
			const char *name = str2[2];
			if (argcount <= 4) { DBG_LOG("wof part_name offset FILE\nwov part_name offset VALUE(max is 0xFFFFFFFF)\n"); argc = 1; continue; }
			if (strstr(name, "fixnv") || strstr(name, "runtimenv") || strstr(name, "userdata")) {
				DBG_LOG("blacklist!\n");
				argc -= 4; argv += 4;
				continue;
			}

			offset = str_to_size(str2[3]);
			if (!strcmp(str2[1], "wov")) {
				src = malloc(4);
				if (!src) { DBG_LOG("malloc failed\n"); argc -= 4; argv += 4; continue; }
				length = 4;
				*(uint32_t *)src = strtoul(str2[4], NULL, 0);
			}
			else {
				const char *fn = str2[4];
				src = loadfile(fn, &length, 0);
				if (!src) { DBG_LOG("fopen %s failed\n", fn); argc -= 4; argv += 4; continue; }
			}
			w_mem_to_part_offset(io, name, offset, src, length, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			free(src);
			argc -= 4; argv += 4;

		}
		else if (!strcmp(str2[1], "read_pactime")) {
			read_pactime(io);
			argc -= 1; argv += 1;

		}
		else if (!strcmp(str2[1], "blk_size") || !strcmp(str2[1], "bs")) {
			if (argcount <= 2) { DBG_LOG("blk_size byte\n\tmax is 65535\n"); argc = 1; continue; }
			blk_size = strtol(str2[2], NULL, 0);
#ifndef _MYDEBUG
			blk_size = blk_size < 0 ? 0 :
				blk_size > 0xf800 ? 0xf800 : ((blk_size + 0x7FF) & ~0x7FF);
#else
			blk_size = blk_size < 0 ? 0 : blk_size;
#endif
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "fblk_size") || !strcmp(str2[1], "fbs")) {
			if (argcount <= 2) { DBG_LOG("fblk_size mb\n"); argc = 1; continue; }
			fblk_size = strtoull(str2[2], NULL, 0) * 1024 * 1024;
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "verity")) {
			if (argcount <= 2) { DBG_LOG("verity {0,1}\n"); argc = 1; continue; }
			if (atoi(str2[2])) dm_enable(io, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			else {
				if (!io->part_count) {
					DBG_LOG("Warning: disable dm-verity needs a valid partition table or a write-verification-disabled FDL2\n");
					if (!skip_confirm)
						if (!check_confirm("disable dm-verity")) {
							argc -= 2; argv += 2;
							continue;
						}
				}
				dm_disable(io, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			}
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "set_active")) {
			if (argcount <= 2) { DBG_LOG("set_active {a,b}\n"); argc = 1; continue; }
			set_active(io, str2[2]);
			selected_ab = str2[2][0] - 'a' + 1;
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "firstmode")) {
			if (argcount <= 2) { DBG_LOG("firstmode mode_id\n"); argc = 1; continue; }
			uint8_t *modebuf = malloc(4);
			if (!modebuf) ERR_EXIT("malloc failed\n");
			uint32_t mode = strtol(str2[2], NULL, 0) + 0x53464D00;
			memcpy(modebuf, &mode, 4);
			w_mem_to_part_offset(io, "miscdata", 0x2420, modebuf, 4, 0x1000);
			free(modebuf);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "skip_confirm")) {
			if (argcount <= 2) { DBG_LOG("skip_confirm {0,1}\n"); argc = 1; continue; }
			skip_confirm = atoi(str2[2]);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "rawdata")) {
			if (argcount <= 2) { DBG_LOG("rawdata {0,1,2}\n"); argc = 1; continue; }
			Da_Info.bSupportRawData = atoi(str2[2]);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "slot")) {
			if (argcount <= 2) { DBG_LOG("slot {0,1,2}\n"); argc = 1; continue; }
			selected_ab = atoi(str2[2]);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "chip_uid")) {
			encode_msg_nocpy(io, BSL_CMD_READ_CHIP_UID, 0);
			send_msg(io);
			ret = recv_msg(io);
			if (!ret) ERR_EXIT("timeout reached\n");
			if ((ret = recv_type(io)) != BSL_REP_READ_CHIP_UID) {
				DBG_LOG("unexpected response (0x%04x)\n", ret); argc -= 1; argv += 1; continue;
			}

			DBG_LOG("BSL_REP_READ_CHIP_UID: ");
			print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
			argc -= 1; argv += 1;

		}
		else if (!strcmp(str2[1], "disable_transcode")) {
			encode_msg_nocpy(io, BSL_CMD_DISABLE_TRANSCODE, 0);
			if (!send_and_check(io)) io->flags &= ~FLAGS_TRANSCODE;
			argc -= 1; argv += 1;

		}
		else if (!strcmp(str2[1], "transcode")) {
			unsigned a, f;
			if (argcount <= 2) { DBG_LOG("transcode {0,1}\n"); argc = 1; continue; }
			a = atoi(str2[2]);
			if (a >> 1) { DBG_LOG("transcode {0,1}\n"); argc -= 2; argv += 2; continue; }
			f = (io->flags & ~FLAGS_TRANSCODE);
			io->flags = f | (a ? FLAGS_TRANSCODE : 0);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "keep_charge")) {
			if (argcount <= 2) { DBG_LOG("keep_charge {0,1}\n"); argc = 1; continue; }
			keep_charge = atoi(str2[2]);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "timeout")) {
			if (argcount <= 2) { DBG_LOG("timeout ms\n"); argc = 1; continue; }
			io->timeout = atoi(str2[2]);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "end_data")) {
			if (argcount <= 2) { DBG_LOG("end_data {0,1}\n"); argc = 1; continue; }
			end_data = atoi(str2[2]);
			argc -= 2; argv += 2;

		}
		else if (!strcmp(str2[1], "dis_avb")) {
			dis_avb_with_cve(io, blk_size ? blk_size : DEFAULT_BLK_SIZE);
			argc -= 1; argv += 1;

		}
		else if (!strcmp(str2[1], "dis_avb_ex")) {
			if (argcount <= 3) { DBG_LOG("dis_avb_ex sml_or_teecfg tos\n"); argc = 1; continue; }
			char *fn_tos = NULL;
			if (!bsp_chsize(str2[2])) {
				DBG_LOG("sml_or_teecfg chsize error.\n");
				argc -= 3; argv += 3; continue;
			}
			if (dis_avb(str2[3])) fn_tos = "tos-noavb";
			else fn_tos = str2[3];
			if (!bsp_cve_2img(str2[2], fn_tos, "tos-noavb-bsp-bypassed"))
				DBG_LOG("bsp_cve: failed or already patched.\n");
			argc -= 3; argv += 3;

		}
		else if (!strcmp(str2[1], "mergenv-xml")) {
			if (argcount <= 3) { DBG_LOG("mergenv-xml xml new_nv\n"); argc = 1; continue; }
			get_partition_info(io, "nr_fixnv1", 1);
			if (!gPartInfo.size) get_partition_info(io, "l_fixnv1", 1);
			if (!gPartInfo.size) { DBG_LOG("part not exist\n");  argc -= 3; argv += 3; continue; }
			dump_partition(io, gPartInfo.name, 0, gPartInfo.size, "nvbak", blk_size ? blk_size : DEFAULT_BLK_SIZE);
			if (get_nvlist_xml(io, str2[2])) {
				size_t a_size = 0, b_size = 0, c_size = 0;
				uint8_t *a = loadfile("nvbak", &a_size, 0);
				uint8_t *b = loadfile(str2[3], &b_size, 0);
				uint8_t *c = calloc(a_size + b_size, 1);
				if (!c) ERR_EXIT("malloc failed\n");
				merge_nv(io, a, a_size, b, b_size, c, &c_size);
				FILE *fi = fopen("nvmerged", "wb");
				if (!fi) ERR_EXIT("fopen failed\n");
				if (fseek(fi, 0, SEEK_SET) != 0) ERR_EXIT("fseek failed\n");
				if (fwrite(c, 1, c_size, fi) != c_size) ERR_EXIT("fwrite failed\n");
				fclose(fi);
				load_nv_partition(io, gPartInfo.name, "nvmerged", 4096);
				free(a); free(b); free(c);
			}
			free(io->nvid_list);
			io->nvid_list = NULL;
			argc -= 3; argv += 3;

		}
		else if (!strcmp(str2[1], "mergenv-cfg")) {
			if (argcount <= 3) { DBG_LOG("mergenv-cfg cfg new_nv\n"); argc = 1; continue; }
			get_partition_info(io, "nr_fixnv1", 1);
			if (!gPartInfo.size) get_partition_info(io, "l_fixnv1", 1);
			if (!gPartInfo.size) { DBG_LOG("part not exist\n");  argc -= 3; argv += 3; continue; }
			dump_partition(io, gPartInfo.name, 0, gPartInfo.size, "nvbak", blk_size ? blk_size : DEFAULT_BLK_SIZE);
			if (get_nvlist_cfg(io, str2[2])) {
				size_t a_size = 0, b_size = 0, c_size = 0;
				uint8_t *a = loadfile("nvbak", &a_size, 0);
				uint8_t *b = loadfile(str2[3], &b_size, 0);
				uint8_t *c = calloc(a_size + b_size, 1);
				if (!c) ERR_EXIT("malloc failed\n");
				merge_nv(io, a, a_size, b, b_size, c, &c_size);
				FILE *fi = fopen("nvmerged", "wb");
				if (!fi) ERR_EXIT("fopen failed\n");
				if (fseek(fi, 0, SEEK_SET) != 0) ERR_EXIT("fseek failed\n");
				if (fwrite(c, 1, c_size, fi) != c_size) ERR_EXIT("fwrite failed\n");
				fclose(fi);
				load_nv_partition(io, gPartInfo.name, "nvmerged", 4096);
				free(a); free(b); free(c);
			}
			free(io->nvid_list);
			io->nvid_list = NULL;
			argc -= 3; argv += 3;

		}
		else if (!strcmp(str2[1], "mergenv-xml-ex")) {
			if (argcount <= 4) { DBG_LOG("mergenv-xml-ex xml old_nv new_nv\n"); argc = 1; continue; }
			if (get_nvlist_xml(io, str2[2])) {
				size_t a_size = 0, b_size = 0, c_size = 0;
				uint8_t *a = loadfile(str2[3], &a_size, 0);
				uint8_t *b = loadfile(str2[4], &b_size, 0);
				uint8_t *c = calloc(a_size + b_size, 1);
				if (!c) ERR_EXIT("malloc failed\n");
				merge_nv(io, a, a_size, b, b_size, c, &c_size);
				FILE *fi = fopen("nvmerged", "wb");
				if (!fi) ERR_EXIT("fopen failed\n");
				if (fseek(fi, 0, SEEK_SET) != 0) ERR_EXIT("fseek failed\n");
				if (fwrite(c, 1, c_size, fi) != c_size) ERR_EXIT("fwrite failed\n");
				fclose(fi);
				free(a); free(b); free(c);
			}
			free(io->nvid_list);
			io->nvid_list = NULL;
			argc -= 4; argv += 4;

		}
		else if (!strcmp(str2[1], "mergenv-cfg-ex")) {
			if (argcount <= 4) { DBG_LOG("mergenv-cfg-ex cfg old_nv new_nv\n"); argc = 1; continue; }
			if (get_nvlist_cfg(io, str2[2])) {
				size_t a_size = 0, b_size = 0, c_size = 0;
				uint8_t *a = loadfile(str2[3], &a_size, 0);
				uint8_t *b = loadfile(str2[4], &b_size, 0);
				uint8_t *c = calloc(a_size + b_size, 1);
				if (!c) ERR_EXIT("malloc failed\n");
				merge_nv(io, a, a_size, b, b_size, c, &c_size);
				FILE *fi = fopen("nvmerged", "wb");
				if (!fi) ERR_EXIT("fopen failed\n");
				if (fseek(fi, 0, SEEK_SET) != 0) ERR_EXIT("fseek failed\n");
				if (fwrite(c, 1, c_size, fi) != c_size) ERR_EXIT("fwrite failed\n");
				fclose(fi);
				free(a); free(b); free(c);
			}
			free(io->nvid_list);
			io->nvid_list = NULL;
			argc -= 4; argv += 4;

		}
		else if (!strcmp(str2[1], "reboot-recovery")) {
			if (!fdl1_loaded) {
				DBG_LOG("FDL NOT READY\n");
				argc -= 1; argv += 1;
				continue;
			}
			char *miscbuf = calloc(0x800, 1);
			if (!miscbuf) ERR_EXIT("malloc failed\n");
			strcpy(miscbuf, "boot-recovery");
			w_mem_to_part_offset(io, "misc", 0, (uint8_t *)miscbuf, 0x800, 0x1000);
			free(miscbuf);
			encode_msg_nocpy(io, BSL_CMD_NORMAL_RESET, 0);
			if (!send_and_check(io)) break;

		}
		else if (!strcmp(str2[1], "reboot-fastboot")) {
			if (!fdl1_loaded) {
				DBG_LOG("FDL NOT READY\n");
				argc -= 1; argv += 1;
				continue;
			}
			char *miscbuf = calloc(0x800, 1);
			if (!miscbuf) ERR_EXIT("malloc failed\n");
			strcpy(miscbuf, "boot-recovery");
			strcpy(miscbuf + 0x40, "recovery\n--fastboot\n");
			w_mem_to_part_offset(io, "misc", 0, (uint8_t *)miscbuf, 0x800, 0x1000);
			free(miscbuf);
			encode_msg_nocpy(io, BSL_CMD_NORMAL_RESET, 0);
			if (!send_and_check(io)) break;

		}
		else if (!strcmp(str2[1], "reset") || !strncmp(str2[1], "reboot", 6)) {
			if (!fdl1_loaded) {
				DBG_LOG("FDL NOT READY\n");
				argc -= 1; argv += 1;
				continue;
			}
			encode_msg_nocpy(io, BSL_CMD_NORMAL_RESET, 0);
			if (!send_and_check(io)) break;

		}
		else if (!strcmp(str2[1], "poweroff")) {
			if (!fdl1_loaded) {
				DBG_LOG("FDL NOT READY\n");
				argc -= 1; argv += 1;
				continue;
			}
			encode_msg_nocpy(io, BSL_CMD_POWER_OFF, 0);
			if (!send_and_check(io)) break;

		}
		else if (!strcmp(str2[1], "verbose")) {
			if (argcount <= 2) { DBG_LOG("verbose {0,1,2}\n"); argc = 1; continue; }
			io->verbose = atoi(str2[2]);
			argc -= 2; argv += 2;

		}
		else if (strlen(str2[1])) {
			print_help();
			argc = 1;
		}
		if (in_quote != -1)
			for (i = 1; i < argcount; i++)
				free(str2[i]);
		free(str2);
		if (m_bOpened == -1) {
			DBG_LOG("[main] device removed, exiting...\n");
			break;
		}
	}
	spdio_free(io);
	return 0;
}
