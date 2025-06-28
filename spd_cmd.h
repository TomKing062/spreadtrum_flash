
#define HDLC_HEADER 0x7e
#define HDLC_ESCAPE 0x7d
#define FDL1_DUMP_MEM 0
#define DEFAULT_NAND_ID 0x15
#define DEFAULT_BLK_SIZE 0x1000

/*

SC6531EFM.xml (SC6531E):
 FDL1 = 0x40004000
 FDL = 0x14000000

NOR_FLASH_SC6530.xml (SC6531DA):
 FDL = 0x34000000

IDs:
 BOOTLOADER = 0x80000000
 PS = 0x80000003
 NV = 0x90000001
 PHASE_CHECK = 0x90000002, 0x1000
 FLASH = 0x90000003, 0xc0000
 MMIRES = 0x90000004
 ERASE_UDISK = 0x90000005
 UDISK_IMG = 0x90000006
 DSP_CODE = 0x90000009

FDL1:
 BSL_CMD_CONNECT()
 BSL_SET_BAUDRATE(u32 baud)
 BSL_CMD_START_DATA(u32 start_addr, u32 file_size)
 BSL_CMD_MIDST_DATA(...)
 BSL_CMD_END_DATA()
 BSL_CMD_EXEC_DATA()
 unknown: bootPanic

FDL2:
 BSL_CMD_CONNECT()
 BSL_CMD_START_DATA(u32 start_addr, u32 file_size)
 BSL_CMD_MIDST_DATA(...)
 BSL_CMD_END_DATA()
 BSL_CMD_NORMAL_RESET()
 BSL_CMD_READ_FLASH(u32 addr, u32 size, u32 offset)
 BSL_REPARTITION(): nop
 BSL_ERASE_FLASH(u32 addr, u32 size)
 BSL_CMD_POWER_OFF()
 unknown: BSL_REP_INVALID_CMD, bootPanic
*/

enum {
	/* Link Control */
	BSL_CMD_CONNECT = 0x00,

	/* Data Download */
	BSL_CMD_START_DATA = 0x01, /* The start flag of the data downloading */
	BSL_CMD_MIDST_DATA = 0x02, /* The midst flag of the data downloading */
	BSL_CMD_END_DATA = 0x03, /* The end flag of the data downloading */
	BSL_CMD_EXEC_DATA = 0x04, /* Execute from a certain address */
	/* End of Data Download command */

	BSL_CMD_NORMAL_RESET = 0x05, /* Reset to normal mode */
	BSL_CMD_READ_FLASH = 0x06, /* Read flash content */ // id based nand-flash
	BSL_CMD_READ_CHIP_TYPE = 0x07, /* Read chip type */
	BSL_CMD_READ_NVITEM = 0x08, /* Lookup a nvitem in specified area */
	BSL_CMD_CHANGE_BAUD = 0x09, /* Change baudrate */
	BSL_CMD_ERASE_FLASH = 0x0A, /* Erase an area of flash */
	BSL_CMD_REPARTITION = 0x0B, /* Repartition nand flash */
	BSL_CMD_READ_FLASH_TYPE = 0x0C, /* Read flash type */ // customer
	BSL_CMD_READ_FLASH_INFO = 0x0D, /* Read flash infomation */
	BSL_CMD_READ_SECTOR_SIZE = 0x0F, /* Read Nor flash sector size */
	BSL_CMD_READ_START = 0x10, /* Read flash start */
	BSL_CMD_READ_MIDST = 0x11, /* Read flash midst */
	BSL_CMD_READ_END = 0x12, /* Read flash end */

	BSL_CMD_KEEP_CHARGE = 0x13, /* Keep charge */
	BSL_CMD_EXTTABLE = 0x14, /* Set ExtTable */
	BSL_CMD_READ_FLASH_UID = 0x15, /* Read flash UID */
	BSL_CMD_READ_SOFTSIM_EID = 0x16, /* Read softSIM EID */
	BSL_CMD_POWER_OFF = 0x17, /* Power Off */
	BSL_CMD_CHECK_ROOT = 0x19, /* Check Root */ // miscdata related, rerutn 0xA7 if ROOT_MAGIC matches, otherwise return 0x80
	BSL_CMD_READ_CHIP_UID = 0x1A, /* Read Chip UID */
	BSL_CMD_ENABLE_WRITE_FLASH = 0x1B, /* Enable flash */ // disable write protect, return 0x80
	BSL_CMD_ENABLE_SECUREBOOT = 0x1C, /* Enable secure boot */
	BSL_CMD_IDENTIFY_START = 0x1D, /* Identify start */
	BSL_CMD_IDENTIFY_END = 0x1E, /* Identify end */
	BSL_CMD_READ_CU_REF = 0x1F, /* Read CU ref */
	BSL_CMD_READ_REFINFO = 0x20, /* Read Ref Info */ // miscdata related
	BSL_CMD_DISABLE_TRANSCODE = 0x21, /* Use the non-escape function */
	BSL_CMD_WRITE_APR_INFO = 0x22, /* Write pac file build time to miscdata for APR */ // miscdata related
	BSL_CMD_CUST_DUMMY = 0x23, /* Customized Dummy */
	BSL_CMD_READ_RF_TRANSCEIVER_TYPE = 0x24, /* Read RF transceiver type */
	BSL_CMD_ENABLE_DEBUG_MODE = 0x25, /* Enable debug mode */ // miscdata related
	BSL_CMD_DDR_CHECK = 0x26, /* DDR check */
	BSL_CMD_SELF_REFRESH = 0x27, /* Self Refresh */
	BSL_CMD_ENABLE_RAW_DATA = 0x28, /* Enable Raw Data */
	BSL_CMD_READ_NAND_BLOCK_INFO = 0x29, /* ReadNandBlockInfo */

	BSL_CMD_SET_FIRST_MODE = 0x2A, /* Set First Mode */ // miscdata related
	BSL_CMD_SET_RANDOM_DATA = 0x2B, /* Set Random Data */ // handshake related, device send encrypted data in 0x96 packet to PC, PC send 0x2B decrypted data, device return 0x80 or 0xB9

	BSL_CMD_SET_TIME_STAMP = 0x2C, /* Set Time Stamp used for second hand memory check */ // miscdata related
	BSL_CMD_READ_PARTITION = 0x2D, /* Read partition information from phone */
	BSL_CMD_READ_VCUR_DATA = 0x2E, /* Read Vpac */ // miscdata related
	BSL_CMD_WRITE_VPAC_DATA = 0x2F, /* Write Vpac */ // miscdata related

	BSL_CMD_MIDST_RAW_START = 0x31, /* Midst Raw Start */
	BSL_CMD_FLUSH_DATA = 0x32, /* Flush Data */ // sha256 a small packet before download raw data (unused currently)
	BSL_CMD_MIDST_RAW_START2 = 0x33, /* Midst Raw Start for V2, only send once */
	BSL_CMD_ENABLE_UBOOT_LOG = 0x34, /* Enable 0xFF type uboot log */ // return 0x80
	BSL_CMD_DUMP_UBOOT_LOG = 0x35, /* request dump uboot log */

	BSL_CMD_DISABLE_SELINUX = 0x40, /* Disable Selinux */ // miscdata related

	BSL_CMD_AUTH_BEGIN = 0x41, /* Begin Auth - Ack M1 */ // handshake related
	BSL_CMD_AUTH_END = 0x42, /* End Auth - Send Secure */ // handshake related

	BSL_CMD_EMMC_CID = 0x43, /* Read EMMC_CID */

	BSL_CMD_OPEN_WATCH_DOG = 0x44, /* Open WatchDog */ // miscdata related
	BSL_CMD_CLOSE_WATCH_DOG = 0x45, /* Close WatchDog */ // miscdata related
	BSL_CMD_POWEROFF_NOKEY = 0x46, /* no key to dl */
	BSL_CMD_WRITE_EFUSE = 0x47, /* Write efuse */
	BSL_CMD_READ_PARTITION_VALUE = 0x48, /* Read Partition Value */
	BSL_CMD_WRITE_PARTITION_VALUE = 0x49, /* Write Partition Value */
	BSL_CMD_WRITE_DOWNLOAD_TIMESTAMP = 0x50, /* Write Download Timestamp */
	BSL_CMD_PARTITION_SIGNATURE = 0x51, /* Partition Signature */

	BSL_CMD_SEND_FLAG = 0xCC, /* SendFlag before Reset */

	BSL_CMD_CHECK_BAUD = 0x7E, /* CheckBaud command, for internal use */
	BSL_CMD_END_PROCESS = 0x7F, /* End flash process */

	BSL_REP_ACK = 0x80, /* The operation acknowledge */
	BSL_REP_VER = 0x81,

	/* the operation not acknowledge */
	/* system */
	BSL_REP_INVALID_CMD = 0x82,
	BSL_REP_UNKNOW_CMD = 0x83,
	BSL_REP_OPERATION_FAILED = 0x84,

	/* Link Control */
	BSL_REP_NOT_SUPPORT_BAUDRATE = 0x85,

	/* Data Download */
	BSL_REP_DOWN_NOT_START = 0x86,
	BSL_REP_DOWN_MULTI_START = 0x87,
	BSL_REP_DOWN_EARLY_END = 0x88,
	BSL_REP_DOWN_DEST_ERROR = 0x89,
	BSL_REP_DOWN_SIZE_ERROR = 0x8A,
	BSL_REP_VERIFY_ERROR = 0x8B,
	BSL_REP_NOT_VERIFY = 0x8C,

	/* Phone Internal Error */
	BSL_PHONE_NOT_ENOUGH_MEMORY = 0x8D,
	BSL_PHONE_WAIT_INPUT_TIMEOUT = 0x8E,

	/* Phone Internal return value */
	BSL_PHONE_SUCCEED = 0x8F,
	BSL_PHONE_VALID_BAUDRATE = 0x90,
	BSL_PHONE_REPEAT_CONTINUE = 0x91,
	BSL_PHONE_REPEAT_BREAK = 0x92,

	/* End of the Command can be transmited by phone */
	BSL_REP_READ_FLASH = 0x93,
	BSL_REP_READ_CHIP_TYPE = 0x94,
	BSL_REP_READ_NVITEM = 0x95,

	BSL_REP_INCOMPATIBLE_PARTITION = 0x96,
	BSL_REP_UNKNOWN_DEVICE = 0x97,
	BSL_REP_INVALID_DEVICE_SIZE = 0x98,
	BSL_REP_ILLEGAL_SDRAM = 0x99,
	BSL_WRONG_SDRAM_PARAMETER = 0x9A,
	BSL_REP_READ_FLASH_INFO = 0x9B,
	BSL_REP_READ_SECTOR_SIZE = 0x9C,
	BSL_REP_READ_FLASH_TYPE = 0x9D,
	BSL_REP_READ_FLASH_UID = 0x9E,
	BSL_REP_READ_SOFTSIM_EID = 0x9F,

	/* information returned from FDL when downloading fixed NV */
	BSL_ERROR_CHECKSUM = 0xA0,
	BSL_CHECKSUM_DIFF = 0xA1,
	BSL_WRITE_ERROR = 0xA2,
	BSL_CHIPID_NOT_MATCH = 0xA3,
	BSL_FLASH_CFG_ERROR = 0xA4,
	BSL_REP_DOWN_STL_SIZE_ERROR = 0xA5,
	BSL_REP_PHONE_IS_ROOTED = 0xA7, /* Phone has been rooted */
	BSL_REP_SEC_VERIFY_ERROR = 0xAA, /* Security data verify error */
	BSL_REP_READ_CHIP_UID = 0xAB, /* Received Chip UID */
	BSL_REP_NOT_ENABLE_WRITE_FLASH = 0xAC, /* Not enable to write flash */
	BSL_REP_ENABLE_SECUREBOOT_ERROR = 0xAD, /* Enable secure boot fail */
	BSL_REP_IDENTIFY_START = 0xAE, /* Identify start */
	BSL_REP_IDENTIFY_END = 0xAF, /* Identify end */
	BSL_REP_READ_CU_REF = 0xB0, /* Report CU ref */
	BSL_REP_READ_REFINFO = 0xB1, /* Read Ref Info */
	BSL_REP_CUST_DUMMY = 0xB2, /* Response Customized Dummy */
	BSL_REP_FLASH_WRITTEN_PROTECTION = 0xB3, /* Flash written protection */
	BSL_REP_FLASH_INITIALIZING_FAIL = 0xB4, /* Flash initializing failed */
	BSL_REP_RF_TRANSCEIVER_TYPE = 0xB5, /* RF transceiver type */
	BSL_REP_DDR_CHECK_ERROR = 0xB6, /* DDR Check error */
	BSL_REP_SELF_REFRESH_ERROR = 0xB7, /* Self Refresh error */
	BSL_REP_READ_NAND_BLOCK_INFO = 0xB8, /* Read Nand Block Info rep */
	BSL_REP_RANDOM_DATA_ERROR = 0xB9, /* Set Random Data rep */
	BSL_REP_READ_PARTITION = 0xBA, /* Read partition infor from phone */
	BSL_REP_DUMP_UBOOT_LOG = 0xBB, /* Dump uboot log data */
	BSL_REP_READ_VCUR_DATA = 0xBC, /* Read Vpac from device */
	BSL_REP_AUTH_M1_DATA = 0xBD, /* Auth Data from Device */
	BSL_REP_READ_PARTITION_VALUE = 0xBE, /* Read Partition Value */
	BSL_REP_UNSUPPORT_PARTITION = 0xBF, /* Partition is not supported to Read or Write */
	BSL_REP_EMMC_CID_DATA = 0xC0, /* Read EMMC CID From Device */

	BSL_REP_MAGIC_ERROR = 0xD0,
	BSL_REP_REPARTITION_ERROR = 0xD1,
	BSL_REP_READ_FLASH_ERROR = 0xD2,
	BSL_REP_MALLOC_ERROR = 0xD3,

	BSL_REP_UNSUPPORTED_COMMAND = 0xFE, /* Software has not supported this feature */
	BSL_REP_LOG = 0xFF /* FDL can output some log info use this type */
};
