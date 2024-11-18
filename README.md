## Spreadtrum firmware dumper

work with Official SPRD U2S Diag Driver or LibUSB Driver.

### [Download prebuilt program (windows)](https://github.com/TomKing062/spreadtrum_flash/releases)

### [Original info](https://github.com/ilyakurdyukov/spreadtrum_flash)

### Usage

```
spd_dump [OPTIONS] [COMMANDS] [EXIT COMMANDS]
```

#### Examples

**One-line mode**

```
spd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec path savepath r all_lite reset
```

**Interactive mode**

```
spd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec
```

Then the prompt should display `FDL2>`.

#### Options

- `--wait <seconds>`  
  Specifies the time to wait for the device to connect.

- `--stage <number>`  
  Try to reconnect device in brom/fdl1/fdl2 stage. Any number ≥ 0 behaves the same way.

- `--verbose <level>`  
  Sets the verbosity level of the output (supports 0, 1, or 2).

- `--kick`  
  Connects the device using the route `boot_diag -> cali_diag -> dl_diag`.

- `--kickto <mode>`  
  Connects the device using a custom route `boot_diag -> custom_diag`. Supported modes are 0-127.
  
  (mode 1 = cali_diag, mode 2 = dl_diag; not all devices support mode 2).
  
- `-h|--help|help`
  Show help and usage information.

#### Runtime Commands

- `verbose level`  
  Sets the verbosity level of the output (supports 0, 1, or 2).

- `timeout ms`  
  Sets the command timeout in milliseconds.

- `baudrate [rate]` (Windows SPRD driver only, and brom/fdl2 stage only)  
  Supported baudrates are 57600, 115200, 230400, 460800, 921600, 1000000, 2000000, 3250000, and 4000000.

  While in u-boot/littlekernel source code, only 115200, 230400, 460800, and 921600 are listed.
  
- `exec_addr [addr]` (brom stage only)  
  Sends `custom_exec_no_verify_addr.bin` to the specified memory address to bypass the signature verification by brom for `splloader/fdl1`.

  Used for CVE-2022-38694.
  
- `fdl FILE addr`  
  Sends a file (`splloader`, `fdl1`, `fdl2`, `sml`, `trustos`, `teecfg`) to the specified memory address.

- `exec`  
  Executes a sent file in the fdl1 stage. Typically used with `sml` or `fdl2` (also known as uboot/lk).

- `path [save_location]`  
  Changes the save directory for commands like `r`, `read_part(s)`, `read_flash`, and `read_mem`.

- `nand_id [id]`  
  Specifies the 4th NAND ID, affecting `read_part(s)` size calculation, default value is 0x15.

- `rawdata {0,2}` (fdl2 stage only)  
  Enables the rawdata protocol to speed up the `w` and `write_part(s)` commands.

  (Note: rawdata = 1 is currently not supported.)
  
- `blk_size byte` (fdl2 stage only)  
  Sets the block size, with a maximum of 65535 bytes. This option helps speed up the `w` and `write_part(s)` commands when the rawdata protocol is disabled.

- `r all|part_name|part_id`  
  When the partition table is available::
  
    - `r all`: Full backup (excludes blackbox, cache, userdata)
    - `r all_lite`: Backup excluding inactive slot partitions, blackbox, cache, and userdata
  
  When the partition table is unavailable:
    - `r` will auto-calculate part size (supports all partitions on emmc/ufs and only `ubipac` on NAND).

- `read_part part_name|part_id offset size FILE`  
  Reads a specific partition to a file at the given offset and size.

  (read ubi on nand) `read_part system 0 ubi40m system.bin`
  
- `read_parts partition_list_file`  
  Reads partitions from a list file (If the file name starts with "ubi", the size will be calculated using the NAND ID).

- `w|write_part part_name|part_id FILE`  
  Writes the specified file to a partition.

- `write_parts save_location`  
  Writes all partitions dumped by `read_parts`.

- `e|erase_part part_name|part_id`  
  Erases the specified partition.

- `partition_list FILE`  
  Read the partition list on emmc/ufs, not all fdl2 supports this command.

- `repartition partition_list_xml`  
  Repartitions based on partition list XML.

- `p|print`
  
  Prints partition_list
  
- `verity {0,1}`  
  Enables or disables `dm-verity` on android 10(+).

#### Exit Commands

Applicable mainly to the FDL2 stage; only new FDL1 supports exit

- `reset`

- `poweroff`
- 
### Android(Termux)

1.Install termux API and authorize self startup

2.Install dependency libraries and compile components

```
pkg install termux-api libusb clang git
```

3.Pull source code

```
git clone https://github.com/hxzbaka/spreadtrum_flash.git
```

4.Build

```
make
```

