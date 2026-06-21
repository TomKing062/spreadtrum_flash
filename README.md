## Spreadtrum firmware dumper

### [中文文档](https://github.com/TomKing062/spreadtrum_flash/blob/main/README_zh.md)

work with Official SPRD U2S Diag Driver or LibUSB Driver.


### [Prebuilt Program for Windows](https://nightly.link/TomKing062/action_spd_dump_it/workflows/build/main)

### [Prebuilt Program for Linux](https://nightly.link/TomKing062/action_spd_dump_it/workflows/build-musl/main)

### [Original information of ilyakurdyukov version](https://github.com/ilyakurdyukov/spreadtrum_flash)

### Usage

```
spd_dump [OPTIONS] [COMMANDS] [EXIT COMMANDS]
```

#### Examples

**One-line mode**

```
spd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec path savepath r all reset
```

**Interactive mode**

```
spd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec
```

Then the prompt should display `FDL2>`.

#### Options

- `--wait <seconds>`

  Specifies the time to wait for the device to connect.

- `--stage <number>|-r|--reconnect`

  Try to reconnect device in brom/fdl1/fdl2 stage. Any number behaves the same way.

  (unstable, a device in brom/fdl1 stage can be reconnected infinite times, but only once in fdl2 stage)

- `--verbose <level>`

  Sets the verbosity level of the output (supports 0, 1, or 2).

- `--kick`

  Connects the device using the route `boot_diag -> cali_diag -> dl_diag`.

- `--kickto <mode>`

  Connects the device using a custom route `boot_diag -> custom_diag`. Supported modes are 0-127.

  (mode 0 = `--kickto 2` on ums9621, mode 1 = cali_diag, mode 2 = dl_diag; not all devices support mode 2).

- `-h|--help|help`

  Show help and usage information.

#### Runtime Commands

- `verbose level`

  Sets the verbosity level of the output (supports 0, 1, or 2).

- `timeout ms`

  Sets the command timeout (during read and write) in milliseconds.

- `baudrate [rate]` (Windows SPRD driver only, and brom/fdl2 stage only)

  Supported baudrates are 57600, 115200, 230400, 460800, 921600, 1000000, 2000000, 3250000, and 4000000.

  While in u-boot/littlekernel source code, only 115200, 230400, 460800, and 921600 are listed.

- `exec_addr [addr]` (brom stage only)

  Sends `custom_exec_no_verify_addr.bin` to the specified memory address to bypass the signature verification by brom for `splloader/fdl1`.

  Used for CVE-2022-38694.

- `fdl FILE addr`

  Sends a file (`splloader`, `fdl1`, `fdl2`, `sml`, `trustos`, `teecfg`) to the specified memory address.

- `loadexec FILE(addr_in_name)`

  Set exec_addr with the address encoded in filename and save exec_file path.

- `loadfdl FILE(addr_in_name)`

  Load FDL file to the address encoded in filename..

- `exec`

  Executes a sent file in the fdl1 stage. Typically used with `sml` or `fdl2` (also known as uboot/lk).

- `path [save_location]`

  Changes the save directory for commands like `r`, `read_part(s)`, `read_flash`, and `read_mem`.

- `nand_id [id]`

  Specifies the 4th NAND ID, affecting `read_part(s)` size calculation, default value is 0x15.

- `rawdata {0,1,2}` (fdl2 stage only)

  Rawdata protocol helps speed up `w` and `write_part(s)` commands, when rawdata > 0, `blk_size` will not effect write speed. (rawdata relays on u-boot/lk, so don't set it manually.)

- `blk_size byte` (fdl2 stage only)

  Sets the block size, with a maximum of 65535 bytes. This option helps speed up `r`, `w`,`read_part(s)` and `write_part(s)` commands.

- `r all|part_name|part_id`

  When the partition table is available:

    - `r all`: full backup (excludes blackbox, cache, userdata)
    - `r all_lite`: full backup (excludes inactive slot partitions, blackbox, cache, and userdata)
    - all/all_lite is not usable on NAND

  When the partition table is unavailable:

    - `r` will auto-calculate part size (supports emmc/ufs and NAND).

- `read_part part_name|part_id offset size FILE`

  Reads a specific partition to a file at the given offset and size.

  (read ubi on nand) `read_part system 0 ubi40m system.bin`

- `read_parts partition_list_file`

  Reads partitions from a list file (If the file name starts with "ubi", the size will be calculated using the NAND ID).

- `w|write_part part_name|part_id FILE`

  Writes the specified file to a partition.

- `write_parts|write_parts_a|write_parts_b save_location`

  Writes all partitions dumped by `read_parts`.

- `w_force part_name|part_id FILE`

  Force-writes a partition file bypassing size/name checks.

- `g_w_force {0,1,2}`

  Sets the global write-force flag.
  0 = disable force write feature
  1 = non-AB partitions written normally, AB-slot partitions force-written
  2 = Force all partitions

- `wof part_name offset FILE`

  Writes the specified file to a partition at the given offset.

- `wov part_name offset VALUE`

  Writes the specified value (max is 0xFFFFFFFF) to a partition at the given offset.

- `e|erase_part part_name|part_id`

  Erases the specified partition.

- `erase_all`

  Erases all partitions. Use with caution!

- `partition_list FILE`

  Read the partition list on emmc/ufs, not all fdl2 supports this command.

- `repartition partition_list_xml`

  Repartitions based on partition list XML.

- `p|print`

  Prints partition_list.

- `size_part|part_size part_name`

  Displays the size of the specified partition.

- `check_part part_name`

  Checks if the specified partition exists.

- `verity {0,1}`

  Disable or enable `dm-verity` on android 10(+).

- `set_active {a,b}`

  Sets the active slot on VAB devices.

- `firstmode mode_id`

  Sets the mode the device will enter after reboot.

- `skip_confirm {0,1}`

  Sets whether to skip confirmation prompts.

- `keep_charge {0,1}`

  Sets whether to send keep-charge command during FDL1 init.

- `dis_avb`

  Disables Android Verified Boot (AVB) via CVE.

- `dis_avb_ex sml_or_teecfg tos`

  Disables AVB externally by patching partition images.

- `mergenv-xml xml new_nv`

  Merges NV changes from XML list and writes back to device.

- `mergenv-cfg cfg new_nv`

  Merges NV changes from CFG list and writes back to device.

- `mergenv-xml-ex xml old_nv new_nv`

  Merges NV from XML list on two files externally (no device write).

- `mergenv-cfg-ex cfg old_nv new_nv`

  Merges NV from CFG list on two files externally (no device write).

#### Legacy Commands

- `send|write_flash FILE addr`

  Sends a file to flash at the given address.

- `read_flash addr offset size FILE`

  Reads a region of flash memory to a file.

- `erase_flash addr size`

  Erases a region of flash.

- `read_mem addr size FILE`

  Reads device memory to a file.

- `read_pactime`

  Reads and prints packet timing information.

- `chip_uid`

  Reads and prints the chip UID.

#### Debug Commands

- `sendloop addr`

  Debug: repeatedly sends 4 zero bytes to decrementing addresses.

- `sendloopadd addr`

  Debug: repeatedly sends zero-byte packets to incrementing addresses.

- `sendcmd type file`

  Sends raw command with given type from file.

- `sendcmdv type value`

  Sends raw command with given type and 8-byte value (max 0xFFFFFFFF).

- `sendcmdvl type value`

  Sends looped raw command from value to 0x100000000, saves each response.

- `sendpack file`

  Sends a pre-formatted 7E-packed packet from file.

- `rawpack file`

  Sends raw file as a packet (CRC and transcode added automatically).

- `write_word addr VALUE`

  Writes a 32-bit value to a memory address.

- `disable_transcode`

  Sends command to disable HDLC transcoding on the device.

- `transcode {0,1}`

  Locally enables or disables HDLC transcoding.

- `end_data {0,1}`

  Sets whether to append end-of-data markers when writing to flash.

- `fblk_size|fbs mb`

  Sets the flash block size in megabytes.

- `slot {0,1,2}`

  Sets the A/B slot selection (0=auto, 1=a, 2=b).

#### EXTENDED Commands

- `e_readmem addr length FILE`

  Reads memory at `addr` for `length` bytes and saves to `FILE`.

- `e_bl`

  Unlock bootloader.

- `e_rpmb_pagecount`

  Queries RPMB page count.

- `e_rpmb_counter`

  Queries RPMB write counter.

- `e_rpmb_read page_start page_count FILE`

  Reads RPMB pages starting at `page_start` and saves to `FILE`.

- `e_rpmb_read_auto`

  Automatically reads all RPMB pages to file `rpmb_dump`.

- `e_rpmb_write page_start FILE`

  Writes `FILE` data to RPMB starting at `page_start`.

- `e_efuse_read block_id`

  Reads eFuse block at given index, returns 4 bytes.

- `e_pwn`

  PWN trustos (bypass verification in modem).

- `e_checkpwn`

  Checks if device's trustos is pwned.

#### Exit Commands

- `reboot-recovery`

  FDL2 only

- `reboot-fastboot`

  FDL2 only

- `reset`

  FDL2 and new FDL1

- `poweroff`

  FDL2 and new FDL1

### Android(Termux)

1. Install [Termux-api](https://github.com/termux/termux-api/releases) and authorize self startup

2. Install dependency libraries and compile components

```
pkg install termux-api libusb clang git
```

3. Pull source code

```
git clone https://github.com/TomKing062/spreadtrum_flash.git
cd spreadtrum_flash
```

4. Build

```
make
```

Produce executable files: spd_dump

5. Search OTG Device

```
termux-usb -l
[
"/dev/bus/usb/xxx/xxx"
]
```

6. Authorize OTG devices

```
termux-usb -r /dev/bus/usb/xxx/xxx
```

Allow access to the target device

7. Run SPD_SUMP

```
termux-usb -e './spd_dump --usb-fd' /dev/bus/usb/xxx/xxx
```

