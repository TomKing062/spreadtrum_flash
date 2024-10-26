## Spreadtrum firmware dumper

### [Download prebuilt program (windows)](https://github.com/TomKing062/spreadtrum_flash/releases)

### [Original info](https://github.com/ilyakurdyukov/spreadtrum_flash)

### Modification info

1. **can work with Official SPRD U2S Diag Driver**

2. **after send FDL2(uboot), you need `exec` before using any fdl2 related command**

3. (brom stage: set BEFORE send fdl1 by `exec_addr 0x1234` ) overwrite an addr in stack AFTER sending fdl1 (to skip sign check of fdl1 in brom)

4. (win sprd driver only) (brom stage or FDL2 stage) set baudrate by `baudrate rate`  

   according to researchdown，supported baudrates are 57600,115200,230400,460800,921600,1000000,2000000,3250000,4000000

   while in littlekernel code, only 115200, 230400, 460800, 921600 are listed (maybe they are internal values in lk, not for usb transfer)

5. interactive mode

6. (on emmc/ufs) auto detect sector size when reading partition list

7. (on nand) support read ubi part and calculate size according to nand 4th id, use `nand_id id` to set id, then use `read_part part_name 0 ubi40m part.img` to read

8. support write_part fixnv (this is dangerous, make sure just flash own backups, flash nvitem from official pack/other backups LEAD to lost calibration parameters)

9. change savepath by `path folder`

10. `r partname`/`w partname file`/`e partname`

    `r all` to make full backup (without blackbox, cache, userdata)

    `r all_lite` to make backup (without  inactive slot partitions, blackbox, cache, userdata)

    `r` only support emmc/ufs, not support nand(except `ubipac`), `r` will also calculate part size automatically

    r/w/e/read_part/write_part/erase_part support use partid instead of partname when partition table is available

    r/w/e/read_part/write_part/read_parts/write_parts support detect slot_a/_b

11. make custom backup by `read_parts part.xml`(userdata will be skipped by read_parts),

    when xml name starts with ubi, ubi size will be used.

    restore backup by `write_parts folder` (don't try `write_parts .`)

12. (win only)support device detect (speedup connection speed, and auto exit when device disconnected)

13. android 10(+): enable dm-verity by `verity 1`, disable dm-verity by `verity 0`
