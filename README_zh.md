## Spreadtrum firmware dumper

使用官方SPRD U2S Diag驱动程序或LibUSB驱动程序。

### [下载预构建程序（Windows）](https://github.com/TomKing062/spreadtrum_flash/releases)

### [原始信息](https://github.com/ilyakurdyukov/spreadtrum_flash)

### 使用方法

```
spd_dump [选项] [指令] [退出指令]
```

#### 示例

**单线模式**

```
spd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec path savepath r all_lite reset
```

**交互模式**

```
spd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec
```

成功后应提示 `FDL2>`

#### 选项

- `--wait <秒数>`  
  指定等待设备连接的时间。

- `--stage <数字>`  
  尝试在brom/fdl1/fdl2阶段重新连接设备。任何≥0的数字都有同样的行为。

- `--verbose <等级>`  
  设置输出的详细程度（支持0、1或2）。

- `--kick`  
  使用阶段 `boot_diag->cali_diag->dl_diag` 连接设备。
  
  指在设备关机上电后开启的boot_diag，此功能依赖RECOVERY完整！

- `--kickto <模式>`  
  使用自定义阶段`boot_diag->custom_diag` 连接设备。支持的模式为0-127。
  
  (模式 1 = cali_diag, 模式 2 = dl_diag; 并非所有设备都支持模式 2)
  
- `-h|--help|help`
  显示帮助和使用信息。

#### 运行时命令

- `verbose level`  
  设置输出的详细程度（支持0、1或2）

- `timeout <毫秒>`  
  设置命令超时时间（毫秒）

- `baudrate [波特率]`(仅限Windows SPRD驱动程序和brom/fdl2阶段)  
  支持的波特率为57600、115200、230400、460800、921600、1000000、2000000、3250000和4000000。

  在u-boot/littlekernel源代码中，只列出了115200、230400、460800和921600。
  
- `exec_addr [addr]`（仅限brom阶段）
将 `customexec_no_verify_addr.bin` 发送到指定的内存地址，以绕过brom对 `splloader/fdl1` 的签名验证。

  用于CVE-2022-38694。
  
- `fdl FILE addr`  
  将文件（`splloader`,`fdl1`,`fdl2`,`“sml`,`trustos`,`teecfg`）发送到指定的内存地址。

- `exec`  
  在fdl1阶段执行已发送的文件。通常与`sml`或`fdl2`（也称为uboot/lk）一起使用。

- `path [保存目录]`  
  更改`r`,`read_part`,`read_flash`和`read_mem`等命令的保存目录。

- `nand_id [id]`  
  指定影响`read_part`大小计算的第四个NAND ID，默认值为0x15。

- `rawdata {0,2}`（仅限fdl2阶段）
启用rawdata协议以加速`w`和`write_part`命令。

（注意：目前不支持rawdata=1）
  
- `blk_size byte`（仅限fdl2阶段）
  设置块大小，最大为65535字节。当禁用rawdata协议时，此选项有助于加快`w`和`write_part（s）`命令的速度。

- `r all|part_name|part_id`  
  当分区表可用时::
  
    - `r all`: 完全备份 (不包含 blackbox, cache, userdata)
    - `r all_lite`: 备份不包括非活动插槽分区,blackbox,cache和userdata
  
  当分区表不可用时:
    - `r` 将自动计算部件大小（支持emmc/ufs上的所有分区，仅支持NAND上的`ubipac`）

- `read_part part_name|part_id offset size FILE`  
  以给定的偏移量和大小将特定分区读取到文件中。

  （在nand上读取ubi）`read_part system 0 ubi40m system.bin`
  
- `read_parts partition_list_file`  
  从列表文件读取分区（如果文件名以“ubi”开头，则将使用NAND ID计算大小）

- `w|write_part part_name|part_id FILE`  
  将指定的文件写入分区。

- `write_parts save_location`  
  写入由`read_parts`转储的所有分区。

- `e|erase_part part_name|part_id`  
  擦除指定分区。

- `partition_list FILE`  
  读取emmc/ufs上的分区列表，并非所有fdl2都支持此命令。

- `repartition partition_list_xml`  
  根据XML类型分区列表重新分区。

- `p|print`
  
  打印分区列表
  
- `verity {0,1}`  
  在Android 10(+)上启用或禁用`dm-verity`

#### 退出指令

主要适用于FDL2阶段；只有新的FDL1支持退出

- `reset`

- `poweroff`

### Android(Termux)

1.安装Termux-api并授权自启动
### [Termux-api](https://github.com/termux/termux-api/releases)

2.安装依赖库和编译组件

```
pkg install termux-api libusb clang git
```

3.拉取源代码

```
git clone https://github.com/TomKing062/spreadtrum_flash.git
cd spreadtrum_flash
```

4.编译

```
make
```
生成可执行文件:spd_dump


5.搜索OTG设备

```
termux-usb -l
[
"/dev/bus/usb/xxx/xxx"
]
```

6.授权OTG设备(如果可用)

```
termux-usb -r /dev/bus/usb/xxx/xxx
```
允许访问目标设备


7.运行 SPD_SUMP

```
termux-usb -e './spd_dump --usb-fd' /dev/bus/usb/xxx/xxx
```
