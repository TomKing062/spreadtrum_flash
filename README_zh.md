## Spreadtrum firmware dumper

使用官方SPRD U2S Diag驱动程序或LibUSB驱动程序。


### [Windows预编译版本下载](https://nightly.link/TomKing062/action_spd_dump_it/workflows/build/main)

### [Linux预编译版本下载](https://nightly.link/TomKing062/action_spd_dump_it/workflows/build-musl/main)

### [原作者(ilyakurdyukov)版本的说明信息](https://github.com/ilyakurdyukov/spreadtrum_flash)

### 使用方法

```
spd_dump [选项] [指令] [退出指令]
```

#### 示例

**单行模式**

```
spd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec path savepath r all reset
```

**交互模式**

```
spd_dump --wait 300 fdl /path/to/fdl1 fdl1_addr fdl /path/to/fdl2 fdl2_addr exec
```

成功后应提示 `FDL2>`

#### 选项

- `--wait <秒数>`

  指定等待设备连接的时间。

- `--stage <数字>|-r|--reconnect`

  尝试重新连接在brom/fdl1/fdl2阶段的设备。数字输入多少无所谓（甚至非数字也行）。

  处于brom/fdl1阶段的设备可以无限次重新连接，但在fdl2阶段只能重新连接一次

- `--verbose <等级>`

  设置屏幕日志的详细程度（支持0、1或2，不影响文件日志）。

- `--kick`

  使用 `boot_diag->cali_diag->dl_diag` 途径连接设备。

  boot_diag是在设备关机直接上电出现的u2s端口，其中cali_diag依赖原厂或少数经过定制的第三方recovery

- `--kickto <模式>`

  使用`boot_diag->custom_diag` 途径连接设备。支持的模式为0-127。

  (模式0为ums9621平台的新版`--kickto 2`, 模式 1 = cali_diag, 模式 2 = dl_diag; 并非所有设备都支持模式 2)

- `-h|--help|help`
  显示使用帮助。

#### 运行时命令

- `verbose level`

  设置屏幕日志的详细程度（支持0、1或2，不影响文件日志）。

- `timeout <毫秒>`

  设置读写等待的超时时间（毫秒）

- `baudrate [波特率]`(仅限Windows SPRD驱动程序和brom/fdl2阶段)

  支持的波特率为57600、115200、230400、460800、921600、1000000、2000000、3250000和4000000。

  在u-boot/littlekernel源代码中，只列出了115200、230400、460800和921600。


- `exec_addr [addr]`（仅限brom阶段）
  将 `customexec_no_verify_addr.bin` 发送到指定的内存地址，以绕过brom对 `splloader/fdl1` 的签名验证。

  用于CVE-2022-38694。

- `fdl FILE addr`

  将文件（`splloader`,`fdl1`,`fdl2`,`sml`,`trustos`,`teecfg`）发送到指定的内存地址。

- `loadexec FILE(addr_in_name)`

  以文件名中的地址作为exec_addr，同时在执行fdl1/spl时使用该文件作为exec_file。

- `loadfdl FILE(addr_in_name)`

  以文件名中的地址作为fdl的目标地址并发送该文件到内存。

- `exec`

  在fdl1阶段执行已发送的文件。通常与`sml`或`fdl2`（也称为uboot/lk）一起使用。

- `path [保存目录]`

  更改`r`,`read_part(s)`,`read_flash`和`read_mem`命令的保存目录。

- `nand_id [id]`

  指定nand芯片的4th id参数，该参数影响`read_part(s)`分区大小的算法，默认值为0x15。

- `rawdata {0,1,2}`（仅限fdl2阶段）
  rawdata协议用于加速`w`和`write_part`命令，当rawdata为1或2时，写入速度与blk_size无关（依赖于u-boot/lk，请勿手动修改）

- `blk_size byte`（仅限fdl2阶段）
  设置块大小，最大为65535字节。此选项用于加快`r`、`w`、`read_part(s)`和`write_part(s)`命令的速度。

- `r all|part_name|part_id`

  当分区表可用时：

    - `r all`: 全盘备份 (跳过 blackbox, cache, userdata)
    - `r all_lite`: 全盘备份（不包括非活动槽位, blackbox, cache和userdata）
    - NAND上all和all_lite不可用

  当分区表不可用时:

    - `r` 将自动计算分区大小（emmc/ufs和NAND均可）

- `read_part part_name|part_id offset size FILE`

  以给定的偏移量和大小将特定分区读取到文件中。

  （在nand上读取ubi）`read_part system 0 ubi40m system.bin`

- `read_parts partition_list_file`

  按照XML类型分区列表从设备读取分区（如果文件名以“ubi”开头，则将使用NAND ID计算大小）

- `w|write_part part_name|part_id FILE`

  将指定的文件写入分区。

- `write_parts|write_parts_a|write_parts_b save_location`

  写入指定文件夹下所有文件到设备分区，通常由`read_parts`得到。

- `w_force part_name|part_id FILE`

  强制写入分区文件（绕过大小/名称检查）。

- `g_w_force {0,1,2}`

  设置全局强制写入标志。
  0 = 不开启
  1 = 非 AB 后缀分区正常写入，AB 槽位分区强制写入
  2 = 所有分区强制

- `wof part_name offset FILE`

  把文件写入分区偏移位置。

- `wov part_name offset VALUE`

  把数值写入分区偏移位置（最大值为0xFFFFFFFF）。

- `e|erase_part part_name|part_id`

  擦除指定分区。

- `erase_all`

  擦除全部分区。

- `partition_list FILE`

  读取emmc/ufs上的分区列表，并非所有fdl2都支持此命令。

- `repartition partition_list_xml`

  根据XML类型分区列表重新分区。

- `p|print`

  打印分区列表。

- `size_part|part_size part_name`

  获取分区大小。

- `check_part part_name`

  检测分区是否存在。

- `verity {0,1}`

  在Android 10(+)上禁用或启用`dm-verity`。

- `set_active {a,b}`

  设置VAB设备上的活动槽位。

- `firstmode mode_id`

  设置重启后设备将进入的模式。

- `skip_confirm {0,1}`

  设置是否跳过确认提示。

- `keep_charge {0,1}`

  设置在 FDL1 初始化时是否发送 keep-charge 指令。

- `dis_avb`

  通过 CVE 禁用 Android 验证启动（AVB）。

- `dis_avb_ex sml_or_teecfg tos`

  通过修补分区镜像从外部禁用 AVB。

- `mergenv-xml xml new_nv`

  从 XML 列表合并 NV 更改并写回设备。

- `mergenv-cfg cfg new_nv`

  从 CFG 列表合并 NV 更改并写回设备。

- `mergenv-xml-ex xml old_nv new_nv`

  在外部对两个文件根据 XML 列表合并 NV（不写入设备）。

- `mergenv-cfg-ex cfg old_nv new_nv`

  在外部对两个文件根据 CFG 列表合并 NV（不写入设备）。

#### 旧版命令

- `send|write_flash FILE addr`

  将文件发送到闪存的指定地址。

- `read_flash addr offset size FILE`

  读取闪存区域到文件。

- `erase_flash addr size`

  擦除闪存区域。

- `read_mem addr size FILE`

  读取设备内存到文件。

- `read_pactime`

  读取并打印数据包时序信息。

- `chip_uid`

  读取并打印芯片 UID。

- `disable_transcode`

  发送指令在设备端禁用 HDLC 转码。

#### 调试命令

- `sendloop addr`

  调试用：重复向递减地址发送 4 字节零。

- `sendloopadd addr`

  调试用：重复向递增地址发送零字节数据包。

- `sendcmd type file`

  以指定 type 发送原始命令（数据来自文件）。

- `sendcmdv type value`

  以指定 type 发送原始命令和 8 字节数值（最大 0xFFFFFFFF）。

- `sendcmdvl type value`

  循环发送原始命令（从 value 到 0x100000000），每次响应保存到文件。

- `sendpack file`

  发送预格式化的 7E 打包数据包。

- `rawpack file`

  发送原始文件作为数据包（自动添加 CRC 和转码）。

- `write_word addr VALUE`

  向内存地址写入 32 位数值。

- `transcode {0,1}`

  在本地启用或禁用 HDLC 转码。

- `end_data {0,1}`

  设置写入闪存时是否追加结束标记。

- `fblk_size|fbs mb`

  设置闪存块大小（兆字节）。

- `slot {0,1,2}`

  设置 A/B 槽位选择（0=自动，1=a，2=b）。

#### EXTENDED Commands - 需要特殊loader的命令

- `e_readmem addr length FILE`

  读取内存地址 `addr` 开始的 `length` 字节并保存到 `FILE`。

- `e_bl`

  发送 e_bl 指令。

- `e_rpmb_pagecount`

  查询 RPMB 页数。

- `e_rpmb_counter`

  查询 RPMB 写入计数器。

- `e_rpmb_read page_start page_count FILE`

  从 `page_start` 开始读取 RPMB 页并保存到 `FILE`。

- `e_rpmb_write page_start FILE`

  将 `FILE` 数据写入 RPMB，起始页为 `page_start`。

- `e_rpmb_read_auto`

  自动读取所有 RPMB 页到文件 `rpmb_dump`。

- `e_pwn`

  PWN trustos（绕过 modem 中的验证）。

- `e_checkpwn`

  检查设备的 trustos 是否已修改。

#### 退出指令

- `reboot-recovery`

  仅FDL2

- `reboot-fastboot`

  仅FDL2

- `reset`

  FDL2和新版FDL1

- `poweroff`

  FDL2和新版FDL1

### Android(Termux)

1. 安装[Termux-api](https://github.com/termux/termux-api/releases)并授权自启动

2. 安装依赖库和编译组件

```
pkg install termux-api libusb clang git
```

3. 拉取源代码

```
git clone https://github.com/TomKing062/spreadtrum_flash.git
cd spreadtrum_flash
```

4. 编译

```
make
```

生成可执行文件: spd_dump

5. 搜索OTG设备

```
termux-usb -l
[
"/dev/bus/usb/xxx/xxx"
]
```

6. 授权OTG设备(如果可用)

```
termux-usb -r /dev/bus/usb/xxx/xxx
```

允许访问目标设备

7. 运行 SPD_SUMP

```
termux-usb -e './spd_dump --usb-fd' /dev/bus/usb/xxx/xxx
```

