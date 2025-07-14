#include "common.h"
DWORD curPort = 0;
DWORD *FindPort(const char *USB_DL) {
	const GUID GUID_DEVCLASS_PORTS = { 0x4d36e978, 0xe325, 0x11ce,{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18} };
	HDEVINFO DeviceInfoSet;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD dwIndex = 0;
	DWORD count = 0;
	DWORD *ports = NULL;

	DeviceInfoSet = SetupDiGetClassDevs(&GUID_DEVCLASS_PORTS, NULL, NULL, DIGCF_PRESENT);

	if (DeviceInfoSet == INVALID_HANDLE_VALUE) {
		DBG_LOG("Failed to get device information set. Error code: %ld\n", GetLastError());
		return 0;
	}

	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	while (SetupDiEnumDeviceInfo(DeviceInfoSet, dwIndex, &DeviceInfoData)) {
		char friendlyName[MAX_PATH];
		DWORD dataType = 0;
		DWORD dataSize = sizeof(friendlyName);

		SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, &DeviceInfoData, SPDRP_FRIENDLYNAME, &dataType, (BYTE *)friendlyName, dataSize, &dataSize);
		char *result = strstr(friendlyName, USB_DL);
		if (result != NULL) {
			char portNum_str[4];
			strncpy(portNum_str, result + strlen(USB_DL) + 5, 3);
			portNum_str[3] = 0;

			DWORD portNum = strtoul(portNum_str, NULL, 0);
			DWORD *temp = (DWORD *)realloc(ports, (count + 2) * sizeof(DWORD));
			if (temp == NULL) {
				DBG_LOG("Memory allocation failed.\n");
				SetupDiDestroyDeviceInfoList(DeviceInfoSet);
				free(ports);
				ports = NULL;
				return NULL;
			}
			ports = temp;
			ports[count] = portNum;
			count++;
		}
		++dwIndex;
	}

	SetupDiDestroyDeviceInfoList(DeviceInfoSet);
	if (count > 0) ports[count] = 0;
	return ports;
}

void usleep(unsigned int us) {
	Sleep(us / 1000);
}

extern int m_bOpened;

void print_mem(FILE *f, uint8_t *buf, size_t len) {
	size_t i; int a, j, n;
	for (i = 0; i < len; i += 16) {
		n = len - i;
		if (n > 16) n = 16;
		for (j = 0; j < n; j++) fprintf(f, "%02x ", buf[i + j]);
		for (; j < 16; j++) fprintf(f, " ");
		fprintf(f, " |");
		for (j = 0; j < n; j++) {
			a = buf[i + j];
			fprintf(f, "%c", a > 0x20 && a < 0x7f ? a : '.');
		}
		fprintf(f, "|\n");
	}
}

void print_string(FILE *f, const void *src, size_t n) {
	size_t i; int a, b = 0;
	const uint8_t *buf = (const uint8_t *)src;
	fprintf(f, "\"");
	for (i = 0; i < n; i++) {
		a = buf[i]; b = 0;
		switch (a) {
		case '"': case '\\': b = a; break;
		case 0: b = '0'; break;
		case '\b': b = 'b'; break;
		case '\t': b = 't'; break;
		case '\n': b = 'n'; break;
		case '\f': b = 'f'; break;
		case '\r': b = 'r'; break;
		}
		if (b) fprintf(f, "\\%c", b);
		else if (a >= 32 && a < 127) fprintf(f, "%c", a);
		else fprintf(f, "\\x%02x", a);
	}
	fprintf(f, "\"\n");
}

char fn_partlist[40] = { 0 };
char savepath[ARGV_LEN] = { 0 };
DA_INFO_T Da_Info;
partition_t gPartInfo;

#define TEMPBUF_LENGTH 0xffff
spdio_t *spdio_init(int flags) {
	uint8_t *p; spdio_t *io;

	p = (uint8_t *)malloc(sizeof(spdio_t) + TEMPBUF_LENGTH);
	io = (spdio_t *)p;
	if (!p) ERR_EXIT("malloc failed\n");
	memset(io, 0, sizeof(spdio_t));
	p += sizeof(spdio_t);
	io->temp_buf = p;
	io->flags = flags;
	io->timeout = 1000;
	return io;
}

void spdio_free(spdio_t *io) {
	if (!io) return;
	if (io->last_decoded_packet) {
		free(io->raw_buf);
		free(io->last_decoded_packet);
	}
	PostThreadMessage(io->iThread, WM_QUIT, 0, 0);
	WaitForSingleObject(io->hThread, INFINITE);
	CloseHandle(io->hThread);
	call_DisconnectChannel(io->handle);
	if (io->m_dwRecvThreadID) DestroyRecvThread(io);
	call_Uninitialize(io->handle);
	destroyClass(io->handle);

	QueueClose(&io->raw);
	WaitForSingleObject(io->m_hEncodeThread, INFINITE);
	WaitForSingleObject(io->m_hSendRecvThread, INFINITE);
	CloseHandle(io->m_hEncodeThread);
	CloseHandle(io->m_hSendRecvThread);

	QueueDestroy(&io->raw);
	QueueDestroy(&io->encoded);
	QueueDestroy(&io->decoded);
	free(io->ptable);
	free(io);
}

int spd_transcode(uint8_t *dst, uint8_t *src, int len) {
	int i, a, n = 0;
	for (i = 0; i < len; i++) {
		a = src[i];
		if (a == HDLC_HEADER || a == HDLC_ESCAPE) {
			if (dst) dst[n] = HDLC_ESCAPE;
			n++;
			a ^= 0x20;
		}
		if (dst) dst[n] = a;
		n++;
	}
	return n;
}

int spd_transcode_max(uint8_t *src, int len, int n) {
	int i, a;
	for (i = 0; i < len; i++) {
		a = src[i];
		a = a == HDLC_HEADER || a == HDLC_ESCAPE ? 2 : 1;
		if (n < a) break;
		n -= a;
	}
	return i;
}

unsigned spd_crc16(unsigned crc, const void *src, unsigned len) {
	uint8_t *s = (uint8_t *)src; int i;
	crc &= 0xffff;
	while (len--) {
		crc ^= *s++ << 8;
		for (i = 0; i < 8; i++)
			crc = crc << 1 ^ ((0 - (crc >> 15)) & 0x11021);
	}
	return crc;
}

#define CHK_FIXZERO 1
#define CHK_ORIG 2

unsigned spd_checksum(unsigned crc, const void *src, int len, int final) {
	uint8_t *s = (uint8_t *)src;

	while (len > 1) {
		crc += s[1] << 8 | s[0]; s += 2;
		len -= 2;
	}
	if (len) crc += *s;
	if (final) {
		crc = (crc >> 16) + (crc & 0xffff);
		crc += crc >> 16;
		crc = ~crc & 0xffff;
		if (len < final)
			crc = crc >> 8 | (crc & 0xff) << 8;
	}
	return crc;
}

void encode_msg(spdio_t *io, int type, const void *data, size_t len) {
	if (len > 0xffff)
		ERR_EXIT("message too long\n");

	Packet *in = malloc(sizeof(Packet));

	if (!in) ERR_EXIT("malloc pack in encode_msg failed\n");
	in->msg_type = type;
	in->length = len;

	if (type == BSL_CMD_CHECK_BAUD) {
		in->data = malloc(len);
		if (!in->data) ERR_EXIT("malloc pack->data in encode_msg failed\n");
		memset(in->data, HDLC_HEADER, len);
		in->allow_empty_reply = 1;
		in->timeout = io->timeout;
		QueuePush(&io->encoded, in);
	}
	else {
		uint8_t *p = malloc(len + 8);
		if (!p) ERR_EXIT("malloc pack->data in encode_msg failed\n");
		in->data = p + 1;
		WRITE16_BE(p + 1, type);
		WRITE16_BE(p + 3, len);
		memcpy(p + 5, data, len);
		in->length += 4; //type and len
		in->allow_empty_reply = 0; // judge in encode_msg_bg
		QueuePush(&io->raw, in);
	}
}

void encode_msg_bg(spdio_t *io, Packet *in) {
	unsigned chk;

	if (io->flags & FLAGS_CRC16)
		chk = spd_crc16(0, in->data, in->length);
	else {
		// if (len & 1) *p++ = 0;
		chk = spd_checksum(0, in->data, in->length, CHK_FIXZERO);
	}
	WRITE16_BE(in->data + in->length, chk);
	in->length += 2;

	if (in->msg_type == BSL_CMD_READ_FLASH_INFO ||
		in->msg_type == BSL_CMD_CONNECT) {
		in->allow_empty_reply = 1;
	}

	if (io->flags & FLAGS_TRANSCODE) {
		io->cur_encoded_packet = malloc(sizeof(Packet));
		if (!io->cur_encoded_packet) ERR_EXIT("malloc cur_encoded_packet failed\n");
		io->cur_encoded_packet->data = malloc(in->length * 2 + 2);
		if (!io->cur_encoded_packet->data) ERR_EXIT("malloc cur_encoded_packet->data failed\n");
		io->cur_encoded_packet->msg_type = in->msg_type;
		io->cur_encoded_packet->allow_empty_reply = in->allow_empty_reply;
		io->cur_encoded_packet->length = spd_transcode(io->cur_encoded_packet->data + 1, in->data, in->length);
		*io->cur_encoded_packet->data = HDLC_HEADER;
		io->cur_encoded_packet->data[io->cur_encoded_packet->length + 1] = HDLC_HEADER;
		io->cur_encoded_packet->length += 2;
		free(in->data - 1);
		free(in);
	}
	else {
		io->cur_encoded_packet = in;
		*(io->cur_encoded_packet->data - 1) = HDLC_HEADER;
		io->cur_encoded_packet->data[in->length] = HDLC_HEADER;
		io->cur_encoded_packet->length += 2;
		io->cur_encoded_packet->data -= 1;
	}

	if (io->pack_timeout) io->cur_encoded_packet->timeout = io->pack_timeout;
	else io->cur_encoded_packet->timeout = io->timeout;
	QueuePush(&io->encoded, io->cur_encoded_packet);
	io->pack_timeout = 0;
}

void send_msg_bg(spdio_t *io) {
	if (!io->last_encoded_packet->length)
		ERR_EXIT("empty message\n");

	if (m_bOpened == -1) {
		if (io->not_exit_w == 0) {
			spdio_free(io);
			ERR_EXIT("device removed, exiting...\n");
		}
		else {
			io->not_exit_w = 0;
			free(io->last_encoded_packet->data);
			free(io->last_encoded_packet);
			return;
		}
	}
	if (io->verbose >= 2) {
		DBG_LOG("send (%d):\n", io->last_encoded_packet->length);
		print_mem(stderr, io->last_encoded_packet->data, io->last_encoded_packet->length);
	}
	else if (io->verbose >= 1) {
		if (io->last_encoded_packet->msg_type == BSL_CMD_CHECK_BAUD)
			DBG_LOG("send: check baud\n");
		else
			DBG_LOG("send: type = 0x%02x, size = %d\n", io->last_encoded_packet->msg_type, io->last_encoded_packet->length);
	}
	
	int ret = call_Write(io->handle, io->last_encoded_packet->data, io->last_encoded_packet->length);
	if (ret != io->last_encoded_packet->length) {
		if (io->not_exit_w == 0) {
			ERR_EXIT("usb_send failed (%d / %d)\n", ret, io->last_encoded_packet->length);
		}
		else {
			io->not_exit_w = 0;
			free(io->last_encoded_packet->data);
			free(io->last_encoded_packet);
			return;
		}
	}
}

int recv_transcode(spdio_t *io, const uint8_t *buf, int buf_len) {
	int a, pos = 0, nread = io->cur_decoded_packet->length, head_found = 0;
	static int esc = 0;
	static int plen = 6;
	if (nread) head_found = 1;
	else plen = 6;

	while (pos < buf_len) {
		a = buf[pos++];
		if (io->flags & FLAGS_TRANSCODE) {
			if (esc && a != (HDLC_HEADER ^ 0x20) &&
				a != (HDLC_ESCAPE ^ 0x20)) {
				DBG_LOG("unexpected escaped byte (0x%02x)\n", a); return 0;
			}
			if (a == HDLC_HEADER) {
				if (!head_found) head_found = 1;
				else if (!nread) continue;
				else if (nread < plen) {
					DBG_LOG("received message too short\n"); return 0;
				}
				else break;
			}
			else if (a == HDLC_ESCAPE) {
				esc = 0x20;
			}
			else {
				if (!head_found) continue;
				if (nread >= plen) {
					DBG_LOG("received message too long\n"); return 0;
				}
				io->cur_decoded_packet->data[nread++] = a ^ esc;
				esc = 0;
			}
		}
		else {
			if (!head_found && a == HDLC_HEADER) {
				if (buf[pos] == buf[pos + 1]) {
					memcpy(io->cur_decoded_packet->data, buf, buf_len);
					io->cur_decoded_packet->is_decoded = 1;
					nread = buf_len;
					break;
				}
				head_found = 1;
				io->cur_decoded_packet->is_decoded = 0;
				continue;
			}
			if (nread == plen) {
				if (a != HDLC_HEADER) {
					DBG_LOG("expected end of message\n"); return 0;
				}
				break;
			}
			io->cur_decoded_packet->data[nread++] = a;
		}
		if (nread == 4) {
			a = READ16_BE(io->cur_decoded_packet->data + 2); // len
			plen = a + 6;
		}
	}
	io->cur_decoded_packet->length = nread;
	if (io->cur_decoded_packet->is_decoded ||
		plen == nread)
		return 1;
	else
		return 0;
}

extern int fdl1_loaded;
int recv_check_crc(spdio_t *io) {
	int a, nread = io->cur_decoded_packet->length, plen = READ16_BE(io->cur_decoded_packet->data + 2) + 6;

	if (nread < 6) {
		DBG_LOG("received message too short\n"); return 0;
	}

	if (nread != plen) {
		DBG_LOG("bad length (%d, expected %d)\n", nread, plen); return 0;
	}

	a = READ16_BE(io->cur_decoded_packet->data + plen - 2);
	if (fdl1_loaded == 0 && !(io->flags & FLAGS_CRC16)) {
		int chk1, chk2;
		chk1 = spd_crc16(0, io->cur_decoded_packet->data, plen - 2);
		if (a == chk1) io->flags |= FLAGS_CRC16;
		else {
			chk2 = spd_checksum(0, io->cur_decoded_packet->data, plen - 2, CHK_ORIG);
			if (a == chk2) fdl1_loaded = 1;
			else {
				DBG_LOG("bad checksum (0x%04x, expected 0x%04x or 0x%04x)\n", a, chk1, chk2);
				return 0;
			}
		}
	}
	else {
		int chk = (io->flags & FLAGS_CRC16) ?
			spd_crc16(0, io->cur_decoded_packet->data, plen - 2) :
			spd_checksum(0, io->cur_decoded_packet->data, plen - 2, CHK_ORIG);
		if (a != chk) {
			DBG_LOG("bad checksum (0x%04x, expected 0x%04x)\n", a, chk);
			return 0;
		}
	}

	if (io->verbose == 1)
		DBG_LOG("recv: type = 0x%02x, size = %d\n",
			READ16_BE(io->cur_decoded_packet->data), READ16_BE(io->cur_decoded_packet->data + 2));

	//io->cur_decoded_packet->msg_type = READ16_BE(io->cur_decoded_packet->data);
	return nread;
}

int recv_msg_async(spdio_t *io) {
	DWORD bWaitCode = WaitForSingleObject(io->m_hOprEvent, io->last_encoded_packet->timeout);
	if (bWaitCode != WAIT_OBJECT_0) {
		if (!io->cur_decoded_packet->allow_empty_reply) ERR_EXIT("recv_msg_async timeout reached\n");
		return 0;
	}
	else {
		ResetEvent(io->m_hOprEvent);
		return io->cur_decoded_packet->length;
	}
}

int recv_msg(spdio_t *io) {
	int ret = 0;
	for (;;) {
		if (io->last_decoded_packet) {
			free(io->last_decoded_packet->data);
			io->raw_buf = NULL;
			free(io->last_decoded_packet);
			io->last_decoded_packet = NULL;
		}
		if ((io->last_decoded_packet = QueuePop(&io->decoded))) {
			ret = io->last_decoded_packet->length;
			io->raw_buf = io->last_decoded_packet->data;
			io->last_decoded_packet->msg_type = READ16_BE(io->last_decoded_packet->data);
			if (io->verbose >= 2 && io->last_decoded_packet->msg_type) {
				DBG_LOG("recv (%d):\n", ret);
				print_mem(stderr, io->raw_buf, ret);
			}
			if (recv_type(io) != BSL_REP_LOG) break;
			DBG_LOG("BSL_REP_LOG: ");
			print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
		}
	}
	return ret;
}

unsigned recv_type(spdio_t *io) {
	if (io->last_decoded_packet)
		return io->last_decoded_packet->msg_type;
		//return READ16_BE(io->last_decoded_packet->data);
	else {
		DBG_LOG("last_packet is NULL\n");
		return 0;
	}
}

// send is not here actually
int send_and_check(spdio_t *io) {
	int ret;
	recv_msg(io);
	ret = recv_type(io);
	if (ret != BSL_REP_ACK) {
		DBG_LOG("unexpected response (0x%04x)\n", ret);
		return -1;
	}
	return 0;
}

int check_confirm(const char *name) {
	char c;
	DBG_LOG("Answer \"y\" to confirm the \"%s\" command: ", name);
	fflush(stdout);
	if (scanf(" %c", &c) != 1) return 0;
	while (getchar() != '\n');
	if (tolower(c) == 'y') return 1;
	return 0;
}

uint8_t *loadfile(const char *fn, size_t *num, size_t extra) {
	size_t n, j = 0; uint8_t *buf = 0;
	FILE *fi = fopen(fn, "rb");
	if (fi) {
		fseek(fi, 0, SEEK_END);
		n = ftell(fi);
		if (n) {
			fseek(fi, 0, SEEK_SET);
			buf = (uint8_t *)malloc(n + extra);
			if (buf) j = fread(buf, 1, n, fi);
		}
		fclose(fi);
	}
	if (num) *num = j;
	return buf;
}

void send_buf(spdio_t *io,
	uint32_t start_addr, int end_data,
	unsigned step, uint8_t *mem, unsigned size) {
	uint32_t data[2], i, n;

	WRITE32_BE(data, start_addr);
	WRITE32_BE(data + 1, size);

	encode_msg(io, BSL_CMD_START_DATA, data, 4 * 2);
	if (send_and_check(io)) return;
	for (i = 0; i < size; i += n) {
		n = size - i;
		// n = spd_transcode_max(mem + i, size - i, 2048 - 2 - 6);
		if (n > step) n = step;
		encode_msg(io, BSL_CMD_MIDST_DATA, mem + i, n);
		if (send_and_check(io)) return;
	}
	if (end_data) {
		encode_msg(io, BSL_CMD_END_DATA, NULL, 0);
		send_and_check(io);
	}
}

size_t send_file(spdio_t *io, const char *fn,
	uint32_t start_addr, int end_data, unsigned step,
	unsigned src_offs, unsigned src_size) {
	uint8_t *mem; size_t size = 0;
	mem = loadfile(fn, &size, 0);
	if (!mem) ERR_EXIT("loadfile(\"%s\") failed\n", fn);
	if ((uint64_t)size >> 32) ERR_EXIT("file too big\n");
	if (size < src_offs) ERR_EXIT("required offset larger than file size\n");
	size -= src_offs;
	if (src_size) {
		if (size < src_size) DBG_LOG("required size larger than file size\n");
		else size = src_size;
	}
	send_buf(io, start_addr, end_data, step, mem + src_offs, size);
	free(mem);
	DBG_LOG("SEND %s to 0x%x\n", fn, start_addr);
	return size;
}

FILE *my_fopen(const char *fn, const char *mode) {
	if (savepath[0]) {
		char fix_fn[1024];
		char *ch;
		if ((ch = strrchr(fn, '/'))) sprintf(fix_fn, "%s/%s", savepath, ch + 1);
		else if ((ch = strrchr(fn, '\\'))) sprintf(fix_fn, "%s/%s", savepath, ch + 1);
		else sprintf(fix_fn, "%s/%s", savepath, fn);
		return fopen(fix_fn, mode);
	}
	else return fopen(fn, mode);
}

unsigned dump_flash(spdio_t *io,
	uint32_t addr, uint32_t start, uint32_t len,
	const char *fn, unsigned step) {
	uint32_t n, offset, nread;
	int ret;
	FILE *fo = my_fopen(fn, "wb");
	if (!fo) ERR_EXIT("fopen(dump) failed\n");

	for (offset = start; offset < start + len; ) {
		uint32_t data[3];
		n = start + len - offset;
		if (n > step) n = step;

		WRITE32_BE(data, addr);
		WRITE32_BE(data + 1, n);
		WRITE32_BE(data + 2, offset);

		encode_msg(io, BSL_CMD_READ_FLASH, data, 4 * 3);
		recv_msg(io);
		if ((ret = recv_type(io)) != BSL_REP_READ_FLASH) {
			DBG_LOG("unexpected response (0x%04x)\n", ret);
			break;
		}
		nread = READ16_BE(io->raw_buf + 2);
		if (n < nread)
			ERR_EXIT("unexpected length\n");
		if (fwrite(io->raw_buf + 4, 1, nread, fo) != nread)
			ERR_EXIT("fwrite(dump) failed\n");
		offset += nread;
		if (n != nread) break;
	}
	DBG_LOG("Read Flash Done: 0x%08x+0x%x, target: 0x%x, read: 0x%x\n", addr, start, len, offset - start);
	fclose(fo);
	return offset;
}

unsigned dump_mem(spdio_t *io,
	uint32_t start, uint32_t len, const char *fn, unsigned step) {
	uint32_t n, offset, nread;
	int ret;
	FILE *fo = my_fopen(fn, "wb");
	if (!fo) ERR_EXIT("fopen(dump) failed\n");

	for (offset = start; offset < start + len; ) {
		uint32_t data[3];
		n = start + len - offset;
		if (n > step) n = step;

		WRITE32_BE(data, offset);
		WRITE32_BE(data + 1, n);
		WRITE32_BE(data + 2, 0); // unused

		encode_msg(io, BSL_CMD_READ_FLASH, data, sizeof(data));
		recv_msg(io);
		if ((ret = recv_type(io)) != BSL_REP_READ_FLASH) {
			DBG_LOG("unexpected response (0x%04x)\n", ret);
			break;
		}
		nread = READ16_BE(io->raw_buf + 2);
		if (n < nread)
			ERR_EXIT("unexpected length\n");
		if (fwrite(io->raw_buf + 4, 1, nread, fo) != nread)
			ERR_EXIT("fwrite(dump) failed\n");
		offset += nread;
		if (n != nread) break;
	}
	DBG_LOG("Read Mem Done: 0x%08x, target: 0x%x, read: 0x%x\n", start, len, offset - start);
	fclose(fo);
	return offset;
}

int copy_to_wstr(uint16_t *d, size_t n, const char *s) {
	size_t i; int a = -1;
	for (i = 0; a && i < n; i++) { a = s[i]; WRITE16_LE(d + i, a); }
	return a;
}

int copy_from_wstr(char *d, size_t n, const uint16_t *s) {
	size_t i; int a = -1;
	for (i = 0; a && i < n; i++) { d[i] = a = s[i]; if (a >> 8) break; }
	return a;
}

void select_partition(spdio_t *io, const char *name,
	uint64_t size, int mode64, int cmd) {
	uint32_t t32; uint64_t n64;
	struct {
		uint16_t name[36];
		uint32_t size, size_hi; uint64_t dummy;
	} pkt = { 0 };
	int ret;

	ret = copy_to_wstr(pkt.name, sizeof(pkt.name) / 2, name);
	if (ret) ERR_EXIT("name too long\n");
	n64 = size;
	WRITE32_LE(&pkt.size, n64);
	if (mode64) {
		t32 = n64 >> 32;
		WRITE32_LE(&pkt.size_hi, t32);
	}

	encode_msg(io, cmd, &pkt,
		sizeof(pkt.name) + (mode64 ? 16 : 4));
}

#define PROGRESS_BAR_WIDTH 40

void print_progress_bar(uint64_t done, uint64_t total, unsigned long long time0) {
	static int completed0 = 0;
	static uint64_t done0 = 0;
	unsigned long long time = GetTickCount64();
	if (completed0 == PROGRESS_BAR_WIDTH) { completed0 = 0; done0 = 0; }
	int completed = (int)(PROGRESS_BAR_WIDTH * done / (double)total);
	if (completed != completed0) {
		int remaining = PROGRESS_BAR_WIDTH - completed;
		DBG_LOG("[");
		for (int i = 0; i < completed; i++) {
			DBG_LOG("=");
		}
		for (int i = 0; i < remaining; i++) {
			DBG_LOG(" ");
		}
		DBG_LOG("]%6.1f%% Speed:%6.2fMb/s\r", 100 * done / (double)total, (double)1000 * done / (time - time0) / 1024 / 1024);
		completed0 = completed;
		done0 = done;
	}
}

extern uint64_t fblk_size;
uint64_t dump_partition(spdio_t *io,
	const char *name, uint64_t start, uint64_t len,
	const char *fn, unsigned step) {
	uint32_t n, nread, t32; uint64_t offset, n64, saved_size = 0;
	int ret, mode64 = (start + len) >> 32;
	char name_tmp[36];

	if (!strcmp(name, "super")) dump_partition(io, "metadata", 0, check_partition(io, "metadata", 1), "metadata.bin", step);
	else if (!strncmp(name, "userdata", 8)) { if (!check_confirm("read userdata")) return 0; }
	else if (strstr(name, "nv1")) {
		strcpy(name_tmp, name);
		char *dot = strrchr(name_tmp, '1');
		if (dot != NULL) *dot = '2';
		name = name_tmp;
		start = 512;
		if (len > 512)
			len -= 512;
	}

	select_partition(io, name, start + len, mode64, BSL_CMD_READ_START);
	if (send_and_check(io)) {
		encode_msg(io, BSL_CMD_READ_END, NULL, 0);
		send_and_check(io);
		return 0;
	}

	FILE *fo = my_fopen(fn, "wb");
	if (!fo) ERR_EXIT("fopen(dump) failed\n");

	unsigned long long time_start = GetTickCount64();
	for (offset = start; (n64 = start + len - offset); ) {
		uint32_t data[3];
		n = (uint32_t)(n64 > step ? step : n64);

		WRITE32_LE(data, n);
		WRITE32_LE(data + 1, offset);
		t32 = offset >> 32;
		WRITE32_LE(data + 2, t32);

		encode_msg(io, BSL_CMD_READ_MIDST, data, mode64 ? 12 : 8);
		recv_msg(io);
		if ((ret = recv_type(io)) != BSL_REP_READ_FLASH) {
			DBG_LOG("unexpected response (0x%04x)\n", ret);
			break;
		}
		nread = READ16_BE(io->raw_buf + 2);
		if (n < nread)
			ERR_EXIT("unexpected length\n");
		if (fwrite(io->raw_buf + 4, 1, nread, fo) != nread)
			ERR_EXIT("fwrite(dump) failed\n");
		print_progress_bar(offset + nread - start, len, time_start);
		offset += nread;
		if (n != nread) break;

		if (fblk_size) {
			saved_size += nread;
			if (saved_size >= fblk_size) { usleep(1000000); saved_size = 0; }
		}
	}
	DBG_LOG("\nRead Part Done: %s+0x%llx, target: 0x%llx, read: 0x%llx\n",
		name, (long long)start, (long long)len,
		(long long)(offset - start));
	fclose(fo);

	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);
	return offset;
}

uint64_t read_pactime(spdio_t *io) {
	uint32_t n, offset = 0x81400, len = 8;
	int ret; uint32_t data[2];
	unsigned long long time, unix;

	select_partition(io, "miscdata", offset + len, 0, BSL_CMD_READ_START);
	if (send_and_check(io)) {
		encode_msg(io, BSL_CMD_READ_END, NULL, 0);
		send_and_check(io);
		return 0;
	}

	WRITE32_LE(data, len);
	WRITE32_LE(data + 1, offset);
	encode_msg(io, BSL_CMD_READ_MIDST, data, sizeof(data));
	recv_msg(io);
	if ((ret = recv_type(io)) != BSL_REP_READ_FLASH) {
		DBG_LOG("unexpected response (0x%04x)\n", ret);
		encode_msg(io, BSL_CMD_READ_END, NULL, 0);
		send_and_check(io);
		return 0;
	}
	n = READ16_BE(io->raw_buf + 2);
	if (n != len) ERR_EXIT("unexpected length\n");

	time = (uint32_t)READ32_LE(io->raw_buf + 4);
	time |= (uint64_t)READ32_LE(io->raw_buf + 8) << 32;

	unix = time ? time / 10000000 - 11644473600 : 0;
	// $ date -d @unixtime
	DBG_LOG("pactime = 0x%llx (unix = %llu)\n", time, unix);

	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);
	return time;
}

int scan_xml_partitions(spdio_t *io, const char *fn, uint8_t *buf, size_t buf_size) {
	const char *part1 = "Partitions>";
	char *src, *p; size_t fsize = 0;
	int part1_len = strlen(part1), found = 0, stage = 0;
	if (io->ptable == NULL) io->ptable = malloc(128 * sizeof(partition_t));
	src = (char *)loadfile(fn, &fsize, 1);
	if (!src) ERR_EXIT("loadfile failed\n");
	src[fsize] = 0;
	p = src;
	for (;;) {
		int i, a = *p++, n; char c; long long size;
		if (a == ' ' || a == '\t' || a == '\n' || a == '\r') continue;
		if (a != '<') {
			if (!a) break;
			if (stage != 1) continue;
			ERR_EXIT("xml: unexpected symbol\n");
		}
		if (!memcmp(p, "!--", 3)) {
			p = strstr(p + 3, "--");
			if (!p || !((p[-1] - '!') | (p[-2] - '<')) || p[2] != '>')
				ERR_EXIT("xml: unexpected syntax\n");
			p += 3;
			continue;
		}
		if (stage != 1) {
			stage += !memcmp(p, part1, part1_len);
			if (stage > 2)
				ERR_EXIT("xml: more than one partition lists\n");
			p = strchr(p, '>');
			if (!p) ERR_EXIT("xml: unexpected syntax\n");
			p++;
			continue;
		}
		if (*p == '/' && !memcmp(p + 1, part1, part1_len)) {
			p = p + 1 + part1_len;
			stage++;
			continue;
		}
		i = sscanf(p, "Partition id=\"%35[^\"]\" size=\"%lli\"/%n%c", (*(io->ptable + found)).name, &size, &n, &c);
		if (i != 3 || c != '>')
			ERR_EXIT("xml: unexpected syntax\n");
		p += n + 1;
		if (buf_size < 0x4c)
			ERR_EXIT("xml: too many partitions\n");
		buf_size -= 0x4c;
		memset(buf, 0, 36 * 2);
		for (i = 0; (a = (*(io->ptable + found)).name[i]); i++) buf[i * 2] = a;
		if (!i) ERR_EXIT("empty partition name\n");
		WRITE32_LE(buf + 0x48, size);
		buf += 0x4c;
		DBG_LOG("[%d] %s, %d\n", found + 1, (*(io->ptable + found)).name, (int)size);
		(*(io->ptable + found)).size = size << 20;
		found++;
	}
	io->part_count = found;
	if (p - 1 != src + fsize) ERR_EXIT("xml: zero byte");
	if (stage != 2) ERR_EXIT("xml: unexpected syntax\n");
	free(src);
	return found;
}

#define SECTOR_SIZE 512
#define MAX_SECTORS 32

extern int selected_ab;
int gpt_info(partition_t *ptable, const char *fn_xml, int *part_count_ptr) {
	FILE *fp = my_fopen("pgpt.bin", "rb");
	if (fp == NULL) {
		return -1;
	}
	efi_header header;
	int bytes_read;
	uint8_t buffer[SECTOR_SIZE];
	int sector_index = 0;
	int found = 0;

	while (sector_index < MAX_SECTORS) {
		bytes_read = fread(buffer, 1, SECTOR_SIZE, fp);
		if (bytes_read != SECTOR_SIZE) {
			fclose(fp);
			return -1;
		}
		if (memcmp(buffer, "EFI PART", 8) == 0) {
			memcpy(&header, buffer, sizeof(header));
			found = 1;
			break;
		}
		sector_index++;
	}

	if (found == 0) {
		fclose(fp);
		return -1;
	}
	else {
		if (sector_index == 1) Da_Info.dwStorageType = 0x102;
		else Da_Info.dwStorageType = 0x103;
	}
	int real_SECTOR_SIZE = SECTOR_SIZE * sector_index;
	efi_entry *entries = malloc(header.number_of_partition_entries * sizeof(efi_entry));
	if (entries == NULL) {
		fclose(fp);
		return -1;
	}
	fseek(fp, (long)header.partition_entry_lba * real_SECTOR_SIZE, SEEK_SET);
	bytes_read = fread(entries, 1, header.number_of_partition_entries * sizeof(efi_entry), fp);
	if (bytes_read != (int)(header.number_of_partition_entries * sizeof(efi_entry)))
		DBG_LOG("only read %d/%d\n", bytes_read, (int)(header.number_of_partition_entries * sizeof(efi_entry)));
	FILE *fo = NULL;
	if (strcmp(fn_xml, "-")) {
		fo = my_fopen(fn_xml, "wb");
		if (!fo) ERR_EXIT("fopen failed\n");
		fprintf(fo, "<Partitions>\n");
	}
	int n = 0;
	for (int i = 0; i < header.number_of_partition_entries; i++) {
		efi_entry entry = *(entries + i);
		if (entry.starting_lba == 0 && entry.ending_lba == 0) {
			n = i;
			break;
		}
	}
	DBG_LOG("  0 %36s     256KB\n", "splloader");
	for (int i = 0; i < n; i++) {
		efi_entry entry = *(entries + i);
		copy_from_wstr((*(ptable + i)).name, 36, (uint16_t *)entry.partition_name);
		uint64_t lba_count = entry.ending_lba - entry.starting_lba + 1;
		(*(ptable + i)).size = lba_count * real_SECTOR_SIZE;
		DBG_LOG("%3d %36s %7lldMB\n", i + 1, (*(ptable + i)).name, ((*(ptable + i)).size >> 20));
		if (fo) {
			fprintf(fo, "    <Partition id=\"%s\" size=\"", (*(ptable + i)).name);
			if (i + 1 == n) fprintf(fo, "0x%x\"/>\n", ~0);
			else fprintf(fo, "%lld\"/>\n", ((*(ptable + i)).size >> 20));
		}
		if (!selected_ab) {
			size_t namelen = strlen((*(ptable + i)).name);
			if (namelen > 2 && 0 == strcmp((*(ptable + i)).name + namelen - 2, "_a")) selected_ab = 1;
		}
	}
	if (fo) {
		fprintf(fo, "</Partitions>");
		fclose(fo);
	}
	free(entries);
	fclose(fp);
	*part_count_ptr = n;
	DBG_LOG("standard gpt table saved to pgpt.bin\n");
	DBG_LOG("skip saving sprd partition list packet\n");
	return 0;
}

extern int gpt_failed;
partition_t *partition_list(spdio_t *io, const char *fn, int *part_count_ptr) {
	long size;
	unsigned i, n = 0;
	int ret; FILE *fo = NULL; uint8_t *p;
	partition_t *ptable = malloc(128 * sizeof(partition_t));
	if (ptable == NULL) return NULL;

	DBG_LOG("Reading Partition List\n");
	if (selected_ab < 0) select_ab(io);
	int verbose = io->verbose;
	io->verbose = 0;
	size = dump_partition(io, "user_partition", 0, 32 * 1024, "pgpt.bin", 4096);
	io->verbose = verbose;
	if (32 * 1024 == size)
		gpt_failed = gpt_info(ptable, fn, part_count_ptr);
	if (gpt_failed) {
		remove("pgpt.bin");
		encode_msg(io, BSL_CMD_READ_PARTITION, NULL, 0);
		recv_msg(io);
		ret = recv_type(io);
		if (ret != BSL_REP_READ_PARTITION) {
			DBG_LOG("unexpected response (0x%04x)\n", ret);
			gpt_failed = -1;
			free(ptable);
			return NULL;
		}
		size = READ16_BE(io->raw_buf + 2);
		if (size % 0x4c) {
			DBG_LOG("not divisible by struct size (0x%04lx)\n", size);
			gpt_failed = -1;
			free(ptable);
			return NULL;
		}
		FILE *fpkt = my_fopen("sprdpart.bin", "wb");
		if (!fpkt) ERR_EXIT("fopen failed\n");
		fwrite(io->raw_buf + 4, 1, size, fpkt);
		fclose(fpkt);
		n = size / 0x4c;
		if (strcmp(fn, "-")) {
			fo = my_fopen(fn, "wb");
			if (!fo) ERR_EXIT("fopen failed\n");
			fprintf(fo, "<Partitions>\n");
		}
		int divisor = 10;
		DBG_LOG("detecting sector size\n");
		p = io->raw_buf + 4;
		for (i = 0; i < n; i++, p += 0x4c) {
			size = READ32_LE(p + 0x48);
			while (!(size >> divisor)) divisor--;
		}
		if (divisor == 10) Da_Info.dwStorageType = 0x102;
		else Da_Info.dwStorageType = 0x103;
		p = io->raw_buf + 4;
		DBG_LOG("  0 %36s     256KB\n", "splloader");
		for (i = 0; i < n; i++, p += 0x4c) {
			ret = copy_from_wstr((*(ptable + i)).name, 36, (uint16_t *)p);
			if (ret) ERR_EXIT("bad partition name\n");
			size = READ32_LE(p + 0x48);
			(*(ptable + i)).size = (long long)size << (20 - divisor);
			DBG_LOG("%3d %36s %7lldMB\n", i + 1, (*(ptable + i)).name, ((*(ptable + i)).size >> 20));
			if (fo) {
				fprintf(fo, "    <Partition id=\"%s\" size=\"", (*(ptable + i)).name);
				if (i + 1 == n) fprintf(fo, "0x%x\"/>\n", ~0);
				else fprintf(fo, "%lld\"/>\n", ((*(ptable + i)).size >> 20));
			}
			if (!selected_ab) {
				size_t namelen = strlen((*(ptable + i)).name);
				if (namelen > 2 && 0 == strcmp((*(ptable + i)).name + namelen - 2, "_a")) selected_ab = 1;
			}
		}
		if (fo) {
			fprintf(fo, "</Partitions>\n");
			fclose(fo);
		}
		*part_count_ptr = n;
		DBG_LOG("unable to get standard gpt table\n");
		DBG_LOG("sprd partition list packet saved to sprdpart.bin\n");
		gpt_failed = 0;
	}
	if (*part_count_ptr) {
		if (strcmp(fn, "-")) DBG_LOG("partition list saved to %s\n", fn);
		DBG_LOG("Total number of partitions: %d\n", *part_count_ptr);
		if (Da_Info.dwStorageType == 0x102) DBG_LOG("Storage is emmc\n");
		else if (Da_Info.dwStorageType == 0x103) DBG_LOG("Storage is ufs\n");
		return ptable;
	}
	else {
		gpt_failed = -1;
		free(ptable);
		return NULL;
	}
}

void repartition(spdio_t *io, const char *fn) {
	uint8_t *buf = io->temp_buf;
	int n = scan_xml_partitions(io, fn, buf, 0xffff);
	// print_mem(stderr, io->temp_buf, n * 0x4c);
	encode_msg(io, BSL_CMD_REPARTITION, buf, n * 0x4c);
	if (!send_and_check(io)) gpt_failed = 0;
}

void erase_partition(spdio_t *io, const char *name) {
	int timeout0 = io->timeout;
	char name0[36];
	if (!strcmp(name, "userdata")) {
		char *miscbuf = malloc(0x800);
		if (!miscbuf) ERR_EXIT("malloc failed\n");
		memset(miscbuf, 0, 0x800);
		strcpy(miscbuf, "boot-recovery");
		strcpy(miscbuf + 0x40, "recovery\n--wipe_data\n");
		w_mem_to_part_offset(io, "misc", 0, (uint8_t *)miscbuf, 0x800, 0x1000);
		free(miscbuf);
		select_partition(io, "persist", 0, 0, BSL_CMD_ERASE_FLASH);
		strcpy(name0, "persist");
	}
	else if (!strcmp(name, "all")) {
		io->timeout = 100000;
		select_partition(io, "erase_all", 0xffffffff, 0, BSL_CMD_ERASE_FLASH);
		strcpy(name0, "erase_all");
	}
	else {
		select_partition(io, name, 0, 0, BSL_CMD_ERASE_FLASH);
		strcpy(name0, name);
	}
	if (!send_and_check(io)) DBG_LOG("Erase Part Done: %s\n", name0);
	io->timeout = timeout0;
}

void load_partition(spdio_t *io, const char *name,
	const char *fn, unsigned step) {
	uint64_t offset, len, n64;
	unsigned mode64, n, step0 = step;
	FILE *fi;

	if (strstr(name, "runtimenv")) { erase_partition(io, name); return; }
	if (!strcmp(name, "calinv")) { return; } //skip calinv

	fi = fopen(fn, "rb");
	if (!fi) ERR_EXIT("fopen(load) failed\n");

	uint8_t header[4], is_simg = 0;
	if (fread(header, 1, 4, fi) != 4)
		ERR_EXIT("fread(load) failed\n");
	if (0xED26FF3A == *(uint32_t *)header) is_simg = 1;
	fseeko(fi, 0, SEEK_END);
	len = ftello(fi);
	fseek(fi, 0, SEEK_SET);
	DBG_LOG("file size : 0x%llx\n", (long long)len);

	mode64 = len >> 32;
	select_partition(io, name, len, mode64, BSL_CMD_START_DATA);
	if (send_and_check(io)) { fclose(fi); return; }

	unsigned long long time_start = GetTickCount64();
	if (Da_Info.bSupportRawData) {
		if (Da_Info.bSupportRawData > 1) {
			encode_msg(io, BSL_CMD_MIDST_RAW_START2, NULL, 0);
			if (send_and_check(io)) { Da_Info.bSupportRawData = 0; goto fallback_load; }
		}
		step = Da_Info.dwFlushSize << 10;

		for (offset = 0; (n64 = len - offset); offset += n) {
			Packet *rawdatapack = (Packet *)malloc(sizeof(Packet));
			if (!rawdatapack) ERR_EXIT("malloc pack in encode_msg failed\n");
			n = (unsigned)(n64 > step ? step : n64);
			if (m_bOpened == -1) {
				spdio_free(io);
				ERR_EXIT("device removed, exiting...\n");
			}
			uint8_t *rawbuf = (uint8_t *)malloc(n + 1);
			if (!rawbuf) ERR_EXIT("malloc failed\n");
			if (Da_Info.bSupportRawData == 1) {
				uint32_t data[3];
				uint32_t t32 = offset >> 32;
				WRITE32_LE(data, offset);
				WRITE32_LE(data + 1, t32);
				WRITE32_LE(data + 2, n);
				encode_msg(io, BSL_CMD_MIDST_RAW_START, data, 12);
				if (send_and_check(io)) {
					if (offset) break;
					else { free(rawbuf); free(rawdatapack); step = step0; Da_Info.bSupportRawData = 0; goto fallback_load; }
				}
			}
			if (fread(rawbuf, 1, n, fi) != n)
				ERR_EXIT("fread(load) failed\n");
			rawdatapack->msg_type = 0;
			rawdatapack->length = n;
			rawdatapack->data = rawbuf;
			rawdatapack->allow_empty_reply = 0;
			if (is_simg) rawdatapack->timeout = 100000;
			else rawdatapack->timeout = 15000;
			QueuePush(&io->encoded, rawdatapack);
			if (send_and_check(io)) break;
			print_progress_bar(offset + n, len, time_start);
		}
	}
	else {
fallback_load:
		for (offset = 0; (n64 = len - offset); offset += n) {
			n = (unsigned)(n64 > step ? step : n64);
			if (fread(io->temp_buf, 1, n, fi) != n)
				ERR_EXIT("fread(load) failed\n");
			if (is_simg) io->pack_timeout = 100000;
			else io->pack_timeout = 15000;
			encode_msg(io, BSL_CMD_MIDST_DATA, io->temp_buf, n);
			if (send_and_check(io)) break;
			print_progress_bar(offset + n, len, time_start);
		}
	}
	fclose(fi);
	encode_msg(io, BSL_CMD_END_DATA, NULL, 0);
	if (!send_and_check(io)) DBG_LOG("\nWrite Part Done: %s, target: 0x%llx, written: 0x%llx\n",
		name, (long long)len, (long long)offset);
}

void load_partition_force(spdio_t *io, const int id, const char *fn, unsigned step) {
	int i, j; char a;
	uint8_t *buf = io->temp_buf;
	char name[] = "w_force";
	for (i = 0; i < io->part_count; i++) {
		memset(buf, 0, 36 * 2);
		if (i == id)
			for (j = 0; (a = name[j]); j++)
				buf[j * 2] = a;
		else
			for (j = 0; (a = (*(io->ptable + i)).name[j]); j++)
				buf[j * 2] = a;
		if (!j) ERR_EXIT("empty partition name\n");
		if (i + 1 == io->part_count) WRITE32_LE(buf + 0x48, ~0);
		else WRITE32_LE(buf + 0x48, (*(io->ptable + i)).size >> 20);
		buf += 0x4c;
	}
	encode_msg(io, BSL_CMD_REPARTITION, io->temp_buf, io->part_count * 0x4c);
	if (send_and_check(io)) return; //repart failed
	load_partition(io, name, fn, step);
	buf = io->temp_buf;
	for (i = 0; i < io->part_count; i++) {
		memset(buf, 0, 36 * 2);
		for (j = 0; (a = (*(io->ptable + i)).name[j]); j++)
			buf[j * 2] = a;
		if (!j) ERR_EXIT("empty partition name\n");
		if (i + 1 == io->part_count) WRITE32_LE(buf + 0x48, ~0);
		else WRITE32_LE(buf + 0x48, (*(io->ptable + i)).size >> 20);
		buf += 0x4c;
	}
	encode_msg(io, BSL_CMD_REPARTITION, io->temp_buf, io->part_count * 0x4c);
	if (!send_and_check(io)) DBG_LOG("Force Write %s Done\n", (*(io->ptable + id)).name);
}

unsigned short const crc16_table[256] = {
	0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

unsigned short crc16(unsigned short crc, unsigned char const *buffer, unsigned int len) {
	while (len--)
		crc = (unsigned short)((crc >> 8) ^ (crc16_table[(crc ^ (*buffer++)) & 0xff]));
	return crc;
}

void load_nv_partition(spdio_t *io, const char *name,
	const char *fn, unsigned step) {
	size_t offset, rsz;
	unsigned n; int ret;
	size_t len = 0;
	uint8_t *mem;
	uint16_t crc = 0;
	uint32_t cs = 0;

	mem = loadfile(fn, &len, 0);
	if (!mem) ERR_EXIT("loadfile(\"%s\") failed\n", fn);

	uint8_t *mem0 = mem;
	if (*(uint32_t *)mem == 0x4e56) mem += 0x200;
	len = 0;
	len += sizeof(uint32_t);

	uint16_t tmp[2];
	while (1) {
		tmp[0] = 0;
		tmp[1] = 0;
		memcpy(tmp, mem + len, sizeof(tmp));
		if (!tmp[1]) { DBG_LOG("broken NV file, skipping!\n"); return; }
		len += sizeof(tmp);
		len += tmp[1];

		uint32_t doffset = ((len + 3) & 0xFFFFFFFC) - len;
		len += doffset;
		if (*(uint16_t *)(mem + len) == 0xffff) {
			len += 8;
			break;
		}
	}
	crc = crc16(crc, mem + 2, len - 2);
	WRITE16_BE(mem, crc);
	for (offset = 0; offset < len; offset++) cs += mem[offset];
	DBG_LOG("file size : 0x%zx\n", len);

	struct {
		uint16_t name[36];
		uint32_t size, cs;
	} pkt = { 0 };
	ret = copy_to_wstr(pkt.name, sizeof(pkt.name) / 2, name);
	if (ret) ERR_EXIT("name too long\n");
	WRITE32_LE(&pkt.size, len);
	WRITE32_LE(&pkt.cs, cs);
	encode_msg(io, BSL_CMD_START_DATA, &pkt, sizeof(pkt));
	if (send_and_check(io)) { free(mem0); return; }

	for (offset = 0; (rsz = len - offset); offset += n) {
		n = rsz > step ? step : rsz;
		memcpy(io->temp_buf, &mem[offset], n);
		io->pack_timeout = 15000;
		encode_msg(io, BSL_CMD_MIDST_DATA, io->temp_buf, n);
		if (send_and_check(io)) break;
	}
	free(mem0);
	encode_msg(io, BSL_CMD_END_DATA, NULL, 0);
	if (!send_and_check(io)) DBG_LOG("Write NV_Part Done: %s, target: 0x%llx, written: 0x%llx\n",
		name, (long long)len, (long long)offset);
}

void find_partition_size_new(spdio_t *io, const char *name, unsigned long long *offset_ptr) {
	int ret;
	char *name_tmp = malloc(strlen(name) + 5 + 1);
	if (name_tmp == NULL) return;
	sprintf(name_tmp, "%s_size", name);
	select_partition(io, name_tmp, 0x80, 0, BSL_CMD_READ_START);
	free(name_tmp);
	if (send_and_check(io)) {
		encode_msg(io, BSL_CMD_READ_END, NULL, 0);
		send_and_check(io);
		return;
	}

	uint32_t data[2] = { 0x80,0 };
	encode_msg(io, BSL_CMD_READ_MIDST, data, 8);
	recv_msg(io);
	if (recv_type(io) == BSL_REP_READ_FLASH) {
		ret = sscanf((char *)(io->raw_buf + 4), "size:%*[^:]: 0x%llx", offset_ptr);
		if (ret != 1) ret = sscanf((char *)(io->raw_buf + 4), "partition %*s total size: 0x%llx", offset_ptr); // new lk
		DBG_LOG("partition_size_device: %s, 0x%llx\n", name, *offset_ptr);
	}
	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);
}

uint64_t check_partition(spdio_t *io, const char *name, int need_size) {
	uint32_t t32; uint64_t n64;
	unsigned long long offset = 0; //uint64_t differs between platforms
	int ret, i, end = 20;
	char name_tmp[36];

	if (selected_ab > 0 && strcmp(name, "uboot") == 0) return 0;
	if (strstr(name, "fixnv")) {
		if (selected_ab > 0) {
			size_t namelen = strlen(name);
			if (strcmp(name + namelen - 2, "_a") && strcmp(name + namelen - 2, "_b")) return 0;
		}
		strcpy(name_tmp, name);
		char *dot = strrchr(name_tmp, '1');
		if (dot != NULL) *dot = '2';
		name = name_tmp;
	}
	else if (strstr(name, "runtimenv")) {
		size_t namelen = strlen(name);
		if (0 == strcmp(name + namelen - 2, "_a") || 0 == strcmp(name + namelen - 2, "_b")) return 0;
		strcpy(name_tmp, name);
		char *dot = strrchr(name_tmp, '1');
		if (dot != NULL) *dot = '2';
		name = name_tmp;
	}

	if (selected_ab > 0) {
		find_partition_size_new(io, name, &offset);
		if (offset) {
			if (need_size) return offset;
			else return 1;
		}
	}

	select_partition(io, name, 0x8, 0, BSL_CMD_READ_START);
	if (send_and_check(io)) {
		encode_msg(io, BSL_CMD_READ_END, NULL, 0);
		send_and_check(io);
		return 0;
	}

	uint32_t data[2] = { 0x8, 0 };
	encode_msg(io, BSL_CMD_READ_MIDST, data, 8);
	recv_msg(io);
	if (recv_type(io) == BSL_REP_READ_FLASH) ret = 1;
	else ret = 0;
	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);
	if (0 == ret || 0 == need_size) return ret;

	int incrementing = 1;
	select_partition(io, name, 0xffffffff, 0, BSL_CMD_READ_START);
	if (send_and_check(io)) {
		//NAND flash !!!
		end = 10;
		encode_msg(io, BSL_CMD_READ_END, NULL, 0);
		send_and_check(io);
		for (i = 21; i >= end;) {
			n64 = offset + (1ll << i) - (1ll << end);
			select_partition(io, name, n64, 0, BSL_CMD_READ_START);
			recv_msg(io);
			ret = recv_type(io);
			if (incrementing) {
				if (ret != BSL_REP_ACK) {
					offset += 1ll << (i - 1);
					i -= 2;
					incrementing = 0;
				}
				else i++;
			}
			else {
				if (ret == BSL_REP_ACK) offset += (1ll << i);
				i--;
			}
			encode_msg(io, BSL_CMD_READ_END, NULL, 0);
			send_and_check(io);
		}
		offset -= (1ll << end);
	}
	else {
		for (i = 21; i >= end;) {
			uint32_t data[3];
			n64 = offset + (1ll << i) - (1ll << end);
			WRITE32_LE(data, 4);
			WRITE32_LE(data + 1, n64);
			t32 = n64 >> 32;
			WRITE32_LE(data + 2, t32);

			encode_msg(io, BSL_CMD_READ_MIDST, data, sizeof(data));
			recv_msg(io);
			ret = recv_type(io);
			if (incrementing) {
				if (ret != BSL_REP_READ_FLASH) {
					offset += 1ll << (i - 1);
					i -= 2;
					incrementing = 0;
				}
				else i++;
			}
			else {
				if (ret == BSL_REP_READ_FLASH) offset += (1ll << i);
				i--;
			}
		}
	}
	if (end == 10) Da_Info.dwStorageType = 101;
	DBG_LOG("partition_size_pc: %s, 0x%llx\n", name, offset);
	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);
	return offset;
}

void get_partition_info(spdio_t *io, const char *name, int need_size) {
	int i;
	char name_ab[36];
	int verbose = io->verbose;
	io->verbose = 0;

	if (isdigit(name[0])) {
		i = atoi(name);
		if (i == 0) {
			strcpy(gPartInfo.name, "splloader");
			gPartInfo.size = 256 * 1024;
			io->verbose = verbose;
			return;
		}
		if (gpt_failed == 1) io->ptable = partition_list(io, fn_partlist, &io->part_count);
		if (i > io->part_count) {
			DBG_LOG("part not exist\n");
			gPartInfo.size = 0;
			io->verbose = verbose;
			return;
		}
		strcpy(gPartInfo.name, (*(io->ptable + i - 1)).name);
		gPartInfo.size = (*(io->ptable + i - 1)).size;
		io->verbose = verbose;
		return;
	}

	if (!strncmp(name, "splloader", 9)) {
		strcpy(gPartInfo.name, name);
		gPartInfo.size = 256 * 1024;
		io->verbose = verbose;
		return;
	}
	if (io->part_count) {
		if (selected_ab > 0) snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
		for (i = 0; i < io->part_count; i++) {
			if (!strcmp(name, (*(io->ptable + i)).name)) break;
			if (selected_ab > 0 && !strcmp(name_ab, (*(io->ptable + i)).name)) {
				name = name_ab;
				break;
			}
		}
		strcpy(gPartInfo.name, name);
		gPartInfo.size = (*(io->ptable + i)).size;
		io->verbose = verbose;
		return;
	}

	if (selected_ab < 0) select_ab(io);
	gPartInfo.size = check_partition(io, name, need_size);
	if (!gPartInfo.size && selected_ab > 0) {
		snprintf(name_ab, sizeof(name_ab), "%s_%c", name, 96 + selected_ab);
		gPartInfo.size = check_partition(io, name_ab, need_size);
		name = name_ab;
	}
	if (!gPartInfo.size) {
		DBG_LOG("part not exist\n");
		io->verbose = verbose;
		return;
	}
	strcpy(gPartInfo.name, name);
	io->verbose = verbose;
}

uint64_t str_to_size(const char *str) {
	char *end; int shl = 0; uint64_t n;
	n = strtoull(str, &end, 0);
	if (*end) {
		char suffix = tolower(*end);
		if (suffix == 'k') shl = 10;
		else if (suffix == 'm') shl = 20;
		else if (suffix == 'g') shl = 30;
		else ERR_EXIT("unknown size suffix\n");
	}
	if (shl) {
		int64_t tmp = n;
		tmp >>= 63 - shl;
		if (tmp && ~tmp)
			ERR_EXIT("size overflow on multiply\n");
	}
	return n << shl;
}

uint64_t str_to_size_ubi(const char *str, int *nand_info) {
	if (strncmp(str, "ubi", 3)) return str_to_size(str);
	else {
		char *end;
		uint64_t n;
		n = strtoull(&str[3], &end, 0);
		if (*end) {
			char suffix = tolower(*end);
			if (suffix == 'm') {
				int block = (int)(n * (1024 / nand_info[2]) + n * (1024 / nand_info[2]) / (512 / nand_info[1]) + 1);
				return 1024 * (nand_info[2] - 2 * nand_info[0]) * block;
			}
			else {
				DBG_LOG("only support mb as unit, will not treat kb/gb as ubi size\n");
				return str_to_size(&str[3]);
			}
		}
		else return n;
	}
}

void dump_partitions(spdio_t *io, const char *fn, int *nand_info, unsigned step) {
	const char *part1 = "Partitions>";
	char *src, *p;
	int part1_len = strlen(part1), found = 0, stage = 0, ubi = 0;
	size_t size = 0;
	partition_t *partitions = malloc(128 * sizeof(partition_t));
	if (partitions == NULL) return;

	if (!strncmp(fn, "ubi", 3)) ubi = 1;
	src = (char *)loadfile(fn, &size, 1);
	if (!src) ERR_EXIT("loadfile failed\n");
	src[size] = 0;
	p = src;

	for (;;) {
		int i, a = *p++, n;
		char c;

		if (a == ' ' || a == '\t' || a == '\n' || a == '\r') continue;

		if (a != '<') {
			if (!a) break;
			if (stage != 1) continue;
			ERR_EXIT("xml: unexpected symbol\n");
		}

		if (!memcmp(p, "!--", 3)) {
			p = strstr(p + 3, "--");
			if (!p || !((p[-1] - '!') | (p[-2] - '<')) || p[2] != '>')
				ERR_EXIT("xml: unexpected syntax\n");
			p += 3;
			continue;
		}

		if (stage != 1) {
			stage += !memcmp(p, part1, part1_len);
			if (stage > 2)
				ERR_EXIT("xml: more than one partition lists\n");
			p = strchr(p, '>');
			if (!p) ERR_EXIT("xml: unexpected syntax\n");
			p++;
			continue;
		}

		if (*p == '/' && !memcmp(p + 1, part1, part1_len)) {
			p = p + 1 + part1_len;
			stage++;
			continue;
		}

		i = sscanf(p, "Partition id=\"%35[^\"]\" size=\"%lli\"/%n%c", partitions[found].name, &partitions[found].size, &n, &c);
		if (i != 3 || c != '>')
			ERR_EXIT("xml: unexpected syntax\n");
		p += n + 1;
		found++;
		if (found >= 128) break;
	}
	if (p - 1 != src + size) ERR_EXIT("xml: zero byte");
	if (stage != 2) ERR_EXIT("xml: unexpected syntax\n");

	for (int i = 0; i < found; i++) {
		DBG_LOG("Partition %d: name=%s, size=%llim\n", i + 1, partitions[i].name, partitions[i].size);
		if (!strncmp(partitions[i].name, "userdata", 8)) continue;

		get_partition_info(io, partitions[i].name, 0);
		if (!gPartInfo.size) continue;
		if (!strncmp(partitions[i].name, "splloader", 9)) gPartInfo.size = 256 * 1024;
		else if (0xffffffff == partitions[i].size) gPartInfo.size = check_partition(io, gPartInfo.name, 1);
		else if (ubi) {
			int block = (int)(partitions[i].size * (1024 / nand_info[2]) + partitions[i].size * (1024 / nand_info[2]) / (512 / nand_info[1]) + 1);
			gPartInfo.size = 1024 * (nand_info[2] - 2 * nand_info[0]) * block;
		}
		else gPartInfo.size = partitions[i].size << 20;

		char dfile[40];
		snprintf(dfile, sizeof(dfile), "%s.bin", partitions[i].name);
		dump_partition(io, gPartInfo.name, 0, gPartInfo.size, dfile, step);
	}
	if (selected_ab > 0) { DBG_LOG("saving slot info\n"); dump_partition(io, "misc", 0, 1048576, "misc.bin", step); }

	if (savepath[0]) {
		DBG_LOG("saving dump list\n");
		FILE *fo = my_fopen(fn, "wb");
		if (fo) { fwrite(src, 1, size, fo); fclose(fo); }
		else DBG_LOG("create dump list failed, skipping.\n");
	}
	free(src);
	free(partitions);
}

int ab_compare_slots(const slot_metadata *a, const slot_metadata *b);
void load_partitions(spdio_t *io, const char *path, unsigned step, int force_ab) {
	typedef struct {
		char name[36];
		char file_path[1024];
		int written_flag;
	} partition_info_t;
	size_t namelen;
	char miscname[1024] = { 0 };
	int VAB = 0; // slot_in_name
	int partition_count = 0;
	partition_info_t *partitions = malloc(128 * sizeof(partition_info_t));
	if (partitions == NULL) return;
	char *fn;
	char searchPath[ARGV_LEN];
	snprintf(searchPath, ARGV_LEN, "%s\\*", path);

	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(searchPath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		DBG_LOG("Error opening directory.\n");
		return;
	}
	for (fn = findData.cFileName; FindNextFileA(hFind, &findData); fn = findData.cFileName) {
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
		namelen = strlen(fn);
		if (namelen >= 4) {
			if (!strcmp(fn + namelen - 4, ".xml") ||
				!strcmp(fn + namelen - 4, ".exe") ||
				!strcmp(fn + namelen - 4, ".txt")) continue;
		}
		if (!strncmp(fn, "pgpt", 4) ||
			!strncmp(fn, "sprdpart", 8) ||
			!strncmp(fn, "fdl", 3) ||
			!strncmp(fn, "lk", 2) ||
			!strncmp(fn, "0x", 2) ||
			!strncmp(fn, "custom_exec", 11)) continue;

		snprintf(partitions[partition_count].file_path, sizeof(partitions[partition_count].file_path), "%s/%s", path, fn);
		char *dot = strrchr(fn, '.');
		if (dot != NULL) *dot = '\0';
		namelen = strlen(fn);
		if (namelen >= 4 && strcmp(fn + namelen - 4, "_bak") == 0) continue;
		if (!strcmp(fn, "misc")) snprintf(miscname, 1024, "%s", partitions[partition_count].file_path);
		if (namelen > 2) {
			if (!strcmp(fn + namelen - 2, "_a")) VAB |= 1;
			else if (!strcmp(fn + namelen - 2, "_b")) VAB |= 2;
		}

		strcpy(partitions[partition_count].name, fn);
		partitions[partition_count].written_flag = 0;
		partition_count++;
	}
	FindClose(hFind);
	if (selected_ab < 0) select_ab(io);
	int selected_ab_bak = selected_ab;
	bootloader_control *abc = NULL;
	size_t misclen = 0;
	if (force_ab && (force_ab & VAB)) selected_ab = force_ab;
	else {
		if (miscname[0]) {
			uint8_t *mem = loadfile(miscname, &misclen, 0);
			if (misclen >= 0x820) {
				abc = (bootloader_control *)(mem + 0x800);
				if (abc->nb_slot != 2) selected_ab = 0;
				if (ab_compare_slots(&abc->slot_info[1], &abc->slot_info[0]) < 0) selected_ab = 2;
				else selected_ab = 1;
			}
			free(mem);
		}
		if (!selected_ab) {
			if (VAB & 1) selected_ab = 1;
			else if (VAB & 2) selected_ab = 2;
			else if (selected_ab_bak > 0) selected_ab = selected_ab_bak;
		}
	}

	for (int i = 0; i < partition_count; i++) {
		fn = partitions[i].name;
		namelen = strlen(fn);
		if (selected_ab == 1 && namelen > 2 && 0 == strcmp(fn + namelen - 2, "_b")) { partitions[i].written_flag = 1; continue; }
		else if (selected_ab == 2 && namelen > 2 && 0 == strcmp(fn + namelen - 2, "_a")) { partitions[i].written_flag = 1; continue; }
		if (!strcmp(fn, "splloader") ||
			!strcmp(fn, "uboot_a") ||
			!strcmp(fn, "uboot_b") ||
			!strcmp(fn, "vbmeta_a") ||
			!strcmp(fn, "vbmeta_b")) {
			load_partition(io, fn, partitions[i].file_path, step);
			partitions[i].written_flag = 1;
			continue;
		}
		if (strcmp(fn, "uboot") == 0 || strcmp(fn, "vbmeta") == 0) {
			get_partition_info(io, fn, 0);
			if (!gPartInfo.size) continue;

			load_partition_unify(io, gPartInfo.name, partitions[i].file_path, step);
			partitions[i].written_flag = 1;
			continue;
		}
		if (strncmp(fn, "vbmeta_", 7) == 0) {
			get_partition_info(io, fn, 0);
			if (!gPartInfo.size) continue;

			load_partition_unify(io, gPartInfo.name, partitions[i].file_path, step);
			partitions[i].written_flag = 1;
			continue;
		}
	}
	int metadata_in_dump = 0, super_in_dump = 0, metadata_id = -1, super_id = -1;
	for (int i = 0; i < partition_count; i++) {
		if (!partitions[i].written_flag) {
			fn = partitions[i].name;
			get_partition_info(io, fn, 0);
			if (!gPartInfo.size) continue;
			if (!strcmp(gPartInfo.name, "metadata")) { metadata_in_dump = 1; metadata_id = i; continue; }
			if (!strcmp(gPartInfo.name, "super")) { super_in_dump = 1; super_id = i; continue; }
			load_partition_unify(io, gPartInfo.name, partitions[i].file_path, step);
		}
	}
	if (super_in_dump) {
		load_partition(io, "super", partitions[super_id].file_path, step);
		if (metadata_in_dump) load_partition(io, "metadata", partitions[metadata_id].file_path, step);
		else erase_partition(io, "metadata");
	}
	free(partitions);
	if (selected_ab == 1) set_active(io, "a");
	else if (selected_ab == 2) set_active(io, "b");
	selected_ab = selected_ab_bak;
}

void get_Da_Info(spdio_t *io) {
	if (io->last_decoded_packet->length > 6) {
		if (0x7477656e == *(uint32_t *)(io->raw_buf + 4)) {
			int len = 8;
			uint16_t tmp[2];
			while (len + 2 < io->last_decoded_packet->length) {
				tmp[0] = 0;
				tmp[1] = 0;
				memcpy(tmp, io->raw_buf + len, sizeof(tmp));

				len += sizeof(tmp);
				if (tmp[0] == 0) Da_Info.bDisableHDLC = *(uint32_t *)(io->raw_buf + len);
				else if (tmp[0] == 2) Da_Info.bSupportRawData = *(uint8_t *)(io->raw_buf + len);
				else if (tmp[0] == 3) Da_Info.dwFlushSize = *(uint32_t *)(io->raw_buf + len);
				else if (tmp[0] == 6) Da_Info.dwStorageType = *(uint32_t *)(io->raw_buf + len);
				len += tmp[1];
			}
		}
		else memcpy(&Da_Info, io->raw_buf + 4, io->last_decoded_packet->length - 6);
	}
	DBG_LOG("FDL2: incompatible partition\n");
}

int ab_compare_slots(const slot_metadata *a, const slot_metadata *b) {
	if (a->priority != b->priority)
		return b->priority - a->priority;
	if (a->successful_boot != b->successful_boot)
		return b->successful_boot - a->successful_boot;
	if (a->tries_remaining != b->tries_remaining)
		return b->tries_remaining - a->tries_remaining;
	return 0;
}

void select_ab(spdio_t *io) {
	bootloader_control *abc = NULL;

	select_partition(io, "misc", 0x820, 0, BSL_CMD_READ_START);
	if (send_and_check(io)) {
		encode_msg(io, BSL_CMD_READ_END, NULL, 0);
		send_and_check(io);
		selected_ab = 0;
		return;
	}

	uint32_t data[2] = { 0x20,0x800 };
	encode_msg(io, BSL_CMD_READ_MIDST, data, 8);
	recv_msg(io);
	if (recv_type(io) == BSL_REP_READ_FLASH) abc = (bootloader_control *)(io->raw_buf + 4);
	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);

	if (abc == NULL) { selected_ab = 0; return; }
	if (abc->nb_slot != 2) { selected_ab = 0; return; }
	if (ab_compare_slots(&abc->slot_info[1], &abc->slot_info[0]) < 0) selected_ab = 2;
	else selected_ab = 1;

	if (selected_ab > 0 && check_partition(io, "uboot_a", 0) == 0) selected_ab = 0;
}

void dm_disable(spdio_t *io, unsigned step) {
	char ch = '\1';
	w_mem_to_part_offset(io, "vbmeta", 0x7B, (uint8_t *)&ch, 1, step);
}

void dm_enable(spdio_t *io, unsigned step) {
	const char *list[] = { "vbmeta", "vbmeta_system", "vbmeta_vendor", "vbmeta_system_ext", "vbmeta_product", "vbmeta_odm", NULL };
	char ch = '\0';
	for (int i = 0; list[i] != NULL; i++) w_mem_to_part_offset(io, list[i], 0x7B, (uint8_t *)&ch, 1, step);
}

uint32_t const crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t crc32(uint32_t crc_in, const uint8_t *buf, int size) {
	const uint8_t *p = buf;
	uint32_t crc;

	crc = crc_in ^ ~0U;
	while (size--)
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
	return crc ^ ~0U;
}

void w_mem_to_part_offset(spdio_t *io, const char *name, size_t offset, uint8_t *mem, size_t length, unsigned step) {
	get_partition_info(io, name, 1);
	if (!gPartInfo.size) { DBG_LOG("part not exist\n"); return; }
	else if (gPartInfo.size > 0xffffffff) { DBG_LOG("part too large\n"); return; }

	char dfile[40];
	snprintf(dfile, sizeof(dfile), "%s.bin", name);

	char fix_fn[1024];
	if (savepath[0]) sprintf(fix_fn, "%s/%s", savepath, dfile);
	else strcpy(fix_fn, dfile);

	FILE *fi;
	if (offset == 0) fi = fopen(fix_fn, "wb");
	else {
		if (gPartInfo.size != (long long)dump_partition(io, gPartInfo.name, 0, gPartInfo.size, fix_fn, step)) {
			remove(fix_fn);
			return;
		}
		fi = fopen(fix_fn, "rb+");
	}
	if (!fi) ERR_EXIT("fopen %s failed\n", fix_fn);
	if (fseek(fi, offset, SEEK_SET) != 0) ERR_EXIT("fseek failed\n");
	if (fwrite(mem, 1, length, fi) != length) ERR_EXIT("fwrite failed\n");
	fclose(fi);
	load_partition_unify(io, gPartInfo.name, fix_fn, step);
}

// 1 main written and _bak not written, 2 both written
int load_partition_unify(spdio_t *io, const char *name, const char *fn, unsigned step) {
	char name0[36], name1[40];
	unsigned size0, size1;
	int isVBMETA = 0;
	if (strstr(name, "fixnv1")) { load_nv_partition(io, name, fn, 4096); return 1; }
	if (!strcmp(name, "vbmeta")) isVBMETA = 1;
	else if (selected_ab > 0 ||
		Da_Info.dwStorageType == 0x101 ||
		io->part_count == 0 ||
		strncmp(name, "splloader", 9) == 0) {
		load_partition(io, name, fn, step);
		return 1;
	}

	strcpy(name0, name);
	if (strlen(name0) >= sizeof(name1) - 4) { load_partition(io, name0, fn, step); return 1; }
	snprintf(name1, sizeof(name1), "%s_bak", name0);
	get_partition_info(io, name1, 1);
	if (!gPartInfo.size) { load_partition(io, name0, fn, step); return 1; }
	size1 = gPartInfo.size;
	size0 = check_partition(io, name0, 1);

	for (int i = 0; i < io->part_count; i++)
		if (!strcmp(name0, (*(io->ptable + i)).name)) {
			load_partition_force(io, i, fn, step);
			break;
		}
	if (size0 == size1) {
		if (isVBMETA) {
			char ch = '\0';
			FILE *fi = fopen(fn, "rb+");
			if (!fi) { DBG_LOG("fopen %s failed\n", fn); return 1; }
			if (fseek(fi, 0x7B, SEEK_SET) != 0) { DBG_LOG("fseek failed\n"); fclose(fi); return 1; }
			if (fwrite(&ch, 1, 1, fi) != 1) { DBG_LOG("fwrite failed\n"); fclose(fi); return 1; }
			fclose(fi);
		}
		load_partition(io, name1, fn, step);
		return 2;
	}
	return 1;
}

void set_active(spdio_t *io, char *arg) {
	uint32_t tmp[8] = { 0x5F, 0x42414342, 0x201, 0, 0, 0, 0, 0 };
	bootloader_control *abc = (bootloader_control *)tmp;
	int slot = *arg - 'a';

	abc->slot_info[slot].priority = 15;
	abc->slot_info[slot].tries_remaining = 6;
	abc->slot_info[slot].successful_boot = 0;
	abc->slot_info[1 - slot].priority = 14;
	abc->slot_info[1 - slot].tries_remaining = 1;
	abc->slot_suffix[1] = *arg;
	abc->crc32_le = crc32(0, (void *)abc, 0x1C);

	w_mem_to_part_offset(io, "misc", 0x800, (uint8_t *)abc, sizeof(bootloader_control), 0x1000);
}

const _TCHAR CLASS_NAME[] = _T("Sample Window Class");

HWND g_hWnd;

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	static BOOL interface_checked = FALSE;
	static BOOL is_diag = FALSE;
	switch (message) {
	case WM_DEVICECHANGE:
		if (DBT_DEVICEARRIVAL == wParam || DBT_DEVICEREMOVECOMPLETE == wParam) {
			PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;
			PDEV_BROADCAST_DEVICEINTERFACE pDevInf;
			PDEV_BROADCAST_PORT pDevPort;
			switch (pHdr->dbch_devicetype) {
			case DBT_DEVTYP_DEVICEINTERFACE:
				pDevInf = (PDEV_BROADCAST_DEVICEINTERFACE)pHdr;
				if (my_strstr(pDevInf->dbcc_name, _T("VID_1782&PID_4D00"))) interface_checked = TRUE;
				else if (my_strstr(pDevInf->dbcc_name, _T("VID_1782&PID_4D03"))) {
					interface_checked = TRUE;
					is_diag = TRUE;
				}
				break;
			case DBT_DEVTYP_PORT:
				if (interface_checked) {
					pDevPort = (PDEV_BROADCAST_PORT)pHdr;
					DWORD changedPort = my_strtoul(pDevPort->dbcp_name + 3, NULL, 0);
					if (DBT_DEVICEARRIVAL == wParam) {
						if (!curPort) {
							if (is_diag) {
								DWORD *currentports = FindPort("SPRD DIAG");
								if (currentports) {
									for (DWORD *port = currentports; *port != 0; port++) {
										if (changedPort == *port) {
											curPort = changedPort;
											break;
										}
									}
									free(currentports);
									currentports = NULL;
								}
							}
							else {
								curPort = changedPort;
							}
						}
					}
					else {
						if (curPort == changedPort) m_bOpened = -1; // no need to judge changedPort for DBT_DEVICEREMOVECOMPLETE
					}
					interface_checked = FALSE;
					is_diag = FALSE;
				}
				break;
			}
		}
	}

	return DefWindowProc(hWnd, message, wParam, lParam);
}

DWORD WINAPI ThrdFunc(LPVOID lpParam) {
	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = WndProc;
	wc.hInstance = GetModuleHandle(NULL);
	wc.lpszClassName = CLASS_NAME;
	if (0 == RegisterClass(&wc)) return -1;

	g_hWnd = CreateWindowEx(0, CLASS_NAME, _T(""), WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, // Parent window
		NULL, // Menu
		GetModuleHandle(NULL), // Instance handle
		NULL // Additional application data
	);
	if (g_hWnd == NULL) return -1;

	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
	const GUID GUID_DEVINTERFACE = { 0x86e0d1e0, 0x8089, 0x11d0, { 0x9c, 0xe4, 0x08, 0x00, 0x3e, 0x30, 0x1f, 0x73 } };
	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
	NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
	NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	NotificationFilter.dbcc_classguid = GUID_DEVINTERFACE;
	if (RegisterDeviceNotification(g_hWnd, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE) == NULL) return -1;

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}

void send_encoded_data(spdio_t *io, uint8_t *input, int len, int allow_empty_reply) {
	Packet *p = (Packet *)malloc(sizeof(Packet));
	if (!p) ERR_EXIT("malloc pack in send_encoded_data failed\n");
	p->data = malloc(len);
	if (!p->data) ERR_EXIT("malloc pack->data in send_encoded_data failed\n");
	memcpy(p->data, input, len);
	p->msg_type = 0;
	p->length = len;
	p->allow_empty_reply = allow_empty_reply;
	p->timeout = 1000;
	QueuePush(&io->encoded, p);
}

void ChangeMode(spdio_t *io, int ms, int bootmode, int at) {
	if (bootmode >= 0x80) ERR_EXIT("mode not exist\n");
	int ret = 0, done = 0;

	while (done != 1) {
		DBG_LOG("Waiting for boot_diag/cali_diag/dl_diag connection (%ds)\n", ms / 1000);
		for (int i = 0; ; i++) {
			if (curPort) {
				if (!call_ConnectChannel(io->handle, curPort, WM_RCV_CHANNEL_DATA, io->m_dwRecvThreadID)) ERR_EXIT("Connection failed\n");
				break;
			}
			if (100 * i >= ms) ERR_EXIT("find port failed\n");
			usleep(100000);
		}

		uint8_t payload[10] = { 0x7e,0,0,0,0,8,0,0xfe,0,0x7e };
		if (!bootmode) {
			uint8_t hello[10] = { 0x7e,0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e };
			send_encoded_data(io, hello, sizeof(hello), 0);
			recv_msg(io);
			ret = recv_type(io);
			if (ret == BSL_REP_VER ||
				ret == BSL_REP_VERIFY_ERROR ||
				ret == BSL_REP_UNSUPPORTED_COMMAND) {
				return;
			}
			payload[8] = 0x82;
		}
		else if (at) payload[8] = 0x81;
		else payload[8] = bootmode + 0x80;

		send_encoded_data(io, payload, sizeof(payload), 1);
		if (recv_msg(io)) {
			ret = recv_type(io);
			if (ret == BSL_REP_VER ||
				ret == BSL_REP_VERIFY_ERROR ||
				ret == BSL_REP_UNSUPPORTED_COMMAND) {
				if (ret == BSL_REP_VER) { if (io->raw_buf[8] < '4') return; }
				else return;
			}
			else if (ret != 0x7e7e) {
				uint8_t autod[] = { 0x7e,0,0,0,0,0x20,0,0x68,0,0x41,0x54,0x2b,0x53,0x50,0x52,0x45,0x46,0x3d,0x22,0x41,0x55,0x54,0x4f,0x44,0x4c,0x4f,0x41,0x44,0x45,0x52,0x22,0xd,0xa,0x7e };
				usleep(500000);
				io->not_exit_w = 1;
				send_encoded_data(io, autod, sizeof(autod), 1);
				if (recv_msg(io)) done = -1;
			}
		}
		for (int i = 0; ; i++) {
			if (m_bOpened == -1) {
				call_DisconnectChannel(io->handle);
				ret = 0;
				curPort = 0;
				m_bOpened = 0;
				if (done == -1) done = 1;
				break;
			}
			if (i >= 100) {
				if (ret == BSL_REP_VER) return;
				else ERR_EXIT("kick reboot timeout, reboot your phone by pressing POWER and VOL_UP for 7-10 seconds.\n");
			}
			usleep(100000);
		}
		if (!at) done = 1;
	}
}

DWORD WINAPI RcvDataThreadProc(LPVOID lpParam) {
	spdio_t *io = (spdio_t *)lpParam;

	MSG msg;
	PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);

	SetEvent(io->m_hRecvThreadState);

	while (GetMessage(&msg, NULL, 0, 0)) {
		switch (msg.message) {
		case WM_RCV_CHANNEL_DATA:
			if (recv_transcode(io, (const uint8_t *)msg.wParam, (int)msg.lParam)) {
				if (io->cur_decoded_packet->is_decoded || recv_check_crc(io)) {
					SetEvent(io->m_hOprEvent);
				}
			}
			call_FreeMem(io->handle, (LPVOID)msg.wParam);
			break;
		default:
			break;
		}
	}

	SetEvent(io->m_hRecvThreadState);

	return 0;
}

BOOL CreateRecvThread(spdio_t *io) {
	io->m_hRecvThreadState = CreateEvent(NULL, TRUE, FALSE, NULL);
	io->m_hOprEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	io->m_hRecvThread = CreateThread(NULL, 0, RcvDataThreadProc, io, 0, &io->m_dwRecvThreadID);
	if (io->m_hRecvThreadState == NULL || io->m_hOprEvent == NULL || io->m_hRecvThread == NULL) {
		return FALSE;
	}

	DWORD bWaitCode = WaitForSingleObject(io->m_hRecvThreadState, 5000);
	if (bWaitCode != WAIT_OBJECT_0) {
		return FALSE;
	}
	else {
		ResetEvent(io->m_hRecvThreadState);
	}
	return TRUE;
}

void DestroyRecvThread(spdio_t *io) {
	if (io->m_hRecvThread == NULL) {
		return;
	}

	PostThreadMessage(io->m_dwRecvThreadID, WM_QUIT, 0, 0);

	WaitForSingleObject(io->m_hRecvThreadState, INFINITE);
	ResetEvent(io->m_hRecvThreadState);

	if (io->m_hRecvThread) {
		CloseHandle(io->m_hRecvThread);
		io->m_hRecvThread = NULL;
	}

	if (io->m_hRecvThreadState) {
		CloseHandle(io->m_hRecvThreadState);
		io->m_hRecvThreadState = NULL;
	}

	if (io->m_hOprEvent) {
		CloseHandle(io->m_hOprEvent);
		io->m_hOprEvent = NULL;
	}

	io->m_dwRecvThreadID = 0;
}

DWORD WINAPI EncodeThread(LPVOID lpParam) {
	spdio_t *io = (spdio_t *)lpParam;
	Packet *p = NULL;
	while ((p = QueuePop(&io->raw))) {
		encode_msg_bg(io, p);
	}
	QueueClose(&io->encoded);
	return 0;
}

DWORD WINAPI SendRecvThread(LPVOID lpParam) {
	spdio_t *io = (spdio_t *)lpParam;
	while ((io->last_encoded_packet = QueuePop(&io->encoded))) {
		io->cur_decoded_packet = malloc(sizeof(Packet));
		if (io->cur_decoded_packet) {
			io->cur_decoded_packet->data = malloc(0xffff);
			if (io->cur_decoded_packet->data) {
				io->cur_decoded_packet->msg_type = 0;
				io->cur_decoded_packet->length = 0;
				io->cur_decoded_packet->allow_empty_reply = io->last_encoded_packet->allow_empty_reply;
			}
		}
		send_msg_bg(io);
		recv_msg_async(io);
		QueuePush(&io->decoded, io->cur_decoded_packet);
		free(io->last_encoded_packet->data);
		free(io->last_encoded_packet);
	}
	QueueClose(&io->decoded);
	return 0;
}

void QueueInit(Queue *pq) {
	if (!pq) ERR_EXIT("NULL");
	pq->phead = pq->ptail = NULL;
	pq->closed = 0;
	InitializeCriticalSection(&pq->lock);
	InitializeConditionVariable(&pq->not_empty);
}

void QueueDestroy(Queue *pq) {
	if (!pq) ERR_EXIT("NULL");
	EnterCriticalSection(&pq->lock);
	Packet *pcur = pq->phead;
	while (pcur) {
		Packet *next = pcur->next;
		free(pcur->data);
		free(pcur);
		pcur = next;
	}
	pq->phead = pq->ptail = NULL;
	LeaveCriticalSection(&pq->lock);
	DeleteCriticalSection(&pq->lock);
}

void QueuePush(Queue *pq, Packet *in) {
	if (!pq || !in) ERR_EXIT("NULL");
	EnterCriticalSection(&pq->lock);
	if (pq->closed) {
		LeaveCriticalSection(&pq->lock);
		ERR_EXIT("Queue is closed");
	}

	in->next = NULL;
	if (pq->phead == NULL) {
		pq->phead = pq->ptail = in;
	}
	else {
		pq->ptail->next = in;
		pq->ptail = in;
	}

	WakeConditionVariable(&pq->not_empty);
	LeaveCriticalSection(&pq->lock);
}

Packet *QueuePop(Queue *pq) {
	if (!pq) ERR_EXIT("NULL");
	EnterCriticalSection(&pq->lock);
	Packet *out = NULL;
	while (pq->phead == NULL && !pq->closed) {
		SleepConditionVariableCS(&pq->not_empty, &pq->lock, INFINITE);
	}

	if (pq->phead == NULL || pq->closed) {
		LeaveCriticalSection(&pq->lock);
		out = NULL;
		return out;
	}

	out = pq->phead;
	if (pq->phead == pq->ptail)
		pq->phead = pq->ptail = NULL;
	else
		pq->phead = pq->phead->next;

	LeaveCriticalSection(&pq->lock);
	return out;
}

void QueueClose(Queue *pq) {
	if (!pq) return;
	EnterCriticalSection(&pq->lock);
	pq->closed = 1;
	WakeAllConditionVariable(&pq->not_empty);
	LeaveCriticalSection(&pq->lock);
}

