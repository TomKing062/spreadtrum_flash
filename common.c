#include "common.h"
#if !USE_LIBUSB
DWORD curPort = 0;
DWORD* ports = NULL;
DWORD FindPort(const char* USB_DL)
{
	const GUID GUID_DEVCLASS_PORTS = { 0x4d36e978, 0xe325, 0x11ce,{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18} };
	HDEVINFO DeviceInfoSet;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD dwIndex = 0;
	DWORD count = 0;

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

		SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, &DeviceInfoData, SPDRP_FRIENDLYNAME, &dataType, (BYTE*)friendlyName, dataSize, &dataSize);
		char* result = strstr(friendlyName, USB_DL);
		if (result != NULL) {
			char portNum_str[4];
			strncpy(portNum_str, result + strlen(USB_DL) + 5, 3);
			portNum_str[3] = 0;

			DWORD portNum = strtoul(portNum_str, NULL, 0);
			DWORD* temp = (DWORD*)realloc(ports, (count + 2) * sizeof(DWORD));
			if (temp == NULL) {
				DBG_LOG("Memory allocation failed.\n");
				SetupDiDestroyDeviceInfoList(DeviceInfoSet);
				free(ports);
				ports = NULL;
				return 0;
			}
			ports = temp;
			ports[count] = portNum;
			count++;
		}
		++dwIndex;
	}

	SetupDiDestroyDeviceInfoList(DeviceInfoSet);
	if (count > 0) {
		ports[count] = 0;
		return ports[0];
	}
	return 0;
}

void usleep(unsigned int us)
{
	Sleep(us / 1000);
}
#endif

extern int m_bOpened;

void print_mem(FILE* f, uint8_t* buf, size_t len) {
	size_t i; int a, j, n;
	for (i = 0; i < len; i += 16) {
		n = len - i;
		if (n > 16) n = 16;
		for (j = 0; j < n; j++) fprintf(f, "%02x ", buf[i + j]);
		for (; j < 16; j++) fprintf(f, "   ");
		fprintf(f, " |");
		for (j = 0; j < n; j++) {
			a = buf[i + j];
			fprintf(f, "%c", a > 0x20 && a < 0x7f ? a : '.');
		}
		fprintf(f, "|\n");
	}
}

void print_string(FILE* f, const void* src, size_t n) {
	size_t i; int a, b = 0;
	const uint8_t* buf = (const uint8_t*)src;
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

#if USE_LIBUSB
void find_endpoints(libusb_device_handle* dev_handle, int result[2]) {
	int endp_in = -1, endp_out = -1;
	int i, k, err;
	//struct libusb_device_descriptor desc;
	struct libusb_config_descriptor* config;
	libusb_device* device = libusb_get_device(dev_handle);
	if (!device)
		ERR_EXIT("libusb_get_device failed\n");
	//if (libusb_get_device_descriptor(device, &desc) < 0)
	//	ERR_EXIT("libusb_get_device_descriptor failed");
	err = libusb_get_config_descriptor(device, 0, &config);
	if (err < 0)
		ERR_EXIT("libusb_get_config_descriptor failed : %s\n", libusb_error_name(err));

	for (k = 0; k < config->bNumInterfaces; k++) {
		const struct libusb_interface* interface;
		const struct libusb_interface_descriptor* interface_desc;
		int claim = 0;
		interface = config->interface + k;
		if (interface->num_altsetting < 1) continue;
		interface_desc = interface->altsetting + 0;
		for (i = 0; i < interface_desc->bNumEndpoints; i++) {
			const struct libusb_endpoint_descriptor* endpoint;
			endpoint = interface_desc->endpoint + i;
			if (endpoint->bmAttributes == 2) {
				int addr = endpoint->bEndpointAddress;
				err = 0;
				if (addr & 0x80) {
					if (endp_in >= 0) ERR_EXIT("more than one endp_in\n");
					endp_in = addr;
					claim = 1;
				}
				else {
					if (endp_out >= 0) ERR_EXIT("more than one endp_out\n");
					endp_out = addr;
					claim = 1;
				}
			}
		}
		if (claim) {
			i = interface_desc->bInterfaceNumber;
#if LIBUSB_DETACH
			err = libusb_kernel_driver_active(dev_handle, i);
			if (err > 0) {
				DBG_LOG("kernel driver is active, trying to detach\n");
				err = libusb_detach_kernel_driver(dev_handle, i);
				if (err < 0)
					ERR_EXIT("libusb_detach_kernel_driver failed : %s\n", libusb_error_name(err));
			}
#endif
			err = libusb_claim_interface(dev_handle, i);
			if (err < 0)
				ERR_EXIT("libusb_claim_interface failed : %s\n", libusb_error_name(err));
			break;
		}
	}
	if (endp_in < 0) ERR_EXIT("endp_in not found\n");
	if (endp_out < 0) ERR_EXIT("endp_out not found\n");
	libusb_free_config_descriptor(config);

	//DBG_LOG("USB endp_in=%02x, endp_out=%02x\n", endp_in, endp_out);

	result[0] = endp_in;
	result[1] = endp_out;
}
#endif

#define RECV_BUF_LEN (0x8000)

char savepath[ARGV_LEN] = { 0 };
DA_INFO_T Da_Info;

spdio_t* spdio_init(int flags) {
	uint8_t* p; spdio_t* io;

	p = (uint8_t*)malloc(sizeof(spdio_t) + RECV_BUF_LEN + (4 + 0x10000 + 2) * 3 + 2);
	io = (spdio_t*)p;
	if (!p) ERR_EXIT("malloc failed\n");
	memset(io, 0, sizeof(spdio_t));
	p += sizeof(spdio_t);
	io->flags = flags;
	io->recv_len = 0;
	io->recv_pos = 0;
	io->recv_buf = p; p += RECV_BUF_LEN;
	io->temp_buf = p + 4;
	io->raw_buf = p; p += 4 + 0x10000 + 2;
	io->enc_buf = p;
	io->verbose = 0;
	io->timeout = 1000;
	memset(io->recv_buf, 0, 8);
	return io;
}

void spdio_free(spdio_t* io) {
	if (!io) return;
#if _WIN32
	PostThreadMessage(io->iThread, THRD_MESSAGE_EXIT, 0, 0);
	WaitForSingleObject(io->hThread, INFINITE);
	CloseHandle(io->hThread);
#endif
#if USE_LIBUSB
	libusb_close(io->dev_handle);
	libusb_exit(NULL);
#else
	call_DisconnectChannel(io->handle);
	call_Uninitialize(io->handle);
	destroyClass(io->handle);
#endif
	free(io);
}

int spd_transcode(uint8_t* dst, uint8_t* src, int len) {
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

int spd_transcode_max(uint8_t* src, int len, int n) {
	int i, a;
	for (i = 0; i < len; i++) {
		a = src[i];
		a = a == HDLC_HEADER || a == HDLC_ESCAPE ? 2 : 1;
		if (n < a) break;
		n -= a;
	}
	return i;
}

unsigned spd_crc16(unsigned crc, const void* src, unsigned len) {
	uint8_t* s = (uint8_t*)src; int i;
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

unsigned spd_checksum(unsigned crc, const void* src, int len, int final) {
	uint8_t* s = (uint8_t*)src;

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

void encode_msg(spdio_t* io, int type, const void* data, size_t len) {
	uint8_t* p, * p0; unsigned chk;

	if (len > 0xffff)
		ERR_EXIT("message too long\n");

	if (type == BSL_CMD_CHECK_BAUD) {
		memset(io->enc_buf, HDLC_HEADER, len);
		io->enc_len = len;
		*(uint8_t*)(io->raw_buf) = HDLC_HEADER;
		return;
	}

	p = p0 = io->raw_buf;
	WRITE16_BE(p, type); p += 2;
	WRITE16_BE(p, len); p += 2;
	memcpy(p, data, len); p += len;

	len = p - p0;
	if (io->flags & FLAGS_CRC16)
		chk = spd_crc16(0, p0, len);
	else {
		// if (len & 1) *p++ = 0;
		chk = spd_checksum(0, p0, len, CHK_FIXZERO);
	}
	WRITE16_BE(p, chk); p += 2;

	io->raw_len = len = p - p0;

	p = io->enc_buf;
	*p++ = HDLC_HEADER;
	if (io->flags & FLAGS_TRANSCODE)
		len = spd_transcode(p, p0, len);
	else memcpy(p, p0, len);
	p[len] = HDLC_HEADER;
	io->enc_len = len + 2;
}

int send_msg(spdio_t* io) {
	int ret;
	if (!io->enc_len)
		ERR_EXIT("empty message\n");

#if _WIN32
	if (m_bOpened == -1) {
		spdio_free(io);
		ERR_EXIT("device removed, exiting...\n");
	}
#endif
	if (io->verbose >= 2) {
		DBG_LOG("send (%d):\n", io->enc_len);
		print_mem(stderr, io->enc_buf, io->enc_len);
	}
	else if (io->verbose >= 1) {
		if (io->raw_buf[0] == HDLC_HEADER)
			DBG_LOG("send: check baud\n");
		else if (io->raw_len >= 4) {
			DBG_LOG("send: type = 0x%02x, size = %d\n",
				READ16_BE(io->raw_buf), READ16_BE(io->raw_buf + 2));
		}
		else DBG_LOG("send: unknown message\n");
	}

#if USE_LIBUSB
	{
		int err = libusb_bulk_transfer(io->dev_handle,
			io->endp_out, io->enc_buf, io->enc_len, &ret, io->timeout);
		if (err < 0)
			ERR_EXIT("usb_send failed : %s\n", libusb_error_name(err));
	}
#else
	ret = call_Write(io->handle, io->enc_buf, io->enc_len);
#endif
	if (ret != io->enc_len)
		ERR_EXIT("usb_send failed (%d / %d)\n", ret, io->enc_len);

	return ret;
}

extern int fdl1_loaded;
int recv_msg_orig(spdio_t* io) {
	int a, pos, len, chk;
	int esc = 0, nread = 0, head_found = 0, plen = 6;

	len = io->recv_len;
	pos = io->recv_pos;
	memset(io->recv_buf, 0, 8);
	for (;;) {
		if (pos >= len) {
#if _WIN32
			if (m_bOpened == -1) {
				spdio_free(io);
				ERR_EXIT("device removed, exiting...\n");
			}
#endif
#if USE_LIBUSB
			int err = libusb_bulk_transfer(io->dev_handle, io->endp_in, io->recv_buf, RECV_BUF_LEN, &len, io->timeout);
			if (err == LIBUSB_ERROR_NO_DEVICE)
				ERR_EXIT("connection closed\n");
			else if (err < 0)
			{ DBG_LOG("usb_recv failed : %s\n", libusb_error_name(err)); return 0; }
#else
			len = call_Read(io->handle, io->recv_buf, RECV_BUF_LEN, io->timeout);
#endif
			if (len < 0)
			{ DBG_LOG("usb_recv failed, ret = %d\n", len); return 0; }

			if (io->verbose >= 2) {
				DBG_LOG("recv (%d):\n", len);
				print_mem(stderr, io->recv_buf, len);
			}
			pos = 0;
			if (!len) break;
		}
		a = io->recv_buf[pos++];
		if (io->flags & FLAGS_TRANSCODE) {
			if (esc && a != (HDLC_HEADER ^ 0x20) &&
				a != (HDLC_ESCAPE ^ 0x20))
			{ DBG_LOG("unexpected escaped byte (0x%02x)\n", a); return 0; }
			if (a == HDLC_HEADER) {
				if (!head_found) head_found = 1;
				else if (!nread) continue;
				else if (nread < plen)
				{ DBG_LOG("recieved message too short\n"); return 0; }
				else break;
			}
			else if (a == HDLC_ESCAPE) {
				esc = 0x20;
			}
			else {
				if (!head_found) continue;
				if (nread >= plen)
				{ DBG_LOG("recieved message too long\n"); return 0; }
				io->raw_buf[nread++] = a ^ esc;
				esc = 0;
			}
		}
		else {
			if (!head_found && a == HDLC_HEADER) {
				head_found = 1;
				continue;
			}
			if (nread == plen) {
				if (a != HDLC_HEADER)
				{ DBG_LOG("expected end of message\n"); return 0; }
				break;
			}
			io->raw_buf[nread++] = a;
		}
		if (nread == 4) {
			a = READ16_BE(io->raw_buf + 2);	// len
			plen = a + 6;
		}
	}
	io->recv_len = len;
	io->recv_pos = pos;
	io->raw_len = nread;
	if (!nread) return 0;

	if (nread < 6)
	{ DBG_LOG("recieved message too short\n"); return 0; }

	if (nread != plen)
	{ DBG_LOG("bad length (%d, expected %d)\n", nread, plen); return 0; }

	a = READ16_BE(io->raw_buf + plen - 2);
	if (fdl1_loaded == 0 && !(io->flags & FLAGS_CRC16))
	{		
		int chk1, chk2;
		chk1 = spd_crc16(0, io->raw_buf, plen - 2);
		if (a == chk1) io->flags |= FLAGS_CRC16;
		else
		{
			chk2 = spd_checksum(0, io->raw_buf, plen - 2, CHK_ORIG);
			if (a == chk2) fdl1_loaded = 1;
			else
			{
				DBG_LOG("bad checksum (0x%04x, expected 0x%04x or 0x%04x)\n", a, chk1, chk2);
				return 0;
			}
		}
	}
	else
	{
		if (io->flags & FLAGS_CRC16)
			chk = spd_crc16(0, io->raw_buf, plen - 2);
		else
			chk = spd_checksum(0, io->raw_buf, plen - 2, CHK_ORIG);
		if (a != chk)
		{
			DBG_LOG("bad checksum (0x%04x, expected 0x%04x)\n", a, chk);
			return 0;
		}
	}

	if (io->verbose == 1)
		DBG_LOG("recv: type = 0x%02x, size = %d\n",
			READ16_BE(io->raw_buf), READ16_BE(io->raw_buf + 2));

	return nread;
}

extern int fdl2_executed;
int recv_msg(spdio_t* io) {
	int ret;
	for (;;) {
		ret = recv_msg_orig(io);
		// only retry in fdl2 stage
		if (!ret) {
			if (fdl2_executed) {
#if !USE_LIBUSB
				if (io->raw_len) call_Clear(io->handle); //io->raw_len = nread in recv_msg_orig()
#endif
				send_msg(io);
				ret = recv_msg_orig(io);
				if (!ret) break;
			}
			else break;
		}
		if (recv_type(io) != BSL_REP_LOG) break;
		DBG_LOG("BSL_REP_LOG: ");
		print_string(stderr, io->raw_buf + 4, READ16_BE(io->raw_buf + 2));
	}
	return ret;
}

int recv_msg_timeout(spdio_t* io, int timeout) {
	int old = io->timeout, ret;
	io->timeout = old > timeout ? old : timeout;
	ret = recv_msg(io);
	io->timeout = old;
	return ret;
}

unsigned recv_type(spdio_t* io) {
	//if (io->raw_len < 6) return -1;
	return READ16_BE(io->raw_buf);
}

int send_and_check(spdio_t* io) {
	int ret;
	send_msg(io);
	ret = recv_msg(io);
	if (!ret) ERR_EXIT("timeout reached\n");
	ret = recv_type(io);
	if (ret != BSL_REP_ACK) {
		DBG_LOG("unexpected response (0x%04x)\n", ret);
		return -1;
	}
	return 0;
}

int check_confirm(const char* name) {
	char c;
	DBG_LOG("Answer \"y\" to confirm the \"%s\" command: ", name);
	fflush(stdout);
	if (scanf(" %c", &c) != 1) return 0;
	while (getchar() != '\n');
	if (tolower(c) == 'y') return 1;
	return 0;
}

uint8_t* loadfile(const char* fn, size_t* num, size_t extra) {
	size_t n, j = 0; uint8_t* buf = 0;
	FILE* fi = fopen(fn, "rb");
	if (fi) {
		fseek(fi, 0, SEEK_END);
		n = ftell(fi);
		if (n) {
			fseek(fi, 0, SEEK_SET);
			buf = (uint8_t*)malloc(n + extra);
			if (buf) j = fread(buf, 1, n, fi);
		}
		fclose(fi);
	}
	if (num) *num = j;
	return buf;
}

void send_file(spdio_t* io, const char* fn,
	uint32_t start_addr, int end_data, unsigned step) {
	uint8_t* mem; size_t size = 0;
	uint32_t data[2], i, n;

	mem = loadfile(fn, &size, 0);
	if (!mem) ERR_EXIT("loadfile(\"%s\") failed\n", fn);
	if ((uint64_t)size >> 32) ERR_EXIT("file too big\n");

	WRITE32_BE(data, start_addr);
	WRITE32_BE(data + 1, size);

	encode_msg(io, BSL_CMD_START_DATA, data, 4 * 2);
	if (send_and_check(io)) { free(mem); return; }

	for (i = 0; i < size; i += n) {
		n = size - i;
		// n = spd_transcode_max(mem + i, size - i, 2048 - 2 - 6);
		if (n > step) n = step;
		encode_msg(io, BSL_CMD_MIDST_DATA, mem + i, n);
		if (send_and_check(io)) { free(mem); return; }
	}
	free(mem);

	if (end_data) {
		encode_msg(io, BSL_CMD_END_DATA, NULL, 0);
		send_and_check(io);
	}
	DBG_LOG("SEND %s to 0x%x\n", fn, start_addr);
}

unsigned dump_flash(spdio_t* io,
	uint32_t addr, uint32_t start, uint32_t len,
	const char* fn, unsigned step) {
	uint32_t n, offset, nread;
	int ret;
	FILE* fo;
	if (savepath[0]) {
		char fix_fn[1024];
		sprintf(fix_fn, "%s/%s", savepath, fn);
		fo = fopen(fix_fn, "wb");
	}
	else fo = fopen(fn, "wb");
	if (!fo) ERR_EXIT("fopen(dump) failed\n");

	for (offset = start; offset < start + len; ) {
		uint32_t data[3];
		n = start + len - offset;
		if (n > step) n = step;

		WRITE32_BE(data, addr);
		WRITE32_BE(data + 1, n);
		WRITE32_BE(data + 2, offset);

		encode_msg(io, BSL_CMD_READ_FLASH, data, 4 * 3);
		send_msg(io);
		ret = recv_msg(io);
		if (!ret) ERR_EXIT("timeout reached\n");
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

unsigned dump_mem(spdio_t* io,
	uint32_t start, uint32_t len, const char* fn, unsigned step) {
	uint32_t n, offset, nread;
	int ret;
	FILE* fo;
	if (savepath[0]) {
		char fix_fn[2048];
		sprintf(fix_fn, "%s/%s", savepath, fn);
		fo = fopen(fix_fn, "wb");
	}
	else fo = fopen(fn, "wb");
	if (!fo) ERR_EXIT("fopen(dump) failed\n");

	for (offset = start; offset < start + len; ) {
		uint32_t data[3];
		n = start + len - offset;
		if (n > step) n = step;

		WRITE32_BE(data, offset);
		WRITE32_BE(data + 1, n);
		WRITE32_BE(data + 2, 0);	// unused

		encode_msg(io, BSL_CMD_READ_FLASH, data, sizeof(data));
		send_msg(io);
		ret = recv_msg(io);
		if (!ret) ERR_EXIT("timeout reached\n");
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

int copy_to_wstr(uint16_t* d, size_t n, const char* s) {
	size_t i; int a = -1;
	for (i = 0; a && i < n; i++) { a = s[i]; WRITE16_LE(d + i, a); }
	return a;
}

int copy_from_wstr(char* d, size_t n, const uint16_t* s) {
	size_t i; int a = -1;
	for (i = 0; a && i < n; i++) { d[i] = a = s[i]; if (a >> 8) break; }
	return a;
}

void select_partition(spdio_t* io, const char* name,
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

void print_progress_bar(float progress) {
	static int completed0 = 0;
	if (completed0 == PROGRESS_BAR_WIDTH) completed0 = 0;
	int completed = (int)(PROGRESS_BAR_WIDTH * progress);
	int remaining;
	if (completed != completed0)
	{
		remaining = PROGRESS_BAR_WIDTH - completed;
		DBG_LOG("[");
		for (int i = 0; i < completed; i++) {
			DBG_LOG("=");
		}
		for (int i = 0; i < remaining; i++) {
			DBG_LOG(" ");
		}
		DBG_LOG("] %.1f%%\n", 100 * progress);
	}
	completed0 = completed;
}

extern uint64_t fblk_size;
uint64_t dump_partition(spdio_t* io,
	const char* name, uint64_t start, uint64_t len,
	const char* fn, unsigned step) {
	uint32_t n, nread, t32; uint64_t offset, n64, saved_size = 0;
	int ret, mode64 = (start + len) >> 32;
	FILE* fo;
	if (!memcmp(name, "userdata", 8)) { if (!check_confirm("read userdata")) return 0; }
	else if (strstr(name, "nv1") || strstr(name, "nv2"))
	{
		char* name_tmp = malloc(strlen(name) + 1);
		if (name_tmp == NULL) return 0;
		sprintf(name_tmp, "%s", name);
		char* dot = strrchr(name_tmp, '1');
		if (dot != NULL) *dot = '2';
		select_partition(io, name_tmp, 8, 0, BSL_CMD_READ_START);
		free(name_tmp);
		if (send_and_check(io)) return 0;

		uint32_t data[2] = { 8,0 };
		encode_msg(io, BSL_CMD_READ_MIDST, data, 8);
		send_msg(io);
		ret = recv_msg(io);
		if (!ret) ERR_EXIT("timeout reached\n");
		if (recv_type(io) != BSL_REP_READ_FLASH) return 0;
		if (*(uint32_t*)(io->raw_buf + 4) == 0x00004e56)
		{
			if (dot != NULL) len = *(uint32_t*)(io->raw_buf + 8);
			else len = 0x200 + *(uint32_t*)(io->raw_buf + 8);
			DBG_LOG("nv length: 0x%llx\n", (long long)len);
		}
		encode_msg(io, BSL_CMD_READ_END, NULL, 0);
		send_and_check(io);
	}

	select_partition(io, name, start + len, mode64, BSL_CMD_READ_START);
	if (send_and_check(io)) return 0;

	if (savepath[0]) {
		char fix_fn[2048];
		sprintf(fix_fn, "%s/%s", savepath, fn);
		fo = fopen(fix_fn, "wb");
	}
	else fo = fopen(fn, "wb");
	if (!fo) ERR_EXIT("fopen(dump) failed\n");

	for (offset = start; (n64 = start + len - offset); ) {
		uint32_t data[3];
		n = (uint32_t)(n64 > step ? step : n64);

		WRITE32_LE(data, n);
		WRITE32_LE(data + 1, offset);
		t32 = offset >> 32;
		WRITE32_LE(data + 2, t32);

		encode_msg(io, BSL_CMD_READ_MIDST, data, mode64 ? 12 : 8);
		send_msg(io);
		ret = recv_msg(io);
		if (!ret) ERR_EXIT("timeout reached\n");
		if ((ret = recv_type(io)) != BSL_REP_READ_FLASH) {
			DBG_LOG("unexpected response (0x%04x)\n", ret);
			break;
		}
		nread = READ16_BE(io->raw_buf + 2);
		if (n < nread)
			ERR_EXIT("unexpected length\n");
		if (fwrite(io->raw_buf + 4, 1, nread, fo) != nread)
			ERR_EXIT("fwrite(dump) failed\n");
		print_progress_bar((offset + nread - start) / (float)len);
		offset += nread;
		if (n != nread) break;

		if (fblk_size) {
			saved_size += nread;
			if (saved_size >= fblk_size) { usleep(1000000); saved_size = 0; }
		}
	}
	DBG_LOG("Read Part Done: %s+0x%llx, target: 0x%llx, read: 0x%llx\n",
		name, (long long)start, (long long)len,
		(long long)(offset - start));
	fclose(fo);

	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);
	return offset;
}

uint64_t read_pactime(spdio_t* io) {
	uint32_t n, offset = 0x81400, len = 8;
	int ret; uint32_t data[2];
	unsigned long long time, unix;

	select_partition(io, "miscdata", offset + len, 0, BSL_CMD_READ_START);
	if (send_and_check(io)) return 0;

	WRITE32_LE(data, len);
	WRITE32_LE(data + 1, offset);
	encode_msg(io, BSL_CMD_READ_MIDST, data, sizeof(data));
	send_msg(io);
	ret = recv_msg(io);
	if (!ret) ERR_EXIT("timeout reached\n");
	if ((ret = recv_type(io)) != BSL_REP_READ_FLASH)
		ERR_EXIT("unexpected response (0x%04x)\n", ret);
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

int scan_xml_partitions(const char* fn, uint8_t* buf, size_t buf_size) {
	const char* part1 = "Partitions>";
	char* src, * p, name[36]; size_t size = 0;
	int part1_len = strlen(part1), found = 0, stage = 0;
	src = (char*)loadfile(fn, &size, 1);
	if (!src) ERR_EXIT("loadfile failed\n");
	src[size] = 0;
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
		i = sscanf(p, "Partition id=\"%35[^\"]\" size=\"%lli\"/%n%c", name, &size, &n, &c);
		if (i != 3 || c != '>')
			ERR_EXIT("xml: unexpected syntax\n");
		p += n + 1;
		if (buf_size < 0x4c)
			ERR_EXIT("xml: too many partitions\n");
		buf_size -= 0x4c;
		memset(buf, 0, 36 * 2);
		for (i = 0; (a = name[i]); i++) buf[i * 2] = a;
		if (!i) ERR_EXIT("empty partition name\n");
		WRITE32_LE(buf + 0x48, size);
		buf += 0x4c;
		DBG_LOG("[%d] %s, %d\n", found, name, (int)size);
		found++;
	}
	if (p - 1 != src + size) ERR_EXIT("xml: zero byte");
	if (stage != 2) ERR_EXIT("xml: unexpected syntax\n");
	free(src);
	return found;
}

#define SECTOR_SIZE 512
#define MAX_SECTORS 32

extern int selected_ab;
int gpt_info(partition_t* ptable, const char* fn_xml, int* part_count_ptr) {
	FILE* fp;
	if (savepath[0]) {
		char fix_fn[1024];
		sprintf(fix_fn, "%s/pgpt.bin", savepath);
		fp = fopen(fix_fn, "rb");
	}
	else fp = fopen("pgpt.bin", "rb");
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
	efi_entry* entries = malloc(header.number_of_partition_entries * sizeof(efi_entry));
	if (entries == NULL) {
		fclose(fp);
		return -1;
	}
	fseek(fp, (long)header.partition_entry_lba * real_SECTOR_SIZE, SEEK_SET);
	bytes_read = fread(entries, 1, header.number_of_partition_entries * sizeof(efi_entry), fp);
	if (bytes_read != (int)(header.number_of_partition_entries * sizeof(efi_entry)))
		DBG_LOG("only read %d/%d\n", bytes_read, (int)(header.number_of_partition_entries * sizeof(efi_entry)));
	FILE* fo = NULL;
	if (strcmp(fn_xml, "-")) {
		fo = fopen(fn_xml, "wb");
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
		copy_from_wstr((*(ptable + i)).name, 36, (uint16_t*)entry.partition_name);
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
partition_t* partition_list(spdio_t* io, const char* fn, int* part_count_ptr) {
	long size;
	unsigned i, n = 0;
	int ret; FILE* fo = NULL; uint8_t* p;
	partition_t* ptable = malloc(128 * sizeof(partition_t));
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
		send_msg(io);
		ret = recv_msg(io);
		if (!ret) ERR_EXIT("timeout reached\n");
		ret = recv_type(io);
		if (ret != BSL_REP_READ_PARTITION){
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
		FILE* fpkt;
		if (savepath[0]) {
			char fix_fn[1024];
			sprintf(fix_fn, "%s/sprdpart.bin", savepath);
			fpkt = fopen(fix_fn, "wb");
		}
		else fpkt = fopen("sprdpart.bin", "wb");
		if (!fpkt) ERR_EXIT("fopen failed\n");
		fwrite(io->raw_buf + 4, 1, size, fpkt);
		fclose(fpkt);
		n = size / 0x4c;
		if (strcmp(fn, "-")) {
			fo = fopen(fn, "wb");
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
			ret = copy_from_wstr((*(ptable + i)).name, 36, (uint16_t*)p);
			if (ret) ERR_EXIT("bad partition name\n");
			size = READ32_LE(p + 0x48);
			(*(ptable + i)).size = (size << 20) >> divisor;
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

void repartition(spdio_t* io, const char* fn) {
	uint8_t* buf = io->temp_buf;
	int n = scan_xml_partitions(fn, buf, 0xffff);
	// print_mem(stderr, io->temp_buf, n * 0x4c);
	encode_msg(io, BSL_CMD_REPARTITION, buf, n * 0x4c);
	send_and_check(io);
}

void erase_partition(spdio_t* io, const char* name) {
	if (!memcmp(name, "userdata", 8)) select_partition(io, name, 1048576, 0, BSL_CMD_ERASE_FLASH);
	else select_partition(io, name, 0, 0, BSL_CMD_ERASE_FLASH);
	send_and_check(io);
}

void load_partition(spdio_t* io, const char* name,
	const char* fn, unsigned step) {
	uint64_t offset, len, n64;
	unsigned mode64, n; int ret;
	FILE* fi;

	if (strstr(name, "runtimenv")) { erase_partition(io, name); return; }
	if (!strcmp(name, "calinv")) { return; } //skip calinv

	fi = fopen(fn, "rb");
	if (!fi) ERR_EXIT("fopen(load) failed\n");

	uint8_t header[4], is_simg = 0;
	if (fread(header, 1, 4, fi) != 4)
		ERR_EXIT("fread(load) failed\n");
	if (0xED26FF3A == *(uint32_t*)header) is_simg = 1;
	fseeko(fi, 0, SEEK_END);
	len = ftello(fi);
	fseek(fi, 0, SEEK_SET);
	DBG_LOG("file size : 0x%llx\n", (long long)len);

	mode64 = len >> 32;
	select_partition(io, name, len, mode64, BSL_CMD_START_DATA);
	if (send_and_check(io)) { fclose(fi); return; }

#if !USE_LIBUSB
	if (Da_Info.bSupportRawData == 2) {
		encode_msg(io, BSL_CMD_DLOAD_RAW_START2, NULL, 0);
		if (send_and_check(io)) { Da_Info.bSupportRawData = 0; goto fallback_load; }
		step = Da_Info.dwFlushSize << 10;
		uint8_t* rawbuf = (uint8_t*)malloc(step + 1);
		if (!rawbuf) ERR_EXIT("malloc failed\n");

		for (offset = 0; (n64 = len - offset); offset += n) {
			n = (unsigned)(n64 > step ? step : n64);
#if _WIN32
			if (m_bOpened == -1) {
				spdio_free(io);
				ERR_EXIT("device removed, exiting...\n");
			}
#endif
			if (fread(rawbuf, 1, n, fi) != n)
				ERR_EXIT("fread(load) failed\n");
//#if USE_LIBUSB
//			int err = libusb_bulk_transfer(io->dev_handle,
//				io->endp_out, rawbuf, n, &ret, io->timeout);
//			if (err < 0)
//				ERR_EXIT("usb_send failed : %s\n", libusb_error_name(err));
//#else
			ret = call_Write(io->handle, rawbuf, n);
//#endif
			if (io->verbose >= 1) DBG_LOG("send (%d)\n", n);
			if (ret != (int)n)
				ERR_EXIT("usb_send failed (%d / %d)\n", ret, n);
			if (is_simg) ret = recv_msg_timeout(io, 100000);
			else ret = recv_msg_timeout(io, 15000);
			if (!ret) {
				if(n == n64) ERR_EXIT("signature verification of \"%s\" failed or timeout reached\n", name);
				else ERR_EXIT("timeout reached\n"); 
			}
			if ((ret = recv_type(io)) != BSL_REP_ACK) {
				DBG_LOG("unexpected response (0x%04x)\n", ret);
				break;
			}
			print_progress_bar((offset + n) / (float)len);
		}
		free(rawbuf);
	} else {
#endif
		fallback_load:
		for (offset = 0; (n64 = len - offset); offset += n) {
			n = (unsigned)(n64 > step ? step : n64);
			if (fread(io->temp_buf, 1, n, fi) != n)
				ERR_EXIT("fread(load) failed\n");
			encode_msg(io, BSL_CMD_MIDST_DATA, io->temp_buf, n);
			send_msg(io);
			if (is_simg) ret = recv_msg_timeout(io, 100000);
			else ret = recv_msg_timeout(io, 15000);
			if (!ret) {
				if (n == n64) ERR_EXIT("signature verification of \"%s\" failed or timeout reached\n", name);
				else ERR_EXIT("timeout reached\n");
			}
			if ((ret = recv_type(io)) != BSL_REP_ACK) {
				DBG_LOG("unexpected response (0x%04x)\n", ret);
				break;
			}
			print_progress_bar((offset + n) / (float)len);
		}
#if !USE_LIBUSB
	}
#endif
	fclose(fi);
	encode_msg(io, BSL_CMD_END_DATA, NULL, 0);
	if(!send_and_check(io)) DBG_LOG("Write Part Done: %s, target: 0x%llx, written: 0x%llx\n",
		name, (long long)len, (long long)offset);
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

unsigned short crc16(unsigned short crc, unsigned char const* buffer, unsigned int len)
{
	while (len--)
		crc = (unsigned short)((crc >> 8) ^ (crc16_table[(crc ^ (*buffer++)) & 0xff]));
	return crc;
}

void load_nv_partition(spdio_t* io, const char* name,
	const char* fn, unsigned step) {
	size_t offset, rsz;
	unsigned n; int ret;
	size_t len = 0;
	uint8_t* mem;
	uint16_t crc = 0;
	uint32_t cs = 0;

	mem = loadfile(fn, &len, 0);
	if (!mem) ERR_EXIT("loadfile(\"%s\") failed\n", fn);

	size_t memOffset = 0;
	uint8_t* output = (uint8_t*)malloc(len);
	if (!output) ERR_EXIT("malloc failed\n");
	if (*(uint32_t*)mem == 0x4e56) { memOffset = 0x200; len -= 0x200; }
	if (strstr(name, "fix"))
	{
		len = 0;
		len += sizeof(uint32_t);

		uint16_t tmp[2];
		while (1)
		{
			tmp[0] = 0;
			tmp[1] = 0;
			memcpy(tmp, mem + memOffset + len, sizeof(tmp));
			len += sizeof(tmp);
			len += tmp[1];

			uint32_t doffset = ((len + 3) & 0xFFFFFFFC) - len;
			len += doffset;
			if (*(uint16_t*)(mem + memOffset + len) == 0xffff) {
				len += 8;
				break;
			}
		}
		crc = crc16(crc, mem + memOffset + 2, len - 2);
		WRITE16_BE(mem, crc);
	}
	memcpy(output, mem + memOffset, len);
	free(mem);
	mem = output;
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
	if (send_and_check(io)) { free(mem); return; }

	for (offset = 0; (rsz = len - offset); offset += n) {
		n = rsz > step ? step : rsz;
		memcpy(io->temp_buf, &mem[offset], n);
		encode_msg(io, BSL_CMD_MIDST_DATA, io->temp_buf, n);
		send_msg(io);
		ret = recv_msg_timeout(io, 15000);
		if (!ret) ERR_EXIT("timeout reached\n");
		if ((ret = recv_type(io)) != BSL_REP_ACK) {
			DBG_LOG("unexpected response (0x%04x)\n", ret);
			break;
		}
	}
	free(mem);
	encode_msg(io, BSL_CMD_END_DATA, NULL, 0);
	if(!send_and_check(io)) DBG_LOG("Write NV_Part Done: %s, target: 0x%llx, written: 0x%llx\n",
		name, (long long)len, (long long)offset);
}

void find_partition_size_new(spdio_t* io, const char* name, unsigned long long *offset_ptr) {
	int ret;
	char* name_tmp = malloc(strlen(name) + 5 + 1);
	if (name_tmp == NULL) return;
	sprintf(name_tmp, "%s_size", name);
	select_partition(io, name_tmp, 0x80, 0, BSL_CMD_READ_START);
	free(name_tmp);
	if (send_and_check(io)) return;

	uint32_t data[2] = { 0x80,0 };
	encode_msg(io, BSL_CMD_READ_MIDST, data, 8);
	send_msg(io);
	ret = recv_msg(io);
	if (!ret) ERR_EXIT("timeout reached\n");
	if (recv_type(io) == BSL_REP_READ_FLASH) {
		ret = sscanf((char *)(io->raw_buf + 4), "size:%*[^:]: 0x%llx", offset_ptr);
		DBG_LOG("partition_size_device: %s, 0x%llx\n", name, *offset_ptr);
	}
	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);
}

uint64_t find_partition_size(spdio_t* io, const char* name) {
	uint32_t t32; uint64_t n64; unsigned long long offset = 0;
	int ret, i, end = 20;

	if (selected_ab > 0 && strcmp(name, "uboot") == 0) return 0;
	if (strstr(name, "fixnv")) {
		if (selected_ab > 0) {
			size_t namelen = strlen(name);
			if (0 == strcmp(name + namelen - 2, "_a") || 0 == strcmp(name + namelen - 2, "_b")) return 1;
			return 0;
		}
		return 1;
	}
	else if (strstr(name, "runtimenv")) return 1;
	if (selected_ab > 0) {
		find_partition_size_new(io, name, &offset);
		if (offset) return offset;
	}

	if (!strcmp(name, "ubipac")) end = 10;
	select_partition(io, name, 128 * 1024, 0, BSL_CMD_READ_START);
	if (send_and_check(io)) return 0;

	int incrementing = 1;
	for (i = end; i >= end;) {
		uint32_t data[3];
		n64 = offset + (1ll << i) - (1ll << end);
		WRITE32_LE(data, 4);
		WRITE32_LE(data + 1, n64);
		t32 = n64 >> 32;
		WRITE32_LE(data + 2, t32);

		encode_msg(io, BSL_CMD_READ_MIDST, data, sizeof(data));
		send_msg(io);
		ret = recv_msg(io);
		if (!ret) ERR_EXIT("timeout reached\n");
		ret = recv_type(io);
		if (incrementing) {
			if (ret != BSL_REP_READ_FLASH) {
				if (!n64) break;
				offset += 1ll << (i - 1);
				i -= 2;
				incrementing = 0;
			}
			else if (i == 10) i += 11;
			else i++;
		}
		else {
			if (ret == BSL_REP_READ_FLASH) offset += (1ll << i);
			i--;
		}
	}
	DBG_LOG("partition_size_pc: %s, 0x%llx\n", name, offset);
	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);
	return offset;
}

int check_partition(spdio_t* io, const char* name) {
	int ret;

	if (selected_ab > 0 && strcmp(name, "uboot") == 0) return 0;
	if (strstr(name, "fixnv")) {
		if (selected_ab > 0) {
			size_t namelen = strlen(name);
			if (0 == strcmp(name + namelen - 2, "_a") || 0 == strcmp(name + namelen - 2, "_b")) return 1;
			return 0;
		}
		return 1;
	}
	else if (strstr(name, "runtimenv")) return 1;

	select_partition(io, name, 0x8, 0, BSL_CMD_READ_START);
	if (send_and_check(io)) return 0;

	uint32_t data[2] = { 0x8,0 };
	encode_msg(io, BSL_CMD_READ_MIDST, data, 8);
	send_msg(io);
	ret = recv_msg(io);
	if (!ret) ERR_EXIT("timeout reached\n");
	if (recv_type(io) == BSL_REP_READ_FLASH) ret = 1;
	else ret = 0;
	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);

	return ret;
}

uint64_t str_to_size(const char* str) {
	char* end; int shl = 0; uint64_t n;
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

uint64_t str_to_size_ubi(const char* str, int* nand_info) {
	if (memcmp(str, "ubi", 3)) return str_to_size(str);
	else {
		char* end;
		uint64_t n;
		n = strtoull(&str[3], &end, 0);
		if (*end) {
			char suffix = tolower(*end);
			if (suffix == 'm')
			{
				int block = (int)(n * (1024 / nand_info[2]) + n * (1024 / nand_info[2]) / (512 / nand_info[1]) + 1);
				return 1024 * (nand_info[2] - 2 * nand_info[0]) * block;
			}
			else
			{
				DBG_LOG("only support mb as unit, will not treat kb/gb as ubi size\n");
				return str_to_size(&str[3]);
			}
		}
		else return n;
	}
}

void dump_partitions(spdio_t* io, const char* fn, int* nand_info, int blk_size) {
	const char* part1 = "Partitions>";
	char* src, * p;
	int part1_len = strlen(part1), found = 0, stage = 0, ubi = 0;
	size_t size = 0;
	partition_t* partitions = malloc(128 * sizeof(partition_t));
	if (partitions == NULL) return;

	if (!memcmp(fn, "ubi", 3)) ubi = 1;
	src = (char*)loadfile(fn, &size, 1);
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

	int verbose = io->verbose;
	if (selected_ab < 0) select_ab(io);
	for (int i = 0; i < found; i++) {
		DBG_LOG("Partition %d: name=%s, size=%llim\n", i + 1, partitions[i].name, partitions[i].size);
		if (!memcmp(partitions[i].name, "userdata", 8)) continue;

		char* pn = partitions[i].name;
		uint64_t realsize = 0;
		char name_ab[36];
		io->verbose = 0;
		realsize = check_partition(io, pn);
		if (!realsize) {
			if (selected_ab > 0) {
				snprintf(name_ab, sizeof(name_ab), "%s_%c", pn, 96 + selected_ab);
				realsize = check_partition(io, name_ab);
				pn = name_ab;
			}
			if (!realsize) {
				DBG_LOG("part not exist\n");
				io->verbose = verbose;
				continue;
			}
		}
		io->verbose = verbose;
				
		if (!memcmp(partitions[i].name, "splloader",9)) realsize = 256 * 1024;
		else if (0xffffffff == partitions[i].size) realsize = find_partition_size(io, pn);
		else if (ubi) {
			int block = (int)(partitions[i].size * (1024 / nand_info[2]) + partitions[i].size * (1024 / nand_info[2]) / (512 / nand_info[1]) + 1);
			realsize = 1024 * (nand_info[2] - 2 * nand_info[0]) * block;
		}
		else realsize = partitions[i].size << 20;

		char dfile[40];
		snprintf(dfile, sizeof(dfile), "%s.bin", partitions[i].name);
		dump_partition(io, pn, 0, realsize, dfile, blk_size);
	}

	if (savepath[0]) {
		DBG_LOG("saving dump list\n");
		char fix_fn[1024];
		char* ch;
		if ((ch = strrchr(fn, '/'))) sprintf(fix_fn, "%s/%s", savepath, ch + 1);
		else if ((ch = strrchr(fn, '\\'))) sprintf(fix_fn, "%s/%s", savepath, ch + 1);
		else sprintf(fix_fn, "%s/%s", savepath, fn);
		FILE* fo = fopen(fix_fn, "wb");
		if (fo) { fwrite(src, 1, size, fo); fclose(fo); }
		else DBG_LOG("create dump list failed, skipping.\n");
	}
	free(src);
	free(partitions);
}

void load_partitions(spdio_t* io, const char* path, int blk_size) {
	typedef struct {
		char name[36];
		char file_path[1024];
		int written_flag;
	} partition_info_t;

	int partition_count = 0;
	partition_info_t* partitions = malloc(128 * sizeof(partition_info_t));
	if (partitions == NULL) return;
	char* fn;
#if _WIN32
	char searchPath[ARGV_LEN];
	snprintf(searchPath, ARGV_LEN, "%s\\*", path);

	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(searchPath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		DBG_LOG("Error opening directory.\n");
		return;
	}
	for (fn = findData.cFileName; FindNextFileA(hFind, &findData); fn = findData.cFileName)
	{
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
#else
	DIR* dir;
	struct dirent* entry;

	if ((dir = opendir(path)) == NULL || (entry = readdir(dir)) == NULL) {
		DBG_LOG("Error opening directory.\n");
		return;
	}
	for (fn = entry->d_name; (entry = readdir(dir)); fn = entry->d_name)
	{
		if (entry->d_type == DT_DIR) continue;
#endif
		size_t len = strlen(fn);
		if (len >= 4 && strcmp(fn + len - 4, ".xml") == 0) continue;
		if (!memcmp(fn, "pgpt", 4) || !memcmp(fn, "sprdpart", 8)) continue;

		snprintf(partitions[partition_count].file_path, sizeof(partitions[partition_count].file_path), "%s/%s", path, fn);
		char* dot = strrchr(fn, '.');
		if (dot != NULL) *dot = '\0';

		snprintf(partitions[partition_count].name, sizeof(partitions[partition_count].name), "%s", fn);
		partitions[partition_count].written_flag = 0;
		partition_count++;
	}
#if _WIN32
	FindClose(hFind);
#else
	closedir(dir);
#endif
	int verbose = io->verbose;
	if (selected_ab < 0) select_ab(io);
	for (int i = 0; i < partition_count; i++) {
		if (strcmp(partitions[i].name, "splloader") == 0
			|| strcmp(partitions[i].name, "uboot_a") == 0
			|| strcmp(partitions[i].name, "uboot_b") == 0
			|| strcmp(partitions[i].name, "vbmeta_a") == 0
			|| strcmp(partitions[i].name, "vbmeta_b") == 0) {
			load_partition(io, partitions[i].name, partitions[i].file_path, blk_size);
			partitions[i].written_flag = 1;
			if (strcmp(partitions[i].name, "vbmeta_b") == 0) break;
			continue;
		}
		if (strcmp(partitions[i].name, "uboot") == 0 || strcmp(partitions[i].name, "vbmeta") == 0) {
			uint64_t realsize = 0;
			char name_ab[36];
			io->verbose = 0;
			fn = partitions[i].name;
			realsize = check_partition(io, fn);
			if (!realsize) {
				if (selected_ab > 0) {
					snprintf(name_ab, sizeof(name_ab), "%s_%c", fn, 96 + selected_ab);
					realsize = check_partition(io, name_ab);
					fn = name_ab;
				}
				if (!realsize) {
					DBG_LOG("part not exist\n");
					io->verbose = verbose;
					continue;
				}
			}
			io->verbose = verbose;
			load_partition(io, fn, partitions[i].file_path, blk_size);
			partitions[i].written_flag = 1;
			if(strcmp(partitions[i].name, "uboot")) break;
			continue;
		}
	}

	for (int i = 0; i < partition_count; i++) {
		if (!partitions[i].written_flag) {
			uint64_t realsize = 0;
			char name_ab[36];
			fn = partitions[i].name;
			realsize = check_partition(io, fn);
			if (!realsize) {
				if (selected_ab > 0) {
					snprintf(name_ab, sizeof(name_ab), "%s_%c", fn, 96 + selected_ab);
					realsize = check_partition(io, name_ab);
					fn = name_ab;
				}
				if (!realsize) {
					DBG_LOG("part not exist\n");
					io->verbose = verbose;
					continue;
				}
			}
			io->verbose = verbose;

			if (strstr(fn, "fixnv1")) load_nv_partition(io, fn, partitions[i].file_path, 4096);
			else load_partition(io, fn, partitions[i].file_path, blk_size);
		}
	}
	free(partitions);
}

void get_Da_Info(spdio_t* io)
{
	if (io->raw_len > 6) {
		if (0x7477656e == *(uint32_t*)(io->raw_buf + 4)) {
			int len = 8;
			uint16_t tmp[2];
			while (len + 2 < io->raw_len)
			{
				tmp[0] = 0;
				tmp[1] = 0;
				memcpy(tmp, io->raw_buf + len, sizeof(tmp));

				len += sizeof(tmp);
				if (tmp[0] == 0) Da_Info.bDisableHDLC = *(uint32_t*)(io->raw_buf + len);
				else if (tmp[0] == 2) Da_Info.bSupportRawData = *(uint8_t*)(io->raw_buf + len);
				else if (tmp[0] == 3) Da_Info.dwFlushSize = *(uint32_t*)(io->raw_buf + len);
				else if (tmp[0] == 6) Da_Info.dwStorageType = *(uint32_t*)(io->raw_buf + len);
				len += tmp[1];
			}
		}
		else memcpy(&Da_Info, io->raw_buf + 4, io->raw_len - 6);
	}
	DBG_LOG("FDL2: incompatible partition\n");
}

int ab_compare_slots(const slot_metadata* a, const slot_metadata* b)
{
	if (a->priority != b->priority)
		return b->priority - a->priority;
	if (a->successful_boot != b->successful_boot)
		return b->successful_boot - a->successful_boot;
	if (a->tries_remaining != b->tries_remaining)
		return b->tries_remaining - a->tries_remaining;
	return 0;
}

void select_ab(spdio_t* io)
{
	bootloader_control* abc = NULL;
	int ret;

	select_partition(io, "misc", 0x820, 0, BSL_CMD_READ_START);
	if (send_and_check(io)) { selected_ab = 0; return; }

	uint32_t data[2] = { 0x20,0x800 };
	encode_msg(io, BSL_CMD_READ_MIDST, data, 8);
	send_msg(io);
	ret = recv_msg(io);
	if (!ret) ERR_EXIT("timeout reached\n");
	if (recv_type(io) == BSL_REP_READ_FLASH) abc = (bootloader_control*)(io->raw_buf + 4);
	encode_msg(io, BSL_CMD_READ_END, NULL, 0);
	send_and_check(io);

	if (abc == NULL) { selected_ab = 0; return; }
	if (abc->nb_slot != 2) { selected_ab = 0; return; }
	if (ab_compare_slots(&abc->slot_info[1], &abc->slot_info[0]) < 0) selected_ab = 2;
	else selected_ab = 1;
}

void dm_disable(spdio_t* io, int blk_size)
{
	const char* list[] = { "vbmeta", "vbmeta_a", "vbmeta_b", NULL };
	char dfile[40];
	for (int i = 0; list[i] != NULL; i++) {
		sprintf(dfile, "%s.bin", list[i]);
		if (1048576 != dump_partition(io, list[i], 0, 1048576, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE)) {
			remove(dfile);
			continue;
		}
	}
	for (int i = 0; list[i] != NULL; i++) {
		sprintf(dfile, "%s.bin", list[i]);
		FILE* vb = fopen(dfile, "r");
		if (!vb) {
			DBG_LOG("File %s does not exist, skipping.\n", dfile);
			continue;
		}
		fclose(vb);
		vb = fopen(dfile, "rb+");
		if (!vb) ERR_EXIT("fopen %s failed\n", dfile);
		char header[4];
		if (fread(header, 1, 4, vb) != 4) ERR_EXIT("Failed to read header\n");
		if (memcmp(header, "DHTB", 4)) {
			if (fseek(vb, 0x7B, SEEK_SET) != 0) ERR_EXIT("fseek failed\n");
			char ch = '\1';
			if (fwrite(&ch, 1, 1, vb) != 1) ERR_EXIT("fwrite failed\n");
		}
		else { DBG_LOG("unsupported\n"); break; }
		fclose(vb);

		load_partition(io, list[i], dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
	}
}

void dm_enable(spdio_t* io, int blk_size)
{
	const char* list[] = { "vbmeta", "vbmeta_a", "vbmeta_b",
					"vbmeta_system", "vbmeta_system_a", "vbmeta_system_b",
					"vbmeta_vendor", "vbmeta_vendor_a", "vbmeta_vendor_b",
					"vbmeta_system_ext", "vbmeta_system_ext_a", "vbmeta_system_ext_b",
					"vbmeta_product", "vbmeta_product_a", "vbmeta_product_b",
					"vbmeta_odm", "vbmeta_odm_a", "vbmeta_odm_b", NULL };
	char dfile[40];
	for (int i = 0; list[i] != NULL; i++) {
		sprintf(dfile, "%s.bin", list[i]);
		if (1048576 != dump_partition(io, list[i], 0, 1048576, dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE)) {
			remove(dfile);
			continue;
		}
	}
	for (int i = 0; list[i] != NULL; i++) {
		sprintf(dfile, "%s.bin", list[i]);
		FILE* vb = fopen(dfile, "r");
		if (!vb) {
			DBG_LOG("File %s does not exist, skipping.\n", dfile);
			continue;
		}
		fclose(vb);
		vb = fopen(dfile, "rb+");
		if (!vb) ERR_EXIT("fopen %s failed\n", dfile);
		char header[4];
		if (fread(header, 1, 4, vb) != 4) ERR_EXIT("Failed to read header\n");
		if (memcmp(header, "DHTB", 4)) {
			if (fseek(vb, 0x7B, SEEK_SET) != 0) ERR_EXIT("fseek failed\n");
			char ch = '\0';
			if (fwrite(&ch, 1, 1, vb) != 1) ERR_EXIT("fwrite failed\n");
		}
		else { DBG_LOG("unsupported\n"); break; }
		fclose(vb);

		load_partition(io, list[i], dfile, blk_size ? blk_size : DEFAULT_BLK_SIZE);
	}
}

#if _WIN32
const _TCHAR CLASS_NAME[] = _T("Sample Window Class");

HWND hWnd;

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	static BOOL interface_checked = FALSE;
	static BOOL is_diag = FALSE;
	switch (message)
	{
	case WM_DEVICECHANGE:
		if (DBT_DEVICEARRIVAL == wParam || DBT_DEVICEREMOVECOMPLETE == wParam)
		{
			PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;
			PDEV_BROADCAST_DEVICEINTERFACE pDevInf;
			PDEV_BROADCAST_PORT pDevPort;
			switch (pHdr->dbch_devicetype)
			{
			case DBT_DEVTYP_DEVICEINTERFACE:
				pDevInf = (PDEV_BROADCAST_DEVICEINTERFACE)pHdr;
#if USE_LIBUSB
				if (my_strstr(pDevInf->dbcc_name, _T("VID_1782&PID_4D00")))
					if (DBT_DEVICEREMOVECOMPLETE == wParam)
						m_bOpened = -1;
#else
				if (my_strstr(pDevInf->dbcc_name, _T("VID_1782&PID_4D00"))) interface_checked = TRUE;
				else if (my_strstr(pDevInf->dbcc_name, _T("VID_1782&PID_4D03"))) {
					interface_checked = TRUE;
					is_diag = TRUE;
				}
#endif
				break;
#if !USE_LIBUSB
			case DBT_DEVTYP_PORT:
				if (interface_checked) {
					pDevPort = (PDEV_BROADCAST_PORT)pHdr;
					DWORD changedPort;
					if (is_diag) {
						changedPort = FindPort("SPRD DIAG"); //changedPort = 0 when DBT_DEVICEREMOVECOMPLETE
						free(ports);
						ports = NULL;
					}
					else changedPort = my_strtoul(pDevPort->dbcp_name + 3, NULL, 0);
					if (changedPort == 0) m_bOpened = -1;
					else {
						if (DBT_DEVICEARRIVAL == wParam) { if (!curPort) curPort = changedPort; }
						else { if (curPort == changedPort) m_bOpened = -1; }
					}
					interface_checked = FALSE;
					is_diag = FALSE;
				}
				break;
#endif
			}
		}
	}

	return DefWindowProc(hWnd, message, wParam, lParam);
}

DWORD WINAPI ThrdFunc(LPVOID lpParam)
{
	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = WndProc;
	wc.hInstance = GetModuleHandle(NULL);
	wc.lpszClassName = CLASS_NAME;
	if (0 == RegisterClass(&wc)) return -1;

	hWnd = CreateWindowEx(0, CLASS_NAME, _T(""), WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL,       // Parent window
		NULL,       // Menu
		GetModuleHandle(NULL),  // Instance handle
		NULL        // Additional application data
	);
	if (hWnd==NULL) return -1;

	HDEVNOTIFY hDevNotify;
	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
#if USE_LIBUSB
	const GUID GUID_DEVINTERFACE = { 0xa5dcbf10, 0x6530, 0x11d2, { 0x90, 0x1f, 0x00, 0xc0, 0x4f, 0xb9, 0x51, 0xed } };
#else
	const GUID GUID_DEVINTERFACE = { 0x86e0d1e0, 0x8089, 0x11d0, { 0x9c, 0xe4, 0x08, 0x00, 0x3e, 0x30, 0x1f, 0x73 } };
#endif
	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
	NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
	NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	NotificationFilter.dbcc_classguid = GUID_DEVINTERFACE;
	hDevNotify = RegisterDeviceNotification(hWnd, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (msg.message == THRD_MESSAGE_EXIT) break;
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}
#if !USE_LIBUSB
void ChangeMode(spdio_t* io, int ms, int bootmode, int at)
{
	if (bootmode >= 0x80) ERR_EXIT("mode not exist\n");
	DWORD bytes_written, bytes_read;
	int done = 0;

	while (!done)
	{
		DBG_LOG("Waiting for boot_diag/cali_diag/dl_diag connection (%ds)\n", ms / 1000);
		for (int i = 0; ; i++) {
			if (curPort) break;
			if (100 * i >= ms) ERR_EXIT("find port failed\n");
			usleep(100000);
		}
		if (!call_ConnectChannel(io->handle, curPort)) ERR_EXIT("Connection failed\n");

		uint8_t payload[10] = { 0x7e,0,0,0,0,8,0,0xfe,0,0x7e };
		if (!bootmode) {
			uint8_t hello[10] = { 0x7e,0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e };
			if (io->verbose >= 2) {
				DBG_LOG("send (%d):\n", sizeof(hello));
				print_mem(stderr, hello, sizeof(hello));
			}
			if (!(bytes_written = call_Write(io->handle, hello, sizeof(hello)))) ERR_EXIT("Error writing to serial port\n");
			if (!(bytes_read = call_Read(io->handle, io->recv_buf, RECV_BUF_LEN, io->timeout))) ERR_EXIT("read response from boot mode failed\n");
			else
			{
				if (io->verbose >= 2) {
					DBG_LOG("read (%d):\n", bytes_read);
					print_mem(stderr, io->recv_buf, bytes_read);
				}
				if (io->recv_buf[2] == BSL_REP_VER) return;
			}
			payload[8] = 0x82;
		}
		else if (at) payload[8] = 0x81;
		else payload[8] = bootmode + 0x80;
		if (io->verbose >= 2) {
			DBG_LOG("send (%d):\n", sizeof(payload));
			print_mem(stderr, payload, sizeof(payload));
		}
		if (!(bytes_written = call_Write(io->handle, payload, sizeof(payload)))) ERR_EXIT("Error writing to serial port\n");
		if ((bytes_read = call_Read(io->handle, io->recv_buf, RECV_BUF_LEN, io->timeout)))
		{
			if (io->verbose >= 2) {
				DBG_LOG("read (%d):\n", bytes_read);
				print_mem(stderr, io->recv_buf, bytes_read);
			}
			if (io->recv_buf[2] == BSL_REP_VER) { if (io->recv_buf[9] < '4') return; }
			else if (io->recv_buf[2] != 0x7e)
			{
				uint8_t autod[] = { 0x7e,0,0,0,0,0x20,0,0x68,0,0x41,0x54,0x2b,0x53,0x50,0x52,0x45,0x46,0x3d,0x22,0x41,0x55,0x54,0x4f,0x44,0x4c,0x4f,0x41,0x44,0x45,0x52,0x22,0xd,0xa,0x7e };
				if (io->verbose >= 2) {
					DBG_LOG("send (%d):\n", sizeof(autod));
					print_mem(stderr, autod, sizeof(autod));
				}
				if ((bytes_written = call_Write(io->handle, autod, sizeof(autod))))
				{
					if (!(bytes_read = call_Read(io->handle, io->recv_buf, RECV_BUF_LEN, io->timeout))) ERR_EXIT("read response from cali mode failed\n");
					else
					{
						uint8_t ok[] = { 0xd,0xa,0x4f,0x4b,0xd,0xa };
						if (io->verbose >= 2) {
							DBG_LOG("read (%d):\n", bytes_read);
							print_mem(stderr, io->recv_buf, bytes_read);
						}
						if (!memcmp(io->recv_buf + bytes_read - 7, ok, 6)) done = 1;
						else {
							DBG_LOG("Unknown response\n");
							if (io->verbose < 2) print_mem(stderr, io->recv_buf, bytes_read);
						}
					}
				}
			}
		}
		for (int i = 0; ; i++)
		{
			if (m_bOpened == -1)
			{
				call_DisconnectChannel(io->handle);
				io->recv_buf[2] = 0;
				curPort = 0;
				m_bOpened = 0;
				break;
			}
			if (i >= 50)
			{
				if (io->recv_buf[2] == BSL_REP_VER) return;
				else ERR_EXIT("kick reboot timeout, reboot your phone by pressing POWER and VOL_UP for 7-10 seconds.\n");
			}
			usleep(100000);
		}
		if (!at) done = 1;
	}
}
#endif
#endif
