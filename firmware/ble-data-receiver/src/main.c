/*
 * K'amal BLE fixed data-channel receiver prototype.
 *
 * Receive-only proof slice for nRF52840/PCA10059.
 * No connection following, transmission, anchor inference, event-counter
 * inference, or channel-selection inference is implemented here.
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nrfx.h>
#include <zephyr/device.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#define FW_NAME "kamal-ble-data-rx"
#define FW_VERSION "0.1.0"
#define FW_CONTRACT "0.12.0-r07-proto1"

#define BLE_DATA_CHANNEL_MAX 36U
#define BLE_DATA_PAYLOAD_MAX 251U
#define BLE_DATA_PDU_MAX (2U + BLE_DATA_PAYLOAD_MAX)
#define RX_BUFFER_SIZE 260U
#define COMMAND_BUFFER_SIZE 128U
#define RESPONSE_BUFFER_SIZE 896U
#define DEVICE_ID_BYTES 16U
#define DEVICE_ID_HEX_SIZE ((DEVICE_ID_BYTES * 2U) + 1U)

#define BLE_CRC_POLY 0x00065BU

static const struct device *const cdc = DEVICE_DT_GET_ONE(zephyr_cdc_acm_uart);

enum receiver_state {
	RECEIVER_UNCONFIGURED = 0,
	RECEIVER_CONFIGURED,
	RECEIVER_RUNNING,
};

struct receiver_config {
	uint8_t channel;
	uint32_t access_address;
	uint32_t crc_init;
};

static enum receiver_state receiver_state = RECEIVER_UNCONFIGURED;
static struct receiver_config receiver_config;
static uint64_t packet_sequence;
static char device_id_hex[DEVICE_ID_HEX_SIZE] = "unknown";

static uint8_t rx_buffer[RX_BUFFER_SIZE] __attribute__((aligned(4)));
static char command_buffer[COMMAND_BUFFER_SIZE];
static size_t command_length;
static char response_buffer[RESPONSE_BUFFER_SIZE];

static void serial_write(const char *text)
{
	for (const char *p = text; *p != '\0'; ++p) {
		uart_poll_out(cdc, (unsigned char)*p);
	}
}

static void reply(const char *format, ...)
{
	va_list args;
	int written;

	va_start(args, format);
	written = vsnprintf(response_buffer, sizeof(response_buffer), format, args);
	va_end(args);

	if (written < 0) {
		return;
	}

	response_buffer[sizeof(response_buffer) - 1U] = '\0';
	serial_write(response_buffer);
}

static const char *state_name(void)
{
	switch (receiver_state) {
	case RECEIVER_UNCONFIGURED:
		return "unconfigured";
	case RECEIVER_CONFIGURED:
		return "configured";
	case RECEIVER_RUNNING:
		return "running";
	default:
		return "invalid";
	}
}

static void load_device_id(void)
{
	uint8_t raw[DEVICE_ID_BYTES] = {0};
	ssize_t count = hwinfo_get_device_id(raw, sizeof(raw));
	size_t offset = 0U;

	if (count <= 0) {
		strcpy(device_id_hex, "unknown");
		return;
	}

	if ((size_t)count > sizeof(raw)) {
		count = sizeof(raw);
	}

	for (ssize_t i = 0; i < count && offset + 2U < sizeof(device_id_hex); ++i) {
		int n = snprintf(&device_id_hex[offset],
				 sizeof(device_id_hex) - offset,
				 "%02x", raw[i]);
		if (n != 2) {
			strcpy(device_id_hex, "unknown");
			return;
		}
		offset += 2U;
	}

	device_id_hex[offset] = '\0';
}

static uint8_t ble_frequency_reg(uint8_t channel)
{
	/*
	 * nRF RADIO FREQUENCY is an offset from 2400 MHz.
	 * BLE data channels:
	 *   0..10  -> 2404..2424 MHz
	 *   11..36 -> 2428..2478 MHz
	 */
	if (channel <= 10U) {
		return (uint8_t)(4U + (2U * channel));
	}

	return (uint8_t)(6U + (2U * channel));
}

static uint16_t ble_frequency_mhz(uint8_t channel)
{
	return (uint16_t)(2400U + ble_frequency_reg(channel));
}

static bool parse_decimal_channel(const char *text, uint8_t *channel)
{
	char *end = NULL;
	unsigned long value;

	if (text == NULL || *text == '\0') {
		return false;
	}

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || value > BLE_DATA_CHANNEL_MAX) {
		return false;
	}

	*channel = (uint8_t)value;
	return true;
}

static bool parse_fixed_hex(const char *text, size_t digits, uint32_t *value)
{
	char *end = NULL;
	unsigned long parsed;
	const char *digits_start = text;

	if (text == NULL) {
		return false;
	}

	if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
		digits_start += 2;
	}

	if (strlen(digits_start) != digits) {
		return false;
	}

	for (size_t i = 0; i < digits; ++i) {
		if (!isxdigit((unsigned char)digits_start[i])) {
			return false;
		}
	}

	errno = 0;
	parsed = strtoul(digits_start, &end, 16);
	if (errno != 0 || end == digits_start || *end != '\0') {
		return false;
	}

	*value = (uint32_t)parsed;
	return true;
}

static int hfclk_start(void)
{
	int64_t deadline;

	NRF_CLOCK->EVENTS_HFCLKSTARTED = 0U;
	NRF_CLOCK->TASKS_HFCLKSTART = 1U;

	deadline = k_uptime_get() + 100;
	while (NRF_CLOCK->EVENTS_HFCLKSTARTED == 0U) {
		if (k_uptime_get() >= deadline) {
			return -ETIMEDOUT;
		}
	}

	return 0;
}

static int radio_wait_disabled(void)
{
	int64_t deadline = k_uptime_get() + 10;

	while (NRF_RADIO->STATE != RADIO_STATE_STATE_Disabled) {
		if (k_uptime_get() >= deadline) {
			return -ETIMEDOUT;
		}
	}

	return 0;
}

static int radio_disable(void)
{
	int rc;

	if (NRF_RADIO->STATE == RADIO_STATE_STATE_Disabled) {
		return 0;
	}

	NRF_RADIO->EVENTS_DISABLED = 0U;
	NRF_RADIO->TASKS_DISABLE = 1U;
	rc = radio_wait_disabled();
	if (rc != 0) {
		return rc;
	}

	NRF_RADIO->EVENTS_DISABLED = 0U;
	return 0;
}

static void radio_set_access_address(uint32_t access_address)
{
	/*
	 * K'amal stores/displays the BLE access address as conventional hex,
	 * e.g. 0x50656a5e.  On air, BLE transmits the least-significant octet
	 * first.  Nordic logical address 0 is therefore:
	 *
	 *   PREFIX0.AP0 = AA[31:24]
	 *   BASE0[31:8] = AA[23:0]
	 *
	 * This matches Zephyr's Nordic BLE controller mapping.
	 */
	NRF_RADIO->TXADDRESS = 0U;
	NRF_RADIO->RXADDRESSES =
		(RADIO_RXADDRESSES_ADDR0_Enabled << RADIO_RXADDRESSES_ADDR0_Pos);

	NRF_RADIO->PREFIX0 = (access_address >> 24) & 0xFFU;
	NRF_RADIO->BASE0 = (access_address & 0x00FFFFFFU) << 8;
}

static int radio_configure(const struct receiver_config *config)
{
	int rc = hfclk_start();

	if (rc != 0) {
		return rc;
	}

	NRF_RADIO->POWER = 1U;

	rc = radio_disable();
	if (rc != 0) {
		return rc;
	}

	NRF_RADIO->MODE =
		(RADIO_MODE_MODE_Ble_1Mbit << RADIO_MODE_MODE_Pos) &
		RADIO_MODE_MODE_Msk;

#if defined(RADIO_MODECNF0_DTX_Msk)
	NRF_RADIO->MODECNF0 =
		(RADIO_MODECNF0_DTX_Center << RADIO_MODECNF0_DTX_Pos) &
		RADIO_MODECNF0_DTX_Msk;
#endif

	NRF_RADIO->FREQUENCY = ble_frequency_reg(config->channel);
	NRF_RADIO->DATAWHITEIV = config->channel;

	radio_set_access_address(config->access_address);

	/*
	 * BLE data PDU RAM representation for this prototype:
	 *   byte 0: LL data header octet 0 (S0)
	 *   byte 1: LL payload length (8-bit LENGTH)
	 *   byte 2..: LL payload
	 *
	 * No synthetic S1 byte is included in RAM.
	 */
	NRF_RADIO->PCNF0 =
		((1UL << RADIO_PCNF0_S0LEN_Pos) & RADIO_PCNF0_S0LEN_Msk) |
		((8UL << RADIO_PCNF0_LFLEN_Pos) & RADIO_PCNF0_LFLEN_Msk) |
		((0UL << RADIO_PCNF0_S1LEN_Pos) & RADIO_PCNF0_S1LEN_Msk) |
		((RADIO_PCNF0_PLEN_8bit << RADIO_PCNF0_PLEN_Pos) &
		 RADIO_PCNF0_PLEN_Msk);

	NRF_RADIO->PCNF1 =
		(((uint32_t)BLE_DATA_PAYLOAD_MAX << RADIO_PCNF1_MAXLEN_Pos) &
		 RADIO_PCNF1_MAXLEN_Msk) |
		((0UL << RADIO_PCNF1_STATLEN_Pos) & RADIO_PCNF1_STATLEN_Msk) |
		((3UL << RADIO_PCNF1_BALEN_Pos) & RADIO_PCNF1_BALEN_Msk) |
		((RADIO_PCNF1_ENDIAN_Little << RADIO_PCNF1_ENDIAN_Pos) &
		 RADIO_PCNF1_ENDIAN_Msk) |
		((1UL << RADIO_PCNF1_WHITEEN_Pos) & RADIO_PCNF1_WHITEEN_Msk);

	NRF_RADIO->CRCCNF =
		((RADIO_CRCCNF_LEN_Three << RADIO_CRCCNF_LEN_Pos) &
		 RADIO_CRCCNF_LEN_Msk) |
		((RADIO_CRCCNF_SKIPADDR_Skip << RADIO_CRCCNF_SKIPADDR_Pos) &
		 RADIO_CRCCNF_SKIPADDR_Msk);
	NRF_RADIO->CRCPOLY = BLE_CRC_POLY;
	NRF_RADIO->CRCINIT = config->crc_init & 0x00FFFFFFU;

	NRF_RADIO->PACKETPTR = (uint32_t)(uintptr_t)rx_buffer;
	NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk |
			    RADIO_SHORTS_END_DISABLE_Msk;

	return 0;
}

static int radio_arm(void)
{
	int rc = radio_wait_disabled();

	if (rc != 0) {
		return rc;
	}

	memset(rx_buffer, 0, sizeof(rx_buffer));
	NRF_RADIO->EVENTS_END = 0U;
	NRF_RADIO->EVENTS_DISABLED = 0U;
	NRF_RADIO->PACKETPTR = (uint32_t)(uintptr_t)rx_buffer;
	__DMB();
	NRF_RADIO->TASKS_RXEN = 1U;

	return 0;
}

static int receiver_start(void)
{
	int rc;

	if (receiver_state == RECEIVER_RUNNING) {
		return -EALREADY;
	}

	if (receiver_state != RECEIVER_CONFIGURED) {
		return -EINVAL;
	}

	rc = radio_configure(&receiver_config);
	if (rc != 0) {
		return rc;
	}

	rc = radio_arm();
	if (rc != 0) {
		return rc;
	}

	packet_sequence = 0U;
	receiver_state = RECEIVER_RUNNING;
	return 0;
}

static int receiver_stop(void)
{
	int rc;

	if (receiver_state != RECEIVER_RUNNING) {
		return -EALREADY;
	}

	rc = radio_disable();
	if (rc != 0) {
		return rc;
	}

	NRF_RADIO->POWER = 0U;
	receiver_state = RECEIVER_CONFIGURED;
	return 0;
}

static void emit_packet_if_ready(void)
{
	uint8_t packet[BLE_DATA_PDU_MAX];
	uint8_t payload_length;
	size_t pdu_length;
	bool crc_ok;
	uint64_t timestamp_us;
	size_t offset;
	int rc;

	if (receiver_state != RECEIVER_RUNNING ||
	    NRF_RADIO->EVENTS_END == 0U) {
		return;
	}

	NRF_RADIO->EVENTS_END = 0U;
	__DMB();

	crc_ok = NRF_RADIO->CRCSTATUS != 0U;
	payload_length = rx_buffer[1];
	if (payload_length > BLE_DATA_PAYLOAD_MAX) {
		payload_length = BLE_DATA_PAYLOAD_MAX;
	}

	pdu_length = 2U + payload_length;
	memcpy(packet, rx_buffer, pdu_length);
	timestamp_us = k_cyc_to_us_floor64(k_cycle_get_64());

	rc = radio_wait_disabled();
	if (rc != 0) {
		receiver_state = RECEIVER_CONFIGURED;
		reply("ERR radio_disable_timeout\n");
		return;
	}

	rc = radio_arm();
	if (rc != 0) {
		receiver_state = RECEIVER_CONFIGURED;
		reply("ERR radio_rearm rc=%d\n", rc);
		return;
	}

	++packet_sequence;

	offset = (size_t)snprintf(
		response_buffer, sizeof(response_buffer),
		"PKT seq=%" PRIu64 " t_us=%" PRIu64
		" device=%s fw=%s ch=%u aa=0x%08" PRIx32
		" crcinit=0x%06" PRIx32 " crcok=%u len=%u pdu=",
		packet_sequence, timestamp_us, device_id_hex, FW_VERSION,
		receiver_config.channel, receiver_config.access_address,
		receiver_config.crc_init, crc_ok ? 1U : 0U,
		(unsigned int)pdu_length);

	if (offset >= sizeof(response_buffer)) {
		return;
	}

	for (size_t i = 0; i < pdu_length; ++i) {
		if (offset + 2U >= sizeof(response_buffer)) {
			break;
		}
		int n = snprintf(&response_buffer[offset],
				 sizeof(response_buffer) - offset,
				 "%02x", packet[i]);
		if (n != 2) {
			break;
		}
		offset += 2U;
	}

	if (offset + 2U < sizeof(response_buffer)) {
		response_buffer[offset++] = '\n';
		response_buffer[offset] = '\0';
	}

	serial_write(response_buffer);
}

static void command_status(void)
{
	if (receiver_state == RECEIVER_UNCONFIGURED) {
		reply("STATUS state=%s device=%s fw=%s contract=%s phy=1M\n",
		      state_name(), device_id_hex, FW_VERSION, FW_CONTRACT);
		return;
	}

	reply("STATUS state=%s device=%s fw=%s contract=%s phy=1M"
	      " ch=%u freq_mhz=%u aa=0x%08" PRIx32
	      " crcinit=0x%06" PRIx32 "\n",
	      state_name(), device_id_hex, FW_VERSION, FW_CONTRACT,
	      receiver_config.channel,
	      ble_frequency_mhz(receiver_config.channel),
	      receiver_config.access_address,
	      receiver_config.crc_init);
}

static void handle_command(char *line)
{
	char *save = NULL;
	char *command = strtok_r(line, " \t", &save);

	if (command == NULL) {
		return;
	}

	if (strcmp(command, "HELLO") == 0) {
		if (strtok_r(NULL, " \t", &save) != NULL) {
			reply("ERR usage HELLO\n");
			return;
		}
		reply("HELLO name=%s fw=%s contract=%s device=%s"
		      " capabilities=fixed-data-rx,le1m,crc24\n",
		      FW_NAME, FW_VERSION, FW_CONTRACT, device_id_hex);
		return;
	}

	if (strcmp(command, "STATUS") == 0) {
		if (strtok_r(NULL, " \t", &save) != NULL) {
			reply("ERR usage STATUS\n");
			return;
		}
		command_status();
		return;
	}

	if (strcmp(command, "CONFIG") == 0) {
		char *channel_text;
		char *aa_text;
		char *crc_text;
		uint8_t channel;
		uint32_t access_address;
		uint32_t crc_init;

		if (receiver_state == RECEIVER_RUNNING) {
			reply("ERR busy stop_receiver_before_config\n");
			return;
		}

		channel_text = strtok_r(NULL, " \t", &save);
		aa_text = strtok_r(NULL, " \t", &save);
		crc_text = strtok_r(NULL, " \t", &save);

		if (channel_text == NULL || aa_text == NULL || crc_text == NULL ||
		    strtok_r(NULL, " \t", &save) != NULL) {
			reply("ERR usage CONFIG <channel_0_36> <aa_8hex> <crcinit_6hex>\n");
			return;
		}

		if (!parse_decimal_channel(channel_text, &channel)) {
			reply("ERR invalid_channel expected_0_36\n");
			return;
		}

		if (!parse_fixed_hex(aa_text, 8U, &access_address)) {
			reply("ERR invalid_access_address expected_8hex\n");
			return;
		}

		if (!parse_fixed_hex(crc_text, 6U, &crc_init)) {
			reply("ERR invalid_crcinit expected_6hex\n");
			return;
		}

		receiver_config.channel = channel;
		receiver_config.access_address = access_address;
		receiver_config.crc_init = crc_init;
		receiver_state = RECEIVER_CONFIGURED;

		reply("OK configured ch=%u freq_mhz=%u aa=0x%08" PRIx32
		      " crcinit=0x%06" PRIx32 " phy=1M\n",
		      channel, ble_frequency_mhz(channel),
		      access_address, crc_init);
		return;
	}

	if (strcmp(command, "START") == 0) {
		int rc;

		if (strtok_r(NULL, " \t", &save) != NULL) {
			reply("ERR usage START\n");
			return;
		}

		rc = receiver_start();
		if (rc == -EALREADY) {
			reply("ERR already_running\n");
			return;
		}
		if (rc == -EINVAL) {
			reply("ERR not_configured\n");
			return;
		}
		if (rc != 0) {
			reply("ERR start_failed rc=%d\n", rc);
			return;
		}

		reply("OK started ch=%u freq_mhz=%u aa=0x%08" PRIx32
		      " crcinit=0x%06" PRIx32 " phy=1M\n",
		      receiver_config.channel,
		      ble_frequency_mhz(receiver_config.channel),
		      receiver_config.access_address,
		      receiver_config.crc_init);
		return;
	}

	if (strcmp(command, "STOP") == 0) {
		int rc;

		if (strtok_r(NULL, " \t", &save) != NULL) {
			reply("ERR usage STOP\n");
			return;
		}

		rc = receiver_stop();
		if (rc == -EALREADY) {
			reply("ERR not_running\n");
			return;
		}
		if (rc != 0) {
			reply("ERR stop_failed rc=%d\n", rc);
			return;
		}

		reply("OK stopped\n");
		return;
	}

	if (strcmp(command, "CLEAR") == 0) {
		if (strtok_r(NULL, " \t", &save) != NULL) {
			reply("ERR usage CLEAR\n");
			return;
		}
		if (receiver_state == RECEIVER_RUNNING) {
			reply("ERR busy stop_receiver_before_clear\n");
			return;
		}

		memset(&receiver_config, 0, sizeof(receiver_config));
		receiver_state = RECEIVER_UNCONFIGURED;
		packet_sequence = 0U;
		reply("OK cleared\n");
		return;
	}

	if (strcmp(command, "HELP") == 0) {
		if (strtok_r(NULL, " \t", &save) != NULL) {
			reply("ERR usage HELP\n");
			return;
		}
		reply("HELP commands=HELLO,STATUS,CONFIG,START,STOP,CLEAR,HELP"
		      " config=\"CONFIG <channel_0_36> <aa_8hex> <crcinit_6hex>\"\n");
		return;
	}

	reply("ERR unknown_command\n");
}

static void poll_commands(void)
{
	unsigned char byte;
	int rc;

	while ((rc = uart_poll_in(cdc, &byte)) == 0) {
		if (byte == '\r') {
			continue;
		}

		if (byte == '\n') {
			command_buffer[command_length] = '\0';
			handle_command(command_buffer);
			command_length = 0U;
			continue;
		}

		if (command_length + 1U >= sizeof(command_buffer)) {
			command_length = 0U;
			reply("ERR command_too_long\n");
			continue;
		}

		if (isprint(byte) || byte == '\t') {
			command_buffer[command_length++] = (char)byte;
		}
	}
}

int main(void)
{
	if (!device_is_ready(cdc)) {
		return 0;
	}

	load_device_id();

	for (;;) {
		emit_packet_if_ready();
		poll_commands();
		k_sleep(K_MSEC(1));
	}

	return 0;
}
