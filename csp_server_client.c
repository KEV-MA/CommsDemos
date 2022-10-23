#include <csp/csp_debug.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <csp/csp.h>
#include <csp/drivers/usart.h>
#include <csp/drivers/can_socketcan.h>
#include <csp/interfaces/csp_if_zmqhub.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define AX25_MAX_ADDR_LEN 28
#define AX25_MAX_FRAME_LEN 256
#define AX25_MIN_ADDR_LEN 14
#define AX25_SYNC_FLAG 0x7E
#define AX25_MIN_CTRL_LEN 1
#define AX25_MAX_CTRL_LEN 2
#define AX25_CALLSIGN_MAX_LEN 6
#define AX25_CALLSIGN_MIN_LEN 2
#define AX25_PREAMBLE_LEN 16
#define AX25_POSTAMBLE_LEN 16

/**
 * AX.25 Frame types
 */
typedef enum
{
  AX25_I_FRAME, //!< AX25_I_FRAME Information frame
  AX25_S_FRAME, //!< AX25_S_FRAME Supervisory frame
  AX25_U_FRAME, //!< AX25_U_FRAME Unnumbered frame
  AX25_UI_FRAME /**!< AX25_UI_FRAME Unnumbered information frame */
} ax25_frame_type_t;


/**
 * The different states of the AX.25 decoder
 */
typedef enum
{
  AX25_NO_SYNC, //!< AX25_NO_SYNC when not frame has been seen yet
  AX25_IN_SYNC, //!< AX25_IN_SYNC the stating SYNC flag has been received
  AX25_FRAME_END//!< AX25_FRAME_END the trailing SYNC flag has been received
} ax25_decoding_state_t;

typedef enum
{
  AX25_ENC_FAIL, AX25_ENC_OK
} ax25_encode_status_t;

typedef struct
{
  uint8_t address[AX25_MAX_ADDR_LEN];
  size_t address_len;
  uint16_t ctrl;
  size_t ctrl_len;
  uint8_t pid;
  uint8_t *info;
  size_t info_len;
  ax25_frame_type_t type;
} ax25_frame_t;

static const uint16_t crc16_ccitt_table_reverse[256] =
  { 0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48,
      0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x1081, 0x0108,
      0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E, 0x9CC9, 0x8D40, 0xBFDB,
      0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876, 0x2102, 0x308B, 0x0210, 0x1399,
      0x6726, 0x76AF, 0x4434, 0x55BD, 0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E,
      0xFAE7, 0xC87C, 0xD9F5, 0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E,
      0x54B5, 0x453C, 0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD,
      0xC974, 0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
      0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3, 0x5285,
      0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A, 0xDECD, 0xCF44,
      0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72, 0x6306, 0x728F, 0x4014,
      0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5,
      0xA96A, 0xB8E3, 0x8A78, 0x9BF1, 0x7387, 0x620E, 0x5095, 0x411C, 0x35A3,
      0x242A, 0x16B1, 0x0738, 0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862,
      0x9AF9, 0x8B70, 0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E,
      0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
      0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036, 0x18C1,
      0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E, 0xA50A, 0xB483,
      0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5, 0x2942, 0x38CB, 0x0A50,
      0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD, 0xB58B, 0xA402, 0x9699, 0x8710,
      0xF3AF, 0xE226, 0xD0BD, 0xC134, 0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7,
      0x6E6E, 0x5CF5, 0x4D7C, 0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1,
      0xA33A, 0xB2B3, 0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72,
      0x3EFB, 0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
      0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A, 0xE70E,
      0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1, 0x6B46, 0x7ACF,
      0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9, 0xF78F, 0xE606, 0xD49D,
      0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330, 0x7BC7, 0x6A4E, 0x58D5, 0x495C,
      0x3DE3, 0x2C6A, 0x1EF1, 0x0F78 };

// changed strlen to sizeof for dest_addr

static const uint8_t AX25_SYNC_FLAG_MAP_BIN[8] = {0, 1, 1, 1, 1, 1, 1, 0};
uint8_t interm_send_buf[AX25_PREAMBLE_LEN + AX25_POSTAMBLE_LEN
			+ AX25_MAX_FRAME_LEN + AX25_MAX_ADDR_LEN] = {0};
uint8_t tmp_bit_buf[(AX25_PREAMBLE_LEN + AX25_POSTAMBLE_LEN
    + AX25_MAX_FRAME_LEN + AX25_MAX_ADDR_LEN) * 8] = {0};
uint8_t tmp_buf[AX25_MAX_FRAME_LEN * 2] = {0};

uint8_t SSID = 97;
uint8_t DEST_SSID = 224;
const uint8_t CALLSIGN[5] = {"N7LEM"};
const uint8_t DEST_CALLSIGN[4] = {"NJ7P"};
uint8_t AX25_CTRL = 3;

uint16_t ax25_fcs (uint8_t *buffer, size_t len)
{
  uint16_t fcs = 0xFFFF;
  while (len--) {
    fcs = (fcs >> 8) ^ crc16_ccitt_table_reverse[(fcs ^ *buffer++) & 0xFF];
  }
  return fcs ^ 0xFFFF;
}

size_t ax25_create_addr_field (uint8_t *out, const uint8_t  *dest_addr,
			uint8_t dest_ssid,
			const uint8_t *src_addr, uint8_t src_ssid)
{
  uint16_t i = 0;
  
  for (i = 0; i < sizeof (dest_addr); i++) {
    *out++ = dest_addr[i] << 1;
  }
  /*
   * Perhaps the destination callsign was smaller that the maximum allowed.
   * In this case the leftover bytes should be filled with space
   */
  for (; i < AX25_CALLSIGN_MAX_LEN; i++) {
    *out++ = ' ' << 1;
  }
  /* Apply SSID, reserved and C bit */
  /* FIXME: C bit is set to 0 implicitly */
  *out++ = ((0x0F & dest_ssid) << 1) | 0x60;
  //*out++ = ((0b1111 & dest_ssid) << 1) | 0b01100000;

  for (i = 0; i < sizeof (src_addr); i++) {
    *out++ = dest_addr[i] << 1;
  }
  for (; i < AX25_CALLSIGN_MAX_LEN; i++) {
    *out++ = ' ' << 1;
  }
  /* Apply SSID, reserved and C bit. As this is the last address field
   * the trailing bit is set to 1.
   */
  /* FIXME: C bit is set to 0 implicitly */
  *out++ = ((0x0F & dest_ssid) << 1) | 0x61;
  //*out++ = ((0b1111 & dest_ssid) << 1) | 0b01100001;
  return (size_t) AX25_MIN_ADDR_LEN;
}

size_t ax25_prepare_frame (uint8_t *out, const uint8_t *info, size_t info_len,
		    ax25_frame_type_t type, uint8_t *addr, size_t addr_len,
		    uint16_t ctrl, size_t ctrl_len)
{
  uint16_t fcs;
  size_t i;
  if (info_len > AX25_MAX_FRAME_LEN) {
    return 0;
  }


  /* Repeat the AX.25 sync flag a pre-defined number of times */
  memset(out, AX25_SYNC_FLAG, AX25_PREAMBLE_LEN);
  i = AX25_PREAMBLE_LEN;

  /* Insert address and control fields */
  if (addr_len == AX25_MIN_ADDR_LEN || addr_len == AX25_MAX_ADDR_LEN) {
    memcpy (out + i, addr, addr_len);
    i += addr_len;
  }
  else {
    return 0;
  }

  if (ctrl_len == AX25_MIN_CTRL_LEN || ctrl_len == AX25_MAX_CTRL_LEN) {
    memcpy (out + i, &ctrl, ctrl_len);
    i += ctrl_len;
  }
  else {
    return 0;
  }

  /*
   * Set the PID depending the frame type.
   * FIXME: For now, only the "No layer 3 is implemented" information is
   * inserted
   */
  if (type == AX25_I_FRAME || type == AX25_UI_FRAME) {
    out[i++] = 0xF0;
  }
  memcpy (out + i, info, info_len);
  i += info_len;

  /* Compute the FCS. Ignore the AX.25 preamble */
  fcs = ax25_fcs (out + AX25_PREAMBLE_LEN, i - AX25_PREAMBLE_LEN);

  /* The MS bits are sent first ONLY at the FCS field */
  out[i++] = fcs & 0xFF;
  out[i++] = (fcs >> 8) & 0xFF;

  /* Append the AX.25 postample*/
  memset(out+i, AX25_SYNC_FLAG, AX25_POSTAMBLE_LEN);
  return i + AX25_POSTAMBLE_LEN;
}

ax25_encode_status_t ax25_bit_stuffing (uint8_t *out, size_t *out_len, const uint8_t *buffer,
		   const size_t buffer_len)
{
  uint8_t bit;
  uint8_t shift_reg = 0x0;
  size_t out_idx = 0;
  size_t i;

  /* Leading FLAG field does not need bit stuffing */
  for(i = 0; i < AX25_PREAMBLE_LEN; i++){
    memcpy (out + out_idx, AX25_SYNC_FLAG_MAP_BIN, 8);
    out_idx += 8;
  }

  /* Skip the AX.25 preamble and postable */
  buffer += AX25_PREAMBLE_LEN;
  for (i = 0; i < 8 * (buffer_len - AX25_PREAMBLE_LEN - AX25_POSTAMBLE_LEN); i++) {
    bit = (buffer[i / 8] >> (i % 8)) & 0x1;
    shift_reg = (shift_reg << 1) | bit;
    out[out_idx++] = bit;
    /* Check if bit stuffing should be applied */
    if((shift_reg & 0x1F) == 0x1F){
      out[out_idx++] = 0;
      shift_reg = 0x0;
    }
  }

  /*Postamble does not need bit stuffing */
  for(i = 0; i < AX25_POSTAMBLE_LEN; i++){
    memcpy (out + out_idx, AX25_SYNC_FLAG_MAP_BIN, 8);
    out_idx += 8;
  }

  *out_len = out_idx;
  return AX25_ENC_OK;
}

int32_t ax25_send(uint8_t *out, const uint8_t *in, size_t len, uint8_t is_wod)
{
  ax25_encode_status_t status;
  uint8_t addr_buf[AX25_MAX_ADDR_LEN] = {0};
  size_t addr_len = 0;
  size_t interm_len;
  size_t ret_len;
  size_t i;
  size_t pad_bits = 0;
  //uint8_t dest_ssid = is_wod ? __UPSAT_DEST_SSID_WOD :__UPSAT_DEST_SSID;
  uint8_t dest_ssid = DEST_SSID;

  /* Create the address field */
  addr_len = ax25_create_addr_field (addr_buf,
				     (const uint8_t *) DEST_CALLSIGN,
				     dest_ssid,
				     (const uint8_t *) CALLSIGN,
				     SSID);

  /*
   * Prepare address and payload into one frame placing the result in
   * an intermediate buffer
   */
  interm_len = ax25_prepare_frame (interm_send_buf, in, len, AX25_UI_FRAME,
				   addr_buf, addr_len, AX25_CTRL, 1);
  if(interm_len == 0){
    return -1;
  }

  status = ax25_bit_stuffing(tmp_bit_buf, &ret_len, interm_send_buf, interm_len);
  if( status != AX25_ENC_OK){
    return -1;
  }

  /* Pack now the bits into full bytes */
  memset(interm_send_buf, 0, sizeof(interm_send_buf));
  for (i = 0; i < ret_len; i++) {
    interm_send_buf[i/8] |= tmp_bit_buf[i] << (i % 8);
  }

  /*Perhaps some padding is needed due to bit stuffing */
  if(ret_len % 8){
    pad_bits = 8 - (ret_len % 8);
  }
  ret_len += pad_bits;

  /* Perform NRZI and scrambling based on the G3RUH polynomial 
  scrambler_init (&h_scrabler, __SCRAMBLER_POLY, __SCRAMBLER_SEED,
		  __SCRAMBLER_ORDER);
  scrambler_reset(&h_scrabler);
  scramble_data_nrzi(&h_scrabler, out, interm_send_buf,
		     ret_len/8);
	*/
  /* AX.25 sends LS bit first*/
  /*
  for(i = 0; i < ret_len/8; i++){
    out[i] = reverse_byte(out[i]);
  }
  */

  return addr_len;
}

uint8_t * get_ax25(const uint8_t payload[50]) {
	uint8_t *out = {0};
	ax25_send(out, payload, 50, 0);

  return &interm_send_buf[0];
}

/* These three functions must be provided in arch specific way */
int router_start(void);
int server_start(void);
int client_start(void);

/* Server port, the port the server listens on for incoming connections from the client. */
#define MY_SERVER_PORT		10

/* Commandline options */
static uint8_t server_address = 255;

/* test mode, used for verifying that host & client can exchange packets over the loopback interface */
static bool test_mode = false;
static unsigned int server_received = 0;

/* Server task - handles requests from clients */
void server(void) {

	csp_print("Server task started\n");

	/* Create socket with no specific socket options, e.g. accepts CRC32, HMAC, etc. if enabled during compilation */
	csp_socket_t sock = {0};

	/* Bind socket to all ports, e.g. all incoming connections will be handled here */
	csp_bind(&sock, CSP_ANY);

	/* Create a backlog of 10 connections, i.e. up to 10 new connections can be queued */
	csp_listen(&sock, 10);

	/* Wait for connections and then process packets on the connection */
	while (1) {

		/* Wait for a new connection, 10000 mS timeout */
		csp_conn_t *conn;
		if ((conn = csp_accept(&sock, 10000)) == NULL) {
			/* timeout */
			continue;
		}

		/* Read packets on connection, timout is 100 mS */
		csp_packet_t *packet;
		while ((packet = csp_read(conn, 50)) != NULL) {
			switch (csp_conn_dport(conn)) {
			case MY_SERVER_PORT:
				/* Process packet here */
				//csp_print("Packet received on MY_SERVER_PORT: %d\n", (char *) packet->data);

				for (int i=0; i<AX25_MAX_FRAME_LEN; i++) {
					printf("%d", *(packet->data + i));
				}

				csp_buffer_free(packet);
				++server_received;
				break;

			default:
				/* Call the default CSP service handler, handle pings, buffer use, etc. */
				csp_service_handler(packet);
				break;
			}
		}

		/* Close current connection */
		csp_close(conn);

	}

	return;

}
/* End of server task */

/* Client task sending requests to server task */
void client(void) {

	csp_print("Client task started");

	//unsigned int count = 'A';

	while (1) {

		usleep(test_mode ? 200000 : 1000000);

		/* Send ping to server, timeout 1000 mS, ping size 100 bytes */
		int result = csp_ping(server_address, 1000, 100, CSP_O_NONE);
		csp_print("Ping address: %u, result %d [mS]\n", server_address, result);
        (void) result;

		/* Send reboot request to server, the server has no actual implementation of csp_sys_reboot() and fails to reboot */
		csp_reboot(server_address);
		csp_print("reboot system request sent to address: %u\n", server_address);

		/* Send data packet (string) to server */

		/* 1. Connect to host on 'server_address', port MY_SERVER_PORT with regular UDP-like protocol and 1000 ms timeout */
		csp_conn_t * conn = csp_connect(CSP_PRIO_NORM, server_address, MY_SERVER_PORT, 1000, CSP_O_NONE);
		if (conn == NULL) {
			/* Connect failed */
			csp_print("Connection failed\n");
			return;
		}

		/* 2. Get packet buffer for message/data */
		csp_packet_t * packet = csp_buffer_get(100);
		if (packet == NULL) {
			/* Could not get buffer element */
			csp_print("Failed to get CSP buffer\n");
			return;
		}

		/* 3. Copy data to packet */
       // memcpy(packet->data, "Hello world ", 12);
       // memcpy(packet->data + 12, &count, 1);
       // memset(packet->data + 13, 0, 1);
       // count++;

	const uint8_t payload[50] = {"hello world"};
	uint8_t * send_buf = get_ax25(payload);

	for (int i=0; i<AX25_MAX_FRAME_LEN; i++) {
		memcpy(packet->data + i, send_buf + i, sizeof(*(send_buf + i)));
	}

		/* 4. Set packet length */
		packet->length = (strlen((char *) packet->data) + 1); /* include the 0 termination */

		/* 5. Send packet */
		csp_send(conn, packet);

		/* 6. Close connection */
		csp_close(conn);
	}

	return;
}
/* End of client task */

/* main - initialization of CSP and start of server/client tasks */
int main(int argc, char * argv[]) {

    uint8_t address = 0;
#if (CSP_HAVE_LIBSOCKETCAN)
    const char * can_device = NULL;
#endif
    const char * kiss_device = NULL;
#if (CSP_HAVE_LIBZMQ)
    const char * zmq_device = NULL;
#endif
    const char * rtable = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "a:d:r:c:k:z:tR:h")) != -1) {
        switch (opt) {
            case 'a':
                address = atoi(optarg);
                break;
            case 'r':
                server_address = atoi(optarg);
                break;
#if (CSP_HAVE_LIBSOCKETCAN)
            case 'c':
                can_device = optarg;
                break;
#endif
            case 'k':
                kiss_device = optarg;
                break;
#if (CSP_HAVE_LIBZMQ)
            case 'z':
                zmq_device = optarg;
                break;
#endif
            case 't':
                test_mode = true;
                break;
            case 'R':
                rtable = optarg;
                break;
            default:
                csp_print("Usage:\n"
                       " -a <address>     local CSP address\n"
                       " -d <debug-level> debug level, 0 - 6\n"
                       " -r <address>     run client against server address\n"
                       " -c <can-device>  add CAN device\n"
                       " -k <kiss-device> add KISS device (serial)\n"
                       " -z <zmq-device>  add ZMQ device, e.g. \"localhost\"\n"
                       " -R <rtable>      set routing table\n"
                       " -t               enable test mode\n");
                exit(1);
                break;
        }
    }

    csp_print("Initialising CSP");

    /* Init CSP */
    csp_init();

    /* Start router */
    router_start();

    /* Add interface(s) */
    csp_iface_t * default_iface = NULL;
    if (kiss_device) {
        csp_usart_conf_t conf = {
            .device = kiss_device,
            .baudrate = 115200, /* supported on all platforms */
            .databits = 8,
            .stopbits = 1,
            .paritysetting = 0,
            .checkparity = 0};
        int error = csp_usart_open_and_add_kiss_interface(&conf, CSP_IF_KISS_DEFAULT_NAME,  &default_iface);
        if (error != CSP_ERR_NONE) {
            csp_print("failed to add KISS interface [%s], error: %d\n", kiss_device, error);
            exit(1);
        }
    }
#if (CSP_HAVE_LIBSOCKETCAN)
    if (can_device) {
        int error = csp_can_socketcan_open_and_add_interface(can_device, CSP_IF_CAN_DEFAULT_NAME, 0, false, &default_iface);
        if (error != CSP_ERR_NONE) {
            csp_print("failed to add CAN interface [%s], error: %d\n", can_device, error);
            exit(1);
        }
    }
#endif
#if (CSP_HAVE_LIBZMQ)
    if (zmq_device) {
        int error = csp_zmqhub_init(0, zmq_device, 0, &default_iface);
        if (error != CSP_ERR_NONE) {
            csp_print("failed to add ZMQ interface [%s], error: %d\n", zmq_device, error);
            exit(1);
        }
    }
#endif

    if (rtable) {
        int error = csp_rtable_load(rtable);
        if (error < 1) {
            csp_print("csp_rtable_load(%s) failed, error: %d\n", rtable, error);
            exit(1);
        }
    } else if (default_iface) {
        csp_rtable_set(0, 0, default_iface, CSP_NO_VIA_ADDRESS);
    } else {
        /* no interfaces configured - run server and client in process, using loopback interface */
        server_address = address;
    }

    csp_print("Connection table\r\n");
    csp_conn_print_table();

    csp_print("Interfaces\r\n");
    csp_iflist_print();

    csp_print("Route table\r\n");
    csp_rtable_print();

    /* Start server thread */
    if ((server_address == 255) ||  /* no server address specified, I must be server */
        (default_iface == NULL)) {  /* no interfaces specified -> run server & client via loopback */
        server_start();
    }

    /* Start client thread */
    if ((server_address != 255) ||  /* server address specified, I must be client */
        (default_iface == NULL)) {  /* no interfaces specified -> run server & client via loopback */
        client_start();
    }

    /* Wait for execution to end (ctrl+c) */
    while(1) {
        sleep(3);

        if (test_mode) {
            /* Test mode is intended for checking that host & client can exchange packets over loopback */
            if (server_received < 5) {
                csp_print("Server received %u packets\n", server_received);
                exit(1);
            }
            csp_print("Server received %u packets\n", server_received);
            exit(0);
        }
    }

    return 0;
}
