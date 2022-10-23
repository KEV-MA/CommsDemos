#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "coms_ax25.h"

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
  
  for (i = 0; i < sizeof (dest_addr, AX25_CALLSIGN_MAX_LEN); i++) {
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

  for (i = 0; i < sizeof (src_addr, AX25_CALLSIGN_MAX_LEN); i++) {
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
  /* AX.25 sends LS bit first
  for(i = 0; i < ret_len/8; i++){
    out[i] = reverse_byte(out[i]);
  }
  */

  return addr_len;
}

void get_ax25() {
	uint8_t *out;
	const uint8_t payload[50] = {"hello world"};
	ax25_send(out, payload, sizeof(payload), 0);

  
	uint8_t *out_p = &interm_send_buf[0];
	for (int i=0; i<sizeof(interm_send_buf); i++) {
		printf("%d ", *(out_p+i));
	}
  

  //return interm_send_buf;
}


int main(int argc, char ** argv) {

  get_ax25();

	return 0;
}

