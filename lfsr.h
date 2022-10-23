#ifndef INC_LFSR_H_
#define INC_LFSR_H_

#include <stdint.h>

typedef struct {
  uint32_t mask;
  uint32_t seed;
  uint32_t order;
  uint32_t shift_reg;
} lfsr_handle_t;

int32_t
lfsr_init(lfsr_handle_t *h, uint32_t mask, uint32_t seed, uint32_t order);

uint8_t
lfsr_next_bit(lfsr_handle_t *h);

uint8_t
lfsr_next_bit_scramble(lfsr_handle_t *h, uint8_t bit);

uint8_t
lfsr_next_bit_descramble(lfsr_handle_t *h, uint8_t bit);

int32_t
lfsr_reset(lfsr_handle_t *h);


#endif /* INC_LFSR_H_ */
