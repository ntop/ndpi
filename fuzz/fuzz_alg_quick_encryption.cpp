#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdlib.h>
#include <stdint.h>
#include "fuzzer/FuzzedDataProvider.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  char *enc_buffer, *dec_buffer;
  u_int16_t encrypted_msg_len, decrypted_msg_len;

  if(fuzzed_data.remaining_bytes() <= 64) /* Some data */
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  std::vector<unsigned char>key = fuzzed_data.ConsumeBytes<u_int8_t>(64);
  std::vector<char>cleartext_msg = fuzzed_data.ConsumeRemainingBytes<char>();

  enc_buffer = ndpi_quick_encrypt(cleartext_msg.data(), cleartext_msg.size(), &encrypted_msg_len, key.data());
  if(enc_buffer) {
    dec_buffer = ndpi_quick_decrypt(enc_buffer, encrypted_msg_len, &decrypted_msg_len, key.data());
    ndpi_free(enc_buffer);
    ndpi_free(dec_buffer);
  }
  return 0;
}
