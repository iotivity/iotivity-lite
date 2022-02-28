#ifndef AUSY_ENCODER_H
#define AUSY_ENCODER_H

#include "oc_ri.h"

bool ausy_encode_payload_2_cbor(const uint8_t* payload,
                                const size_t payload_len,
                                const oc_content_format_t cf);

#endif // AUSY_ENCODER_H

