#include <gtest/gtest.h>
#include <string>
extern "C" {
#include "ausy_encoder.h"
}
#include "deps/tinycbor/src/cbor.h"
#include "deps/tinycbor/src/cborjson.h"

using namespace std;

class Decoder
{
public:
    Decoder(const string& expected): m_expected{expected} {
        m_length = m_expected.length();
        m_payload = new uint8_t[m_length];
        for (size_t i = 0; i < m_length;  ++i)
        {
            m_payload[i] = (uint8_t)(m_expected[i]);
        }
    }
    ~Decoder() {delete m_payload;}
    void process();

    const string& m_expected;
    string m_result;
    uint8_t* m_payload = nullptr;
    size_t m_length = 0;
};

class PayloadEncoderTestFixture : public testing::TestWithParam<string>
{
public:
    PayloadEncoderTestFixture(): m_decoder(GetParam()) {}
protected:
    Decoder m_decoder;
};

void Decoder::process()
{
    FILE* out = NULL;
    CborValue cbor_value;
    CborParser cbor_parser;
    CborError err = cbor_parser_init(m_payload, m_length, 0, &cbor_parser, &cbor_value);
    out = fopen("payload.json", "w+");
    if (!out) {
        printf("payload.json failed to open!\n");
    } else {
        //printf("payload.json opened suscessfully!\n");
        err |= cbor_value_to_json(out, &cbor_value, 0);
        if (err == CborNoError) {
            // Move the file pointer to the start.
            fseek(out, 0, SEEK_SET);
            char str[100];
            if (fgets(str, 100, out) != NULL) {
             //printf("Decoded payload = %s\n", str);
             m_result = string(str);
            } else {
             printf("fgets return null ptr!\n");
            }
        } else {
            printf("Erreur when decoding the cbor payload!\n");
        }
        fclose(out);
    }
}


TEST_P(PayloadEncoderTestFixture, Payload) {
    const bool success = ausy_encode_payload_2_cbor(m_decoder.m_payload, m_decoder.m_length, TEXT_PLAIN);
    ASSERT_EQ(success, 1);
    m_decoder.process();
    EXPECT_EQ(m_decoder.m_result, m_decoder.m_expected);
}

INSTANTIATE_TEST_CASE_P(
        TestAusyEncoder,
        PayloadEncoderTestFixture,
        ::testing::Values(
            string("{\"value\":true}"),
            string("{\"9001\":\"Home office\",\"9003\":131087,\"9018\":{\"15002\":{\"9003\":[65558,65561]}}}")
            )
        );
