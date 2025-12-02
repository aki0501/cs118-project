#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "consts.h"
#include "io.h"
#include "libsecurity.h"

int state_sec = 0;     // Current state for handshake
char* hostname = NULL; // For client: storing inputted hostname
EVP_PKEY* priv_key = NULL;
tlv* client_hello = NULL;
tlv* server_hello = NULL;

uint8_t ts[1000] = {0};
uint16_t ts_len = 0;

bool inc_mac = false;  // For testing only: send incorrect MACs


void init_sec(int initial_state, char* host, bool bad_mac) {
    state_sec = initial_state;
    hostname = host;
    inc_mac = bad_mac;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        // Generate private key
        generate_private_key();

        // Derive public key from private key
        // Will be stored in public_key global variable
        derive_public_key();
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        client_hello = create_tlv(CLIENT_HELLO);

        // Generate nonce
        uint8_t *nonce_buf = malloc(NONCE_SIZE);

        if (!nonce_buf){
            error("Failed to allocate buffer for nonce");
        }

        // Add Nonce TLV to Client Hello
        tlv* nn = create_tlv(NONCE);

        generate_nonce(nonce_buf, NONCE_SIZE);
        add_val(nn, nonce_buf, NONCE_SIZE);
        add_tlv(client_hello, nn);

        // Add Public Key TLV to Client Hello
        tlv* p_key = create_tlv(PUBLIC_KEY);

        add_val(p_key, public_key, pub_key_size);

        add_tlv(client_hello, p_key);


        // Send data to transport layer, save length of data sent
        uint16_t len = serialize_tlv(buf, client_hello);
        

        free_tlv(client_hello);

        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");
    }
    case DATA_STATE: {
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        client_hello = deserialize_tlv(buf, length);
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
    }
    case SERVER_FINISHED_AWAIT: {
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
    }
    default:
        break;
    }
}