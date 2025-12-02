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

#define MAX_SIG_LENGTH 72

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
        // Will be stored in public_key global variable, pub_key_size is length
        derive_public_key();
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {

    }
}

uint8_t* create_nonce_buf(){
    uint8_t *nonce_buf = malloc(NONCE_SIZE);

    if (!nonce_buf){
        error("Failed to allocate buffer for nonce");
    }

    return nonce_buf;
}

tlv* create_nonce_tlv(uint8_t* nonce_buf){
    tlv* nn = create_tlv(NONCE);

    generate_nonce(nonce_buf, NONCE_SIZE);
    add_val(nn, nonce_buf, NONCE_SIZE);
    
    return nn;
}

tlv* create_pubkey_tlv(){
    tlv* p_key = create_tlv(PUBLIC_KEY);

    add_val(p_key, public_key, pub_key_size);

    return p_key;
}

tlv* create_cert_tlv(uint8_t* cert){
    tlv* cert_tlv = create_tlv(CERTIFICATE);

    add_val(cert_tlv, cert, cert_size);

    return cert_tlv;
}

const uint8_t* prep_data_to_sign(tlv* client_hello, uint8_t* nonce_buf, size_t size){
    const size_t ch_max_len = client_hello->length + 4;
    // Serialize client_hello
    uint8_t* ch_buf = malloc(ch_max_len);
    if (!ch_buf){
        error("Error allocating memory for client hello buffer in prep_data_to_sign");
    }

    uint16_t ch_len = serialize_tlv(ch_buf, client_hello);

    uint8_t* to_sign = malloc(size);
    if(!to_sign){
        error("Failed to allocate memory for data to be signed");
    }

    uint8_t* p = to_sign;

    memcpy(p, ch_buf, ch_len);
    p += ch_len;

    memcpy(p, nonce_buf, NONCE_SIZE);
    p += NONCE_SIZE;

    memcpy(p, certificate, cert_size);
    p += cert_size;

    memcpy(p, public_key, pub_key_size);
    p += pub_key_size;

    return to_sign;
}

uint8_t* prep_salt(tlv* client_hello,tlv* server_hello, uint8_t* ch_buf, uint8_t* sh_buf, uint16_t ch_len, uint16_t sh_len){
    uint8_t* salt_buf = malloc(ch_len + sh_len);
    if (!salt_buf){
        error("Error allocating memory for salt buffer");
    }

    uint8_t* p = salt_buf;

    memcpy(salt_buf, ch_buf, ch_len);
    p += ch_len;

    memcpy(salt_buf, sh_buf, sh_len);
    p += sh_len;

    return salt_buf;
}

void generate_keys(uint8_t* salt, size_t size){
    tlv* c_pub_key_tlv = get_tlv(client_hello, PUBLIC_KEY);

    const uint8_t* c_pub_key = c_pub_key_tlv->val;
    uint16_t c_pub_key_len = c_pub_key_tlv->length;

    // Store client public key in ec_peer_public_key
    load_peer_public_key(c_pub_key, c_pub_key_len);

    // Derive secret with ec_peer_public_key and our private key
    derive_secret();

    derive_keys(salt, size);
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        client_hello = create_tlv(CLIENT_HELLO);

        // Generate nonce
        uint8_t *nonce_buf = create_nonce_buf();

        // Add Nonce TLV to Client Hello
        tlv* nn = create_nonce_tlv(nonce_buf);
        add_tlv(client_hello, nn);

        // Add Public Key TLV to Client Hello
        tlv* p_key = create_pubkey_tlv();
        add_tlv(client_hello, p_key);


        // Send data to transport layer, save length of data sent
        uint16_t len = serialize_tlv(buf, client_hello);

        //TODO: check if len is greater than max_length?

        free_tlv(client_hello);

        state_sec = CLIENT_SERVER_HELLO_AWAIT;

        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        server_hello = create_tlv(SERVER_HELLO);

        uint8_t* nonce_buf = create_nonce_buf();
        tlv* nn = create_nonce_tlv(nonce_buf);
        add_tlv(server_hello, nn);

        // Load certificate
        // Certificate stored in certificate, length in cert_size
        load_certificate("server_cert.bin");
        print_tlv_bytes(certificate, cert_size);

        // spec says "certificate is already encoded as TLV 0xA0" but its uint8_t*
        tlv *cert_tlv = create_cert_tlv(certificate);
        add_tlv(server_hello, cert_tlv);

        // I think this is what the spec refers to as the "ephemeral key" but
        // could be mistaken..
        load_private_key("server_key.bin");
        derive_public_key();

        tlv* p_key = create_pubkey_tlv();
        add_tlv(server_hello, p_key);

        // I'm not sure if client_hello->length + 4 is the max possible length or not
        uint16_t ch_max_len = client_hello->length + 4;
        uint16_t sh_max_len = server_hello->length + 4;

        uint8_t* ch_buf = malloc(ch_max_len);
        if(!ch_buf){
            error("Error allocating memory for client hello buffer");
        }
        // Get length of Client Hello
        uint16_t ch_len = serialize_tlv(ch_buf, client_hello);

        // Sign Server-Hello message
        uint8_t* sig_buf = malloc(MAX_SIG_LENGTH);
        size_t size_to_sign = ch_len + NONCE_SIZE + cert_size + pub_key_size;
        const uint8_t* to_sign = prep_data_to_sign(client_hello, nonce_buf, size_to_sign);

        size_t signed_len = sign(sig_buf, to_sign, size_to_sign);

        // Add Signature TLV to Server Hello
        tlv* sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig, sig_buf, signed_len);
        add_tlv(server_hello, sig);

        uint8_t* sh_buf = malloc(sh_max_len);
        if(!sh_buf){
            error("Error allocating memory for server hello buffer");
        }
        // Get current length of Server Hello
        uint16_t sh_len = serialize_tlv(sh_buf, server_hello);

        // Create salt from client hello appended by server hello
        const uint8_t* salt = prep_salt(client_hello, server_hello, ch_buf, sh_buf, ch_len, sh_len);
        
        generate_keys(salt, ch_len + sh_len);

        uint16_t len = serialize_tlv(buf, server_hello);

        state_sec = SERVER_FINISHED_AWAIT;

        return len;

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

        if (!client_hello){
            error("TLV packet from Client Hello malformed");
        }

        print_tlv_bytes(client_hello, length);

        tlv* nn = get_tlv(client_hello, NONCE);

        tlv* ch_pk = get_tlv(client_hello, PUBLIC_KEY);

        uint8_t* client_pub_key = ch_pk->val;
        uint16_t client_pkey_len = ch_pk->length;

        // Store public key sent over Client Hello  in ec_peer_public_key
        load_peer_public_key(client_pub_key, client_pkey_len);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
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