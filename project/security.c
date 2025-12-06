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

// Store Client Hello and Server Hello buffers globally
static uint8_t ch_buf[1000];
static uint16_t ch_len;
static uint8_t sh_buf[1000];
static uint16_t sh_len;

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


const uint8_t* prep_data_to_sign(uint8_t* ch_buf, uint8_t* nonce_buf, uint8_t* pk_buf, \
                                 uint16_t ch_len, uint16_t nn_len, uint16_t pk_len){
    uint16_t size = ch_len + nn_len + pk_len + cert_size;
    uint8_t* to_sign = malloc(size);
    if(!to_sign){
        error("Failed to allocate memory for data to be signed");
    }

    uint8_t* p = to_sign;

    memcpy(p, ch_buf, ch_len);
    p += ch_len;

    memcpy(p, nonce_buf, nn_len);
    p += nn_len;

    memcpy(p, certificate, cert_size);
    p += cert_size;

    memcpy(p, pk_buf, pk_len);
    p += pk_len;

    return to_sign;
}

// uint8_t* prep_salt(tlv* client_hello,tlv* server_hello, uint8_t* ch_buf, uint8_t* sh_buf, \
//                    uint16_t ch_len, uint16_t sh_len){
//     uint8_t* salt_buf = malloc(ch_len + sh_len);
//     if (!salt_buf){
//         error("Error allocating memory for salt buffer");
//     }

//     uint8_t* p = salt_buf;

//     memcpy(p, ch_buf, ch_len);
//     p += ch_len;

//     memcpy(p, sh_buf, sh_len);
//     p += sh_len;

//     return salt_buf;
// }

// void generate_keys(uint8_t* salt, size_t size){
//     tlv* c_pub_key_tlv = get_tlv(client_hello, PUBLIC_KEY);

//     const uint8_t* c_pub_key = c_pub_key_tlv->val;
//     uint16_t c_pub_key_len = c_pub_key_tlv->length;

//     // Store client public key in ec_peer_public_key
//     load_peer_public_key(c_pub_key, c_pub_key_len);

//     // Derive secret with ec_peer_public_key and our private key
//     derive_secret();

//     derive_keys(salt, size);
// }

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

        // Save Client Hello buffer and length globally
        memcpy(ch_buf, buf, len);
        ch_len = len;

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

        // spec says "certificate is already encoded as TLV 0xA0"
        tlv* cert_tlv = deserialize_tlv(certificate, cert_size);
        add_tlv(server_hello, cert_tlv);

        // TODO: I think this is what the spec refers to as the "ephemeral key" but
        // could be mistaken..
        load_private_key("server_key.bin");
        derive_public_key();

        tlv* p_key = create_pubkey_tlv();
        add_tlv(server_hello, p_key);

        // I'm not sure if client_hello->length + 4 is the max possible length or not
        uint16_t ch_max_len = client_hello->length + 4;

        uint8_t* ch_buf = malloc(ch_max_len);
        uint8_t* nn_buf = malloc(NONCE_SIZE + 4);
        uint8_t* pk_buf = malloc(p_key->length + 4);

        if(!ch_buf || !nn_buf || !pk_buf){
            error("Error allocating memory for buffer");
        }

        // Get lengths of Client Hello and Nonce, PK TLVs
        uint16_t ch_len = serialize_tlv(ch_buf, client_hello);
        uint16_t nn_len = serialize_tlv(nn_buf, nn);
        uint16_t pk_len = serialize_tlv(pk_buf, p_key);

        // Sign Server-Hello message
        uint8_t* sig_buf = malloc(MAX_SIG_LENGTH);
        size_t size_to_sign = ch_len + nn_len + cert_size + pk_len;
        const uint8_t* to_sign = prep_data_to_sign(ch_buf, nn_buf, pk_buf, ch_len, nn_len, pk_len);

        size_t signed_len = sign(sig_buf, to_sign, size_to_sign);

        // Add Signature TLV to Server Hello
        tlv* sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig, sig_buf, signed_len);
        add_tlv(server_hello, sig);

        // Prepare salt
        uint8_t salt[sizeof(ch_buf) + sizeof(sh_buf)];
        uint16_t salt_len = ch_len + sh_len;
        memcpy(salt, ch_buf, ch_len);
        memcpy(salt + ch_len, sh_buf, sh_len);

        // Derive secret and keys
        derive_secret();
        derive_keys(salt, salt_len);

        uint16_t len = serialize_tlv(buf, server_hello);

        state_sec = SERVER_FINISHED_AWAIT;

        return len;

    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");

        // Compute HMAC over transcript
        uint8_t digest[MAC_SIZE];
        uint8_t transcript[sizeof(ch_buf) + sizeof(sh_buf)];
        uint16_t transcript_len = ch_len + sh_len;
        memcpy(transcript, ch_buf, ch_len);
        memcpy(transcript + ch_len, sh_buf, sh_len);

        hmac(digest, transcript, transcript_len);

        // Build Transcript TLV
        tlv* tr = create_tlv(TRANSCRIPT);
        add_val(tr, digest, MAC_SIZE);

        // Build Finished TLV
        tlv* fin = create_tlv(FINISHED);
        add_tlv(fin, tr);

        uint16_t len = serialize_tlv(buf, fin);
        free_tlv(fin);

        // Advance state
        state_sec = DATA_STATE;

        return len;
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
        // Receive Server Hello TLV
        server_hello = deserialize_tlv(buf, length);
        memcpy(sh_buf, buf, length);
        sh_len = length;

        if (!server_hello){
            error("TLV packet from Server Hello malformed");
        }

        // Extract server public key from Server Hello
        tlv* sh_pk = get_tlv(server_hello, PUBLIC_KEY);
        load_peer_public_key(sh_pk->val, sh_pk->length);

        // Verify handshake signature, certificate
        tlv* cert = get_tlv(server_hello, CERTIFICATE);
        if (!cert){
            error("No certificate found in Server Hello");
        }

        tlv* dns = get_tlv(cert, DNS_NAME);
        tlv* cert_pub = get_tlv(cert, PUBLIC_KEY);
        tlv* lifetime = get_tlv(cert, LIFETIME);
        tlv* cert_sig = get_tlv(cert, SIGNATURE);
        if (!dns || !cert_pub || !lifetime || !cert_sig){
            error("Certificate missing required fields");
        }

        // Check DNS name
        if (hostname == NULL || strcmp((char*) dns->val, hostname) != 0){
            error("Certificate DNS name does not match hostname");
        }

        // TODO: Verify certificate signature not working yet

        uint8_t cert_data[1500];
        uint16_t cd_len = 0;

        cd_len += serialize_tlv(cert_data + cd_len, dns);
        cd_len += serialize_tlv(cert_data + cd_len, cert_pub);
        cd_len += serialize_tlv(cert_data + cd_len, lifetime);

        load_ca_public_key("ca_public_key.bin");

        int ok = verify(cert_sig->val, cert_sig->length,
                        cert_data, cd_len,
                        ec_ca_public_key);

        if (!ok){
            error("Certificate verification failed");
        }

        // Prepare salt
        uint8_t salt[sizeof(ch_buf) + sizeof(sh_buf)];
        uint16_t salt_len = ch_len + sh_len;
        memcpy(salt, ch_buf, ch_len);
        memcpy(salt + ch_len, sh_buf, sh_len);

        // Derive secret and keys
        derive_secret();
        derive_keys(salt, salt_len);

        state_sec = CLIENT_FINISHED_SEND;
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        break;
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
        break;
    }
    default:
        break;
    }
}
