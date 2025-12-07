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
#define BLOCK_SIZE 16 // Block size for plaintext
#define MAX_CIPHERTEXT_LEN 950
#define MAX_PLAINTEXT_LEN 943

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
        if (len > max_length) {
            error("Client Hello length exceeds maximum length");
        }

        // Save Client Hello buffer and length globally
        memcpy(ch_buf, buf, len);
        ch_len = len;

        // Cleanup
        free_tlv(client_hello);
        free(nonce_buf); // from create_nonce_buf

        state_sec = CLIENT_SERVER_HELLO_AWAIT;

        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        // Create Server Hello TLV
        server_hello = create_tlv(SERVER_HELLO);

        // Generate nonce
        uint8_t* nonce_buf = create_nonce_buf();
        tlv* nn = create_nonce_tlv(nonce_buf);
        add_tlv(server_hello, nn);

        // Load certificate
        load_certificate("server_cert.bin");

        // Add Certificate TLV to Server Hello
        tlv* cert_tlv = deserialize_tlv(certificate, cert_size);
        add_tlv(server_hello, cert_tlv);

        // Generate ephemeral key pair
        load_private_key("server_key.bin");
        derive_public_key();

        tlv* p_key = create_pubkey_tlv();
        add_tlv(server_hello, p_key);

        uint8_t* nn_buf = malloc(NONCE_SIZE + 4);
        uint8_t* pk_buf = malloc(p_key->length + 4);

        if(!nn_buf || !pk_buf){
            error("Error allocating memory for buffer");
        }

        // Get lengths of Client Hello and Nonce, PK TLVs
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

        // Update sh_buf and sh_len globals
        uint16_t cur_sh_len = serialize_tlv(buf, server_hello);
        memcpy(sh_buf, buf, cur_sh_len);
        sh_len = cur_sh_len;

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

        // Free allocated buffers
        free(nonce_buf); // from create_nonce_buf
        free(nn_buf);
        free(pk_buf);
        free(sig_buf);
        free(to_sign); // from prep_data_to_sign

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
        print("SENDING DATA");

        // Read plaintext from IO
        uint8_t plaintext[MAX_PLAINTEXT_LEN];
        ssize_t plain_len = input_io(plaintext, MAX_PLAINTEXT_LEN);
        if (plain_len <= 0) {
            return 0;
        }

        // Allocate and zero IV
        uint8_t iv[IV_SIZE];
        memset(iv, 0, IV_SIZE);

        // Allocate and zero cipher buffer
        uint8_t* cipher = malloc(plain_len + 16);
        if (!cipher) {
            return 0;
        }
        memset(cipher, 0, plain_len + 16);

        // Encrypt data
        size_t cipher_len = encrypt_data(iv, cipher, plaintext, plain_len);

        // Allocate and zero MAC buffer
        uint8_t mac[MAC_SIZE];
        uint8_t* mac_data = malloc(IV_SIZE + cipher_len);
        if (!mac_data) {
            free(cipher);
            return 0;
        }
        memset(mac_data, 0, IV_SIZE + cipher_len);

        // Create TLVs
        tlv* iv_tlv = create_tlv(IV);
        add_val(iv_tlv, iv, IV_SIZE);

        tlv* ct_tlv = create_tlv(CIPHERTEXT);
        add_val(ct_tlv, cipher, cipher_len);

        // Compute HMAC
        uint8_t temp[1500];
        uint16_t iv_len = serialize_tlv(temp, iv_tlv);
        uint16_t ct_len = serialize_tlv(temp + iv_len, ct_tlv);
        hmac(mac, temp, iv_len + ct_len);

        // Construct MAC TLV after HMAC computation
        tlv* mac_tlv = create_tlv(MAC);
        add_val(mac_tlv, mac, MAC_SIZE);

        // Wrap TLVs into DATA TLV
        tlv* data_tlv = create_tlv(DATA);
        add_tlv(data_tlv, iv_tlv);
        add_tlv(data_tlv, ct_tlv);
        add_tlv(data_tlv, mac_tlv);

        // Serialize TLV to network output buffer (buf)
        uint16_t data_len = serialize_tlv(buf, data_tlv);
        if (data_len > max_length) {
            error("DATA TLV length exceeds maximum length");
        }

        // Cleanup
        free_tlv(data_tlv);
        free(cipher);
        free(mac_data);

        print("DATA SENT");
        return data_len;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        client_hello = deserialize_tlv(buf, length);

        // Save Client Hello buffer and length globally
        memcpy(ch_buf, buf, length);
        ch_len = length;

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

        // Extract fields from Server Hello
        tlv* sh_pk = get_tlv(server_hello, PUBLIC_KEY);
        tlv* sh_nonce = get_tlv(server_hello, NONCE);
        tlv* sh_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);

        // Verify certificate
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

        // Load server's PK in cert
        load_peer_public_key(cert_pub->val, cert_pub->length);

        size_t temp_verify_sig_size = ch_len + (sh_nonce->length + 4) + (cert->length) + (sh_pk->length + 4);
        uint8_t* verify_sig_buf = malloc(temp_verify_sig_size);
        if (!verify_sig_buf){
            error("Error allocating buffer for verify sig");
        }

        // Pointer to copy data into buf
        uint8_t* p = verify_sig_buf;

        // Copy data into buf
        memcpy(p, ch_buf, ch_len);
        p += ch_len;

        p += serialize_tlv(p, sh_nonce); // will write into p and increment its length
        p += serialize_tlv(p, cert);
        p += serialize_tlv(p, sh_pk);

        size_t verify_sig_size = p - verify_sig_buf; // get actual length of buffer

        // Verify handshake-signature
        if (!verify(sh_sig->val, sh_sig->length, verify_sig_buf, verify_sig_size, ec_peer_public_key)){
            error("Handshake signature verification failed");
        }

        // Reload PK with ephemeral key to derive secret
        load_peer_public_key(sh_pk->val, sh_pk->length);

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
        print("RECEIVED CLIENT FINISHED");
        // Deserialize the FINISHED message from client
        tlv* fin = deserialize_tlv(buf, length);
        if (!fin) {
            error("Malformed FINISHED message from client");
        }

        // Extract the embedded TRANSCRIPT TLV
        tlv* tr = get_tlv(fin, TRANSCRIPT);
        if (!tr || tr->length != MAC_SIZE) {
            error("Invalid or missing HMAC in FINISHED message");
        }

        uint8_t* client_digest = tr->val;

        // Reconstruct the handshake transcript: Client Hello + Server Hello
        uint8_t transcript[sizeof(ch_buf) + sizeof(sh_buf)];
        uint16_t transcript_len = ch_len + sh_len;
        memcpy(transcript, ch_buf, ch_len);
        memcpy(transcript + ch_len, sh_buf, sh_len);

        // Compute server's own HMAC
        uint8_t server_digest[MAC_SIZE];
        hmac(server_digest, transcript, transcript_len);

        // Compare the computed HMAC with client's HMAC
        if (memcmp(server_digest, client_digest, MAC_SIZE) != 0) {
            error("HMAC mismatch: handshake verification failed");
            exit(4); // from the spec
        }

        state_sec = DATA_STATE;
        free_tlv(fin);
        break;
    }
    case DATA_STATE: {
        print("RECEIVED DATA");

        // Deserialize the DATA TLV
        tlv* data_tlv = deserialize_tlv(buf, length);
        if (!data_tlv) {
            error("Malformed DATA TLV");
            break;
        }

        // Extract IV, ciphertext, and MAC
        tlv* iv_tlv = get_tlv(data_tlv, IV);
        tlv* ct_tlv = get_tlv(data_tlv, CIPHERTEXT);
        tlv* mac_tlv = get_tlv(data_tlv, MAC);

        if (!iv_tlv || !ct_tlv || !mac_tlv) {
            free_tlv(data_tlv);
            error("Missing fields in DATA TLV");
        }

        // Validate ciphertext length
        if (ct_tlv->length > MAX_CIPHERTEXT_LEN) {
            free_tlv(data_tlv);
            error("Ciphertext length exceeds maximum allowed");
        }

        // Allocate buffer for HMAC verification
        uint8_t* mac_data = malloc(1500); // sufficiently large buffer
        if (!mac_data) {
            free_tlv(data_tlv);
            error("Failed to allocate buffer for HMAC verification");
        }

        // Prepare data for HMAC: IV + ciphertext (in TLV format)
        uint16_t iv_len = serialize_tlv(mac_data, iv_tlv);
        uint16_t ct_len = serialize_tlv(mac_data + iv_len, ct_tlv);
        size_t mac_data_len = iv_len + ct_len;

        // Compute expected HMAC
        uint8_t expected_mac[MAC_SIZE];
        hmac(expected_mac, mac_data, mac_data_len);

        // Verify HMAC with received MAC
        if (memcmp(mac_tlv->val, expected_mac, MAC_SIZE) != 0) {
            free_tlv(data_tlv);
            error("HMAC mismatch: data integrity check failed");
            exit(5); // from the spec
        }

        // Allocate buffer for plaintext
        uint8_t* plaintext = malloc(ct_tlv->length);
        if (!plaintext) {
            free_tlv(data_tlv);
            error("Failed to allocate buffer for plaintext");
        }

        // Decrypt the ciphertext and output plaintext
        size_t plain_len = decrypt_cipher(plaintext, ct_tlv->val, ct_tlv->length, iv_tlv->val);
        output_io(plaintext, plain_len);

        // Cleanup
        free(plaintext);
        free(mac_data);
        free_tlv(data_tlv);

        print("DECRYPTED DATA");
        break;
    }
    default:
        break;
    }
}
