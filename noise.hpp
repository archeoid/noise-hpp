// Noise Protocol Framework (revision 34): https://noiseprotocol.org/noise.html

#pragma once

#include <cstddef>
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <algorithm>
#include <initializer_list>
#include <climits>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <regex>
#include <vector>
#include <utility>
#include <stdexcept>
#include <string>
#include <system_error>

class NoiseTransport;

class ssl_error_category : public std::error_category {
public:
    const char *name() const noexcept override;
    std::string message(int ev) const override;
};

inline const std::error_category &ssl_category() {
    static const ssl_error_category c;
    return c;
}

class ssl_error : public std::system_error {
public:
    ssl_error(unsigned long code, const std::string &message)
        : std::system_error(std::error_code((int)code, ssl_category()), message) {}
    explicit ssl_error(const std::string &message);
};

class NoiseAuthenticationError : public std::runtime_error {
public:
    NoiseAuthenticationError() : std::runtime_error("Noise authentication failed") {}
};

class NoiseProtocol {
public:
    enum class NonceProtection { None, Ordered, Windowed, HalfDuplex };
    struct Config {
        int dh;
        const EVP_CIPHER *cipher;
        const EVP_MD *hash;
        size_t dh_len, hash_len;
        bool aes;
        NonceProtection nonce_protection = NonceProtection::Windowed;
        bool half_duplex = false;
    };
    enum Token : uint8_t { E = 1, S, EE, ES, SE, SS, PSK };
    struct Pattern {
        uint8_t pre_i = 0, pre_r = 0;
        uint8_t tokens[4][8]{};
        unsigned sizes[4]{};
        unsigned messages = 0;
        bool psk[5]{};
        bool psk_mode = false;
        bool fallback = false;
        bool one_way = false;
    };
    struct State {
        uint8_t s[56]{}, spub[56]{}, e[56]{}, epub[56]{}, rs[56]{}, re[56]{};
        bool has_s = false, has_e = false, has_rs = false, has_re = false;
        uint8_t ck[64]{}, h[64]{}, k[32]{};
        bool has_key = false;
        uint64_t nonce = 0;
        unsigned step = 0;
        bool auth_fail = false;
    };
    using PSKCallback = std::function<bool(unsigned position, const uint8_t *remote_static, uint8_t key[32])>;

    struct Parsed { Config config; Pattern pattern; };
    static Parsed parse(const std::string &name);
    static void crypto_hash(const Config &c, const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t output[64]);
    static void crypto_hkdf(const Config &c, const uint8_t *salt, const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size);
    static void crypto_keypair(const Config &c, uint8_t *priv, uint8_t *pub);
    static void crypto_public(const Config &c, const uint8_t *priv, uint8_t *pub);
    static void crypto_dh(const Config &c, const uint8_t *priv, const uint8_t *pub, uint8_t *shared);
    static void crypto_aead(const Config &c, bool encrypt, const uint8_t key[32], const uint8_t iv[12], const uint8_t *ad, size_t ad_size, const uint8_t *input, size_t input_size, uint8_t *output);
    
    static void noise_aead(const Config &c, bool encrypt, const uint8_t key[32], uint64_t nonce, const uint8_t *ad, size_t ad_size, const uint8_t *input, size_t input_size, uint8_t *output);
    static void noise_mix_hash(const Config &c, State &s, const uint8_t *data, size_t size);
    static void noise_mix_key(const Config &c, State &s, const uint8_t *data, size_t size);
    static void noise_mix_key_and_hash(const Config &c, State &s, const uint8_t psk[32]);
    static void noise_init(const Config &c, const std::string &name, const Pattern &p, State &s, bool initiator, const uint8_t *prologue, size_t prologue_size);
    static void noise_encrypt_hash(const Config &c, State &s, const uint8_t *input, size_t input_size, uint8_t *output);
    static void noise_decrypt_hash(const Config &c, State &s, const uint8_t *input, size_t input_size, uint8_t *output);
    static void noise_dh(const Config &c, State &s, uint8_t token, bool initiator);
    static void noise_split(const Config &c, const State &s, uint8_t key1[32], uint8_t key2[32]);
    static void noise_rekey(const Config &c, uint8_t key[32]);
};

class NoiseHandshake {
public:
    NoiseHandshake(const char *name, bool is_initiator);
    ~NoiseHandshake();

    NoiseHandshake(const NoiseHandshake &) = delete;
    NoiseHandshake &operator=(const NoiseHandshake &) = delete;

    void set_prologue(const uint8_t *data, size_t size);
    void set_static(const uint8_t *private_key, size_t size);
    void set_remote_static(const uint8_t *public_key, size_t size);
    void set_ephemeral(const uint8_t *private_key, size_t size);
    void set_remote_ephemeral(const uint8_t *public_key, size_t size);
    void set_psk(unsigned position, const uint8_t key[32]);
    void set_psk_callback(NoiseProtocol::PSKCallback callback);
    void set_nonce_protection(NoiseProtocol::NonceProtection protection);
    void set_half_duplex(bool enabled = true); // NOTE: transport must be strictly alternating, see Noise 11.5

    void set_fallback(const char *protocol);
    void fallback();

    bool wants_write() const;
    bool complete() const;

    void write(const uint8_t *plain, size_t plain_size, uint8_t *message, size_t message_size, size_t &message_used);
    void read(const uint8_t *message, size_t message_size, uint8_t *plain, size_t plain_size, size_t &plain_used);

    size_t remote_static(uint8_t *output, size_t output_size) const;
    size_t handshake_hash(uint8_t *output, size_t output_size) const;

    NoiseTransport split();

private:
    std::string protocol;
    NoiseProtocol::Config config;
    NoiseProtocol::Pattern pattern;
    NoiseProtocol::State state;
    std::vector<uint8_t> prologue;
    uint8_t psk[5][32]{};
    bool psk_set[5]{};
    NoiseProtocol::PSKCallback psk_callback;
    bool initiator, split_done = false;
    struct {
        std::string protocol;
        NoiseProtocol::Config config{};
        NoiseProtocol::Pattern pattern{};
    } fallback_protocol;

    void check_set_allowable() const;
    void fail(const NoiseProtocol::State &attempt, bool auth_fail = false) noexcept;
    void initialize(NoiseProtocol::State &s) const;

    void mix_psk(NoiseProtocol::State &s, unsigned position) const;
};

class NoiseTransport {
public:
    ~NoiseTransport();

    NoiseTransport(const NoiseTransport &) = delete;
    NoiseTransport &operator=(const NoiseTransport &) = delete;
    NoiseTransport(NoiseTransport &&other) noexcept;
    NoiseTransport &operator=(NoiseTransport &&other) noexcept;

    void encrypt(uint64_t &nonce, const uint8_t *plain, size_t plain_size, uint8_t *cipher, size_t cipher_size, size_t &cipher_used);
    void decrypt(uint64_t nonce, const uint8_t *cipher, size_t cipher_size, uint8_t *plain, size_t plain_size, size_t &plain_used);
    void rekey_tx();
    void rekey_rx();

private:
    NoiseProtocol::Config config;
    uint8_t tx[32]{}, rx[32]{};
    uint64_t tx_nonce = 0, rx_nonce = 0, rx_window = 0;
    bool tx_enabled = true, rx_enabled = true;
    explicit NoiseTransport(const NoiseProtocol::Config &c) : config(c) {}
    friend class NoiseHandshake;
};


inline const char *ssl_error_category::name() const noexcept { return "openssl"; }

inline std::string ssl_error_category::message(int ev) const {
    char buf[256];
    ERR_error_string_n((uint32_t)ev, buf, sizeof(buf));
    return buf;
}

inline ssl_error::ssl_error(const std::string &message) : ssl_error(ERR_get_error(), message) {
    ERR_clear_error();
}

inline NoiseHandshake::NoiseHandshake(const char *name, bool is_initiator)
    : protocol(name ? name : ""), initiator(is_initiator) {
    auto parsed = NoiseProtocol::parse(protocol);
    config = parsed.config;
    pattern = parsed.pattern;
}

inline NoiseHandshake::~NoiseHandshake() {
    OPENSSL_cleanse(&state, sizeof(state));
    OPENSSL_cleanse(psk, sizeof(psk));
}

inline bool NoiseHandshake::wants_write() const { return !complete() && ((state.step % 2 == 0) == initiator); }
inline bool NoiseHandshake::complete() const { return state.step == pattern.messages; }

inline void NoiseHandshake::check_set_allowable() const {
    if (state.step || split_done || state.auth_fail) throw std::logic_error("Noise handshake already started");
}

inline void NoiseHandshake::fail(const NoiseProtocol::State &attempt, bool auth_fail) noexcept {
    bool can_fallback = auth_fail && !fallback_protocol.protocol.empty() && !split_done &&
        state.step == (initiator ? 1u : 0u) &&
        (initiator ? state.has_e : (pattern.sizes[0] && pattern.tokens[0][0] == NoiseProtocol::E && attempt.has_re));
    if (can_fallback && !initiator) {
        std::memcpy(state.re, attempt.re, config.dh_len);
        state.has_re = true;
    }
    if (!can_fallback) {
        OPENSSL_cleanse(&state, sizeof(state));
        OPENSSL_cleanse(psk, sizeof(psk));
    }
    state.auth_fail = true;
}

inline void NoiseHandshake::mix_psk(NoiseProtocol::State &s, unsigned position) const {
    if (!pattern.psk[position]) return;
    uint8_t key[32]{};
    try {
        if (psk_set[position]) std::memcpy(key, psk[position], 32);
        else if (!psk_callback || !psk_callback(position, s.has_rs ? s.rs : nullptr, key))
            throw std::invalid_argument("missing Noise PSK");
        NoiseProtocol::noise_mix_key_and_hash(config, s, key);
    } catch (...) {
        OPENSSL_cleanse(key, sizeof(key));
        throw;
    }
    OPENSSL_cleanse(key, sizeof(key));
}

inline NoiseTransport::~NoiseTransport() {
    OPENSSL_cleanse(tx, sizeof(tx));
    OPENSSL_cleanse(rx, sizeof(rx));
}

inline NoiseTransport::NoiseTransport(NoiseTransport &&other) noexcept : config(other.config) {
    *this = std::move(other);
}

inline void NoiseTransport::rekey_tx() {
    if (!tx_enabled) throw std::logic_error("Noise transmit cipher unavailable");
    NoiseProtocol::noise_rekey(config, tx);
    if (config.half_duplex) std::memcpy(rx, tx, sizeof(rx));
}

inline void NoiseTransport::rekey_rx() {
    if (!rx_enabled) throw std::logic_error("Noise receive cipher unavailable");
    NoiseProtocol::noise_rekey(config, rx);
    if (config.half_duplex) std::memcpy(tx, rx, sizeof(tx));
}

inline NoiseProtocol::Parsed NoiseProtocol::parse(const std::string &name) {
    static const std::regex re(R"(^Noise_([A-Z0-9]+)(fallback(?:\+psk[0-4])*|psk[0-4](?:\+psk[0-4])*)?_(25519|448)_(ChaChaPoly|AESGCM)_(SHA256|SHA512|BLAKE2s|BLAKE2b)$)");
    std::smatch match;
    if (name.size() > 255 || !std::regex_match(name, match, re))
        throw std::invalid_argument("invalid Noise protocol name");
    std::string base = match[1].str(), modifiers = match[2].str(), dh = match[3].str(), cipher = match[4].str(), hash = match[5].str();
    Parsed parsed{};
    Config &c = parsed.config;
    if (dh == "25519") { c.dh = EVP_PKEY_X25519; c.dh_len = 32; }
    else { c.dh = EVP_PKEY_X448; c.dh_len = 56; }
    if (cipher == "ChaChaPoly") { c.cipher = EVP_chacha20_poly1305(); c.aes = false; }
    else { c.cipher = EVP_aes_256_gcm(); c.aes = true; }
    if (hash == "SHA256") c.hash = EVP_sha256();
    else if (hash == "SHA512") c.hash = EVP_sha512();
    else if (hash == "BLAKE2s") c.hash = EVP_blake2s256();
    else c.hash = EVP_blake2b512();
    c.hash_len = (size_t)EVP_MD_get_size(c.hash);
    struct Definition { const char *name; uint8_t pre_i, pre_r; std::initializer_list<std::initializer_list<Token>> messages; };
    static const Definition defs[] = {
        {"N", 0, S, {{E, ES}}},
        {"K", S, S, {{E, ES, SS}}},
        {"X", 0, S, {{E, ES, S, SS}}},
        {"NN", 0, 0, {{E}, {E, EE}}},
        {"NK", 0, S, {{E, ES}, {E, EE}}},
        {"NX", 0, 0, {{E}, {E, EE, S, ES}}},
        {"XN", 0, 0, {{E}, {E, EE}, {S, SE}}},
        {"XK", 0, S, {{E, ES}, {E, EE}, {S, SE}}},
        {"XX", 0, 0, {{E}, {E, EE, S, ES}, {S, SE}}},
        {"KN", S, 0, {{E}, {E, EE, SE}}},
        {"KK", S, S, {{E, ES, SS}, {E, EE, SE}}},
        {"KX", S, 0, {{E}, {E, EE, SE, S, ES}}},
        {"IN", 0, 0, {{E, S}, {E, EE, SE}}},
        {"IK", 0, S, {{E, ES, S, SS}, {E, EE, SE}}},
        {"IX", 0, 0, {{E, S}, {E, EE, SE, S, ES}}},
        {"NK1", 0, S, {{E}, {E, EE, ES}}},
        {"NX1", 0, 0, {{E}, {E, EE, S}, {ES}}},
        {"X1N", 0, 0, {{E}, {E, EE}, {S}, {SE}}},
        {"X1K", 0, S, {{E, ES}, {E, EE}, {S}, {SE}}},
        {"XK1", 0, S, {{E}, {E, EE, ES}, {S, SE}}},
        {"X1K1", 0, S, {{E}, {E, EE, ES}, {S}, {SE}}},
        {"X1X", 0, 0, {{E}, {E, EE, S, ES}, {S}, {SE}}},
        {"XX1", 0, 0, {{E}, {E, EE, S}, {ES, S, SE}}},
        {"X1X1", 0, 0, {{E}, {E, EE, S}, {ES, S}, {SE}}},
        {"K1N", S, 0, {{E}, {E, EE}, {SE}}},
        {"K1K", S, S, {{E, ES}, {E, EE}, {SE}}},
        {"KK1", S, S, {{E}, {E, EE, SE, ES}}},
        {"K1K1", S, S, {{E}, {E, EE, ES}, {SE}}},
        {"K1X", S, 0, {{E}, {E, EE, S, ES}, {SE}}},
        {"KX1", S, 0, {{E}, {E, EE, SE, S}, {ES}}},
        {"K1X1", S, 0, {{E}, {E, EE, S}, {SE, ES}}},
        {"I1N", 0, 0, {{E, S}, {E, EE}, {SE}}},
        {"I1K", 0, S, {{E, ES, S}, {E, EE}, {SE}}},
        {"IK1", 0, S, {{E, S}, {E, EE, SE, ES}}},
        {"I1K1", 0, S, {{E, S}, {E, EE, ES}, {SE}}},
        {"I1X", 0, 0, {{E, S}, {E, EE, S, ES}, {SE}}},
        {"IX1", 0, 0, {{E, S}, {E, EE, SE, S}, {ES}}},
        {"I1X1", 0, 0, {{E, S}, {E, EE, S}, {SE, ES}}}
    };
    const Definition *def = nullptr;
    for (const auto &d : defs) if (base == d.name) { def = &d; break; }
    if (!def) throw std::invalid_argument("unsupported Noise handshake pattern");
    Pattern &p = parsed.pattern;
    p.one_way = base == "N" || base == "K" || base == "X";
    p.pre_i = def->pre_i;
    p.pre_r = def->pre_r;
    for (const auto &message : def->messages) {
        if (p.messages >= 4 || message.size() > 8) throw std::invalid_argument("invalid Noise pattern size");
        for (Token token : message) p.tokens[p.messages][p.sizes[p.messages]++] = token;
        ++p.messages;
    }
    p.fallback = modifiers.compare(0, 8, "fallback") == 0;
    int last_psk = -1;
    size_t start = p.fallback ? 8 : 0;
    while (start < modifiers.size()) {
        if (modifiers[start] == '+') ++start;
        unsigned n = unsigned(modifiers[start + 3] - '0');
        if ((int)n <= last_psk) throw std::invalid_argument("invalid Noise PSK modifier order");
        last_psk = (int)n;
        p.psk[n] = true;
        p.psk_mode = true;
        start += 4;
    }
    if (p.fallback) {
        if (p.messages < 2 || p.sizes[0] == 0) throw std::invalid_argument("invalid Noise fallback pattern");
        uint8_t first = 0;
        for (unsigned j = 0; j < p.sizes[0]; ++j) {
            uint8_t tok = p.tokens[0][j];
            if (tok != E && tok != S) throw std::invalid_argument("invalid Noise fallback pre-message");
            first |= tok == E ? 1 : 2;
        }
        uint8_t pi = p.pre_i, pr = p.pre_r;
        p.pre_i = pr;
        p.pre_r = pi | first;
        for (unsigned i = 1; i < p.messages; ++i) {
            p.sizes[i - 1] = p.sizes[i];
            for (unsigned j = 0; j < p.sizes[i]; ++j) {
                uint8_t tok = p.tokens[i][j];
                p.tokens[i - 1][j] = tok == ES ? uint8_t(SE) : tok == SE ? uint8_t(ES) : tok;
            }
        }
        --p.messages;
        p.one_way = false;
    }
    for (unsigned i = 0; i < 5; ++i) if (p.psk[i] && i > p.messages)
        throw std::invalid_argument("Noise PSK position out of range");
    return parsed;
}

inline void NoiseProtocol::crypto_hash(const Config &c, const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t output[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int length = 0;
    bool ok = ctx && EVP_DigestInit_ex(ctx, c.hash, nullptr) == 1 &&
        (!an || EVP_DigestUpdate(ctx, a, an) == 1) &&
        (!bn || EVP_DigestUpdate(ctx, b, bn) == 1) &&
        EVP_DigestFinal_ex(ctx, output, &length) == 1 && length == c.hash_len;
    EVP_MD_CTX_free(ctx);
    if (!ok) throw ssl_error("Noise hash failed");
}

inline void NoiseProtocol::crypto_hkdf(const Config &c, const uint8_t *salt, const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size) {
    if (input_size > INT_MAX) throw std::invalid_argument("invalid HKDF input");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    uint8_t empty = 0;
    size_t actual = output_size;
    std::exception_ptr error;
    try {
        if (!ctx || EVP_PKEY_derive_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_hkdf_md(ctx, c.hash) != 1 ||
            EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)c.hash_len) != 1 ||
            EVP_PKEY_CTX_set1_hkdf_key(ctx, input ? input : &empty, (int)input_size) != 1 ||
            EVP_PKEY_derive(ctx, output, &actual) != 1 || actual != output_size)
            throw ssl_error("Noise HKDF failed");
    } catch (...) { error = std::current_exception(); }
    EVP_PKEY_CTX_free(ctx);
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::crypto_keypair(const Config &c, uint8_t *priv, uint8_t *pub) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(c.dh, nullptr);
    EVP_PKEY *key = nullptr;
    std::exception_ptr error;
    try {
        if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &key) != 1)
            throw ssl_error("Noise key generation failed");
        size_t n = c.dh_len;
        if (EVP_PKEY_get_raw_private_key(key, priv, &n) != 1 || n != c.dh_len)
            throw ssl_error("Noise private key extraction failed");
        n = c.dh_len;
        if (EVP_PKEY_get_raw_public_key(key, pub, &n) != 1 || n != c.dh_len)
            throw ssl_error("Noise public key extraction failed");
    } catch (...) { error = std::current_exception(); }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::crypto_public(const Config &c, const uint8_t *priv, uint8_t *pub) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(c.dh, nullptr, priv, c.dh_len);
    size_t n = c.dh_len;
    bool ok = key && EVP_PKEY_get_raw_public_key(key, pub, &n) == 1 && n == c.dh_len;
    EVP_PKEY_free(key);
    if (!ok) throw ssl_error("Noise public key derivation failed");
}

inline void NoiseProtocol::crypto_dh(const Config &c, const uint8_t *priv, const uint8_t *pub, uint8_t *shared) {
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key(c.dh, nullptr, priv, c.dh_len);
    EVP_PKEY *remote = EVP_PKEY_new_raw_public_key(c.dh, nullptr, pub, c.dh_len);
    EVP_PKEY_CTX *ctx = nullptr;
    std::exception_ptr error;
    try {
        if (!local || !remote) throw ssl_error("Noise DH key import failed");
        ctx = EVP_PKEY_CTX_new(local, nullptr);
        size_t n = c.dh_len;
        if (!ctx || EVP_PKEY_derive_init(ctx) != 1 || EVP_PKEY_derive_set_peer(ctx, remote) != 1 ||
            EVP_PKEY_derive(ctx, shared, &n) != 1 || n != c.dh_len)
            throw ssl_error("Noise DH failed");
    } catch (...) { error = std::current_exception(); }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(remote);
    EVP_PKEY_free(local);
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::crypto_aead(const Config &c, bool encrypt, const uint8_t key[32], const uint8_t iv[12], const uint8_t *ad, size_t ad_size, const uint8_t *input, size_t input_size, uint8_t *output) {
    if (ad_size > INT_MAX || input_size > INT_MAX || (!encrypt && input_size < 16))
        throw std::invalid_argument("invalid Noise AEAD size");
    if (!output && (encrypt || input_size > 16))
        throw std::invalid_argument("null Noise AEAD output");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw ssl_error("Noise AEAD context creation failed");
    int length = 0, used = 0;
    uint8_t unused = 0;
    std::exception_ptr error;
    try {
        if (encrypt) {
            if (EVP_EncryptInit_ex(ctx, c.cipher, nullptr, key, iv) != 1 ||
                (ad_size && EVP_EncryptUpdate(ctx, nullptr, &length, ad, (int)ad_size) != 1) ||
                (input_size && EVP_EncryptUpdate(ctx, output, &used, input, (int)input_size) != 1) ||
                EVP_EncryptFinal_ex(ctx, output ? output + used : &unused, &length) != 1 ||
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, output + input_size) != 1)
                throw ssl_error("Noise AEAD encryption failed");
        } else {
            size_t n = input_size - 16;
            if (EVP_DecryptInit_ex(ctx, c.cipher, nullptr, key, iv) != 1 ||
                (ad_size && EVP_DecryptUpdate(ctx, nullptr, &length, ad, (int)ad_size) != 1) ||
                (n && EVP_DecryptUpdate(ctx, output, &used, input, (int)n) != 1) ||
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (uint8_t *)(input + n)) != 1)
                throw ssl_error("Noise AEAD decryption failed");
            if (EVP_DecryptFinal_ex(ctx, output ? output + used : &unused, &length) != 1)
                throw NoiseAuthenticationError();
        }
    } catch (...) { error = std::current_exception(); }
    if (error && !encrypt && output) OPENSSL_cleanse(output, input_size - 16);
    EVP_CIPHER_CTX_free(ctx);
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::noise_aead(const Config &c, bool encrypt, const uint8_t key[32], uint64_t nonce, const uint8_t *ad, size_t ad_size, const uint8_t *input, size_t input_size, uint8_t *output) {
    uint8_t iv[12]{};
    for (unsigned i = 0; i < 8; ++i) iv[4 + i] = (uint8_t)(nonce >> ((c.aes ? 7 - i : i) * 8));
    crypto_aead(c, encrypt, key, iv, ad, ad_size, input, input_size, output);
}

inline void NoiseProtocol::noise_mix_hash(const Config &c, State &s, const uint8_t *data, size_t size) {
    uint8_t result[64]{};
    std::exception_ptr error;
    try {
        crypto_hash(c, s.h, c.hash_len, data, size, result);
        std::memcpy(s.h, result, c.hash_len);
    } catch (...) { error = std::current_exception(); }
    OPENSSL_cleanse(result, sizeof(result));
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::noise_mix_key(const Config &c, State &s, const uint8_t *data, size_t size) {
    uint8_t keys[128]{};
    std::exception_ptr error;
    try {
        crypto_hkdf(c, s.ck, data, size, keys, 2 * c.hash_len);
        std::memcpy(s.ck, keys, c.hash_len);
        std::memcpy(s.k, keys + c.hash_len, 32);
        s.has_key = true;
        s.nonce = 0;
    } catch (...) { error = std::current_exception(); }
    OPENSSL_cleanse(keys, sizeof(keys));
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::noise_mix_key_and_hash(const Config &c, State &s, const uint8_t psk[32]) {
    uint8_t keys[192]{};
    std::exception_ptr error;
    try {
        crypto_hkdf(c, s.ck, psk, 32, keys, 3 * c.hash_len);
        std::memcpy(s.ck, keys, c.hash_len);
        noise_mix_hash(c, s, keys + c.hash_len, c.hash_len);
        std::memcpy(s.k, keys + 2 * c.hash_len, 32);
        s.has_key = true;
        s.nonce = 0;
    } catch (...) { error = std::current_exception(); }
    OPENSSL_cleanse(keys, sizeof(keys));
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::noise_init(const Config &c, const std::string &name, const Pattern &p, State &s, bool initiator, const uint8_t *prologue, size_t prologue_size) {
    if (name.size() <= c.hash_len) {
        std::memset(s.h, 0, c.hash_len);
        std::memcpy(s.h, name.data(), name.size());
    } else crypto_hash(c, (const uint8_t *)name.data(), name.size(), nullptr, 0, s.h);
    std::memcpy(s.ck, s.h, c.hash_len);
    s.has_key = false;
    s.nonce = 0;
    noise_mix_hash(c, s, prologue, prologue_size);
    for (unsigned side = 0; side < 2; ++side) {
        uint8_t flags = side == 0 ? p.pre_i : p.pre_r;
        bool local = (side == 0) == initiator;
        if (flags & 1) {
            if (local ? !s.has_e : !s.has_re) throw std::invalid_argument("missing Noise pre-message ephemeral");
            const uint8_t *pub = local ? s.epub : s.re;
            noise_mix_hash(c, s, pub, c.dh_len);
            if (p.psk_mode) noise_mix_key(c, s, pub, c.dh_len);
        }
        if (flags & 2) {
            if (local ? !s.has_s : !s.has_rs) throw std::invalid_argument("missing Noise pre-message static key");
            noise_mix_hash(c, s, local ? s.spub : s.rs, c.dh_len);
        }
    }
}

inline void NoiseProtocol::noise_encrypt_hash(const Config &c, State &s, const uint8_t *input, size_t input_size, uint8_t *output) {
    if (s.has_key) {
        if (s.nonce == std::numeric_limits<uint64_t>::max()) throw std::runtime_error("Noise nonce exhausted");
        noise_aead(c, true, s.k, s.nonce, s.h, c.hash_len, input, input_size, output);
        ++s.nonce;
        noise_mix_hash(c, s, output, input_size + 16);
    } else {
        if (input_size) std::memcpy(output, input, input_size);
        noise_mix_hash(c, s, output, input_size);
    }
}

inline void NoiseProtocol::noise_decrypt_hash(const Config &c, State &s, const uint8_t *input, size_t input_size, uint8_t *output) {
    if (s.has_key) {
        if (s.nonce == std::numeric_limits<uint64_t>::max()) throw std::runtime_error("Noise nonce exhausted");
        noise_aead(c, false, s.k, s.nonce, s.h, c.hash_len, input, input_size, output);
        ++s.nonce;
    } else if (input_size) std::memcpy(output, input, input_size);
    noise_mix_hash(c, s, input, input_size);
}

inline void NoiseProtocol::noise_dh(const Config &c, State &s, uint8_t token, bool initiator) {
    const uint8_t *priv = nullptr, *pub = nullptr;
    bool valid = false;
    switch (token) {
    case EE: priv = s.e; pub = s.re; valid = s.has_e && s.has_re; break;
    case ES:
        priv = initiator ? s.e : s.s; pub = initiator ? s.rs : s.re;
        valid = initiator ? s.has_e && s.has_rs : s.has_s && s.has_re; break;
    case SE:
        priv = initiator ? s.s : s.e; pub = initiator ? s.re : s.rs;
        valid = initiator ? s.has_s && s.has_re : s.has_e && s.has_rs; break;
    case SS: priv = s.s; pub = s.rs; valid = s.has_s && s.has_rs; break;
    }
    if (!valid) throw std::invalid_argument("missing Noise DH key");
    uint8_t shared[56]{};
    std::exception_ptr error;
    try {
        crypto_dh(c, priv, pub, shared);
        noise_mix_key(c, s, shared, c.dh_len);
    } catch (...) { error = std::current_exception(); }
    OPENSSL_cleanse(shared, sizeof(shared));
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::noise_split(const Config &c, const State &s, uint8_t key1[32], uint8_t key2[32]) {
    uint8_t keys[128]{};
    std::exception_ptr error;
    try {
        crypto_hkdf(c, s.ck, nullptr, 0, keys, 2 * c.hash_len);
        std::memcpy(key1, keys, 32);
        std::memcpy(key2, keys + c.hash_len, 32);
    } catch (...) { error = std::current_exception(); }
    OPENSSL_cleanse(keys, sizeof(keys));
    if (error) std::rethrow_exception(error);
}

inline void NoiseProtocol::noise_rekey(const Config &c, uint8_t key[32]) {
    uint8_t zeros[32]{}, result[48]{};
    std::exception_ptr error;
    try {
        noise_aead(c, true, key, std::numeric_limits<uint64_t>::max(), nullptr, 0, zeros, 32, result);
        std::memcpy(key, result, 32);
    } catch (...) { error = std::current_exception(); }
    OPENSSL_cleanse(result, sizeof(result));
    if (error) std::rethrow_exception(error);
}

inline void NoiseHandshake::initialize(NoiseProtocol::State &s) const {
    if (s.step) return;
    NoiseProtocol::noise_init(config, protocol, pattern, s, initiator,
        prologue.empty() ? nullptr : prologue.data(), prologue.size());
}

inline void NoiseHandshake::set_prologue(const uint8_t *data, size_t size) {
    check_set_allowable();
    if (size && !data) throw std::invalid_argument("null Noise prologue");
    if (size) prologue.assign(data, data + size);
    else prologue.clear();
}

inline void NoiseHandshake::set_static(const uint8_t *private_key, size_t size) {
    check_set_allowable();
    if (!private_key || size != config.dh_len) throw std::invalid_argument("invalid Noise static private key");
    uint8_t pub[56]{};
    NoiseProtocol::crypto_public(config, private_key, pub);
    std::memcpy(state.s, private_key, size);
    std::memcpy(state.spub, pub, size);
    state.has_s = true;
}

inline void NoiseHandshake::set_remote_static(const uint8_t *public_key, size_t size) {
    check_set_allowable();
    if (!public_key || size != config.dh_len) throw std::invalid_argument("invalid Noise remote static public key");
    std::memcpy(state.rs, public_key, size);
    state.has_rs = true;
}

inline void NoiseHandshake::set_ephemeral(const uint8_t *private_key, size_t size) {
    check_set_allowable();
    if (!private_key || size != config.dh_len) throw std::invalid_argument("invalid Noise ephemeral private key");
    uint8_t pub[56]{};
    NoiseProtocol::crypto_public(config, private_key, pub);
    std::memcpy(state.e, private_key, size);
    std::memcpy(state.epub, pub, size);
    state.has_e = true;
}

inline void NoiseHandshake::set_remote_ephemeral(const uint8_t *public_key, size_t size) {
    check_set_allowable();
    if (!public_key || size != config.dh_len) throw std::invalid_argument("invalid Noise remote ephemeral public key");
    std::memcpy(state.re, public_key, size);
    state.has_re = true;
}

inline void NoiseHandshake::set_psk(unsigned position, const uint8_t key[32]) {
    check_set_allowable();
    if (position > 4 || !key || !pattern.psk[position]) throw std::invalid_argument("invalid Noise PSK position or key");
    std::memcpy(psk[position], key, 32);
    psk_set[position] = true;
}

inline void NoiseHandshake::set_psk_callback(NoiseProtocol::PSKCallback callback) {
    check_set_allowable();
    psk_callback = std::move(callback);
}

inline void NoiseHandshake::set_nonce_protection(NoiseProtocol::NonceProtection protection) {
    check_set_allowable();
    config.nonce_protection = protection;
}

inline void NoiseHandshake::set_half_duplex(bool enabled) {
    check_set_allowable();
    config.half_duplex = enabled;
    if (enabled) config.nonce_protection = NoiseProtocol::NonceProtection::HalfDuplex;
    else if (config.nonce_protection == NoiseProtocol::NonceProtection::HalfDuplex)
        config.nonce_protection = NoiseProtocol::NonceProtection::Windowed;
}

inline void NoiseHandshake::set_fallback(const char *protocol) {
    check_set_allowable();
    if (!protocol) throw std::invalid_argument("null Noise fallback protocol");
    std::string name(protocol);
    auto parsed = NoiseProtocol::parse(name);
    if (!parsed.pattern.fallback || parsed.config.dh != config.dh)
        throw std::invalid_argument("invalid Noise fallback protocol");
    fallback_protocol.protocol = std::move(name);
    fallback_protocol.config = parsed.config;
    fallback_protocol.pattern = parsed.pattern;
}

inline void NoiseHandshake::fallback() {
    if (fallback_protocol.protocol.empty() || split_done || (!initiator && !state.auth_fail) || state.step != (initiator ? 1u : 0u)) 
        throw std::logic_error("Noise fallback unavailable");
    if (initiator ? !state.has_e : !state.has_re)
        throw std::logic_error("missing Noise fallback ephemeral");
    NoiseProtocol::State next = state;
    OPENSSL_cleanse(next.ck, sizeof(next.ck));
    OPENSSL_cleanse(next.h, sizeof(next.h));
    OPENSSL_cleanse(next.k, sizeof(next.k));
    next.has_key = false;
    next.nonce = 0;
    next.step = 0;
    next.auth_fail = false;
    initiator = !initiator;
    protocol = fallback_protocol.protocol;
    fallback_protocol.config.nonce_protection = config.nonce_protection;
    fallback_protocol.config.half_duplex = config.half_duplex;
    config = fallback_protocol.config;
    pattern = fallback_protocol.pattern;
    uint8_t required_pre = initiator ? pattern.pre_r : pattern.pre_i;
    if (!(required_pre & 2)) { OPENSSL_cleanse(next.rs, sizeof(next.rs)); next.has_rs = false; }
    if (!(required_pre & 1)) { OPENSSL_cleanse(next.re, sizeof(next.re)); next.has_re = false; }
    OPENSSL_cleanse(&state, sizeof(state));
    state = next;
    OPENSSL_cleanse(&next, sizeof(next));
    fallback_protocol = {};
}

inline void NoiseHandshake::write(const uint8_t *plain, size_t plain_size, uint8_t *message, size_t message_size, size_t &message_used) {
    message_used = 0;
    if (!wants_write()) throw std::logic_error("Noise handshake does not want a write");
    if (plain_size > 65535 || (plain_size && !plain) || !message)
        throw std::invalid_argument("invalid Noise handshake output");
    if (state.auth_fail) throw std::logic_error("Noise handshake failed");
    auto s = state;
    std::exception_ptr error;
    size_t used = 0;
    try {
        initialize(s);
        unsigned step = s.step;
        if (step == 0) mix_psk(s, 0);
        for (unsigned i = 0; i < pattern.sizes[step]; ++i) {
            uint8_t tok = pattern.tokens[step][i];
            if (tok == NoiseProtocol::E) {
                if (!s.has_e) {
                    NoiseProtocol::crypto_keypair(config, s.e, s.epub);
                    s.has_e = true;
                }
                if (config.dh_len > 65535 - used || config.dh_len > message_size - std::min(used, message_size))
                    throw std::invalid_argument("Noise handshake output buffer too small");
                std::memcpy(message + used, s.epub, config.dh_len);
                used += config.dh_len;
                NoiseProtocol::noise_mix_hash(config, s, s.epub, config.dh_len);
                if (pattern.psk_mode) NoiseProtocol::noise_mix_key(config, s, s.epub, config.dh_len);
            } else if (tok == NoiseProtocol::S) {
                if (!s.has_s) throw std::invalid_argument("missing Noise static private key");
                size_t n = config.dh_len + (s.has_key ? 16 : 0);
                if (n > 65535 - used || n > message_size - std::min(used, message_size))
                    throw std::invalid_argument("Noise handshake output buffer too small");
                NoiseProtocol::noise_encrypt_hash(config, s, s.spub, config.dh_len, message + used);
                used += n;
            } else {
                try { NoiseProtocol::noise_dh(config, s, tok, initiator); }
                catch (...) { fail(s); throw; }
            }
        }
        mix_psk(s, step + 1);
        size_t n = plain_size + (s.has_key ? 16 : 0);
        if (n > 65535 - used || n > message_size - std::min(used, message_size))
            throw std::invalid_argument("Noise handshake output buffer too small");
        NoiseProtocol::noise_encrypt_hash(config, s, plain, plain_size, message + used);
        used += n;
        ++s.step;
    } catch (...) { error = std::current_exception(); }
    if (!error) {
        state = s;
        message_used = used;
    }
    OPENSSL_cleanse(&s, sizeof(s));
    if (error) std::rethrow_exception(error);
}

inline void NoiseHandshake::read(const uint8_t *message, size_t message_size, uint8_t *plain, size_t plain_size, size_t &plain_used) {
    plain_used = 0;
    if (complete() || wants_write()) throw std::logic_error("Noise handshake does not want a read");
    if (message_size > 65535 || (message_size && !message))
        throw std::invalid_argument("invalid Noise handshake input");
    if (state.auth_fail) throw std::logic_error("Noise handshake failed");
    const uint8_t empty = 0;
    const uint8_t *input = message ? message : &empty;
    auto s = state;
    std::exception_ptr error;
    size_t used = 0, output_used = 0;
    try {
        initialize(s);
        unsigned step = s.step;
        if (step == 0) mix_psk(s, 0);
        for (unsigned i = 0; i < pattern.sizes[step]; ++i) {
            uint8_t tok = pattern.tokens[step][i];
            if (tok == NoiseProtocol::E) {
                if (s.has_re || config.dh_len > message_size - used)
                    throw std::invalid_argument("invalid Noise remote ephemeral");
                std::memcpy(s.re, input + used, config.dh_len);
                s.has_re = true;
                NoiseProtocol::noise_mix_hash(config, s, s.re, config.dh_len);
                if (pattern.psk_mode) NoiseProtocol::noise_mix_key(config, s, s.re, config.dh_len);
                used += config.dh_len;
            } else if (tok == NoiseProtocol::S) {
                if (s.has_rs) throw std::invalid_argument("Noise remote static key already set");
                size_t n = config.dh_len + (s.has_key ? 16 : 0);
                if (n > message_size - used) throw std::invalid_argument("truncated Noise static key");
                try { NoiseProtocol::noise_decrypt_hash(config, s, input + used, n, s.rs); }
                catch (const NoiseAuthenticationError &) { fail(s, true); throw; }
                catch (...) { fail(s); throw; }
                s.has_rs = true;
                used += n;
            } else {
                try { NoiseProtocol::noise_dh(config, s, tok, initiator); }
                catch (...) { fail(s); throw; }
            }
        }
        mix_psk(s, step + 1);
        size_t n = message_size - used;
        if (s.has_key && n < 16) throw std::invalid_argument("truncated Noise handshake payload");
        output_used = n - (s.has_key ? 16 : 0);
        if (output_used > plain_size || (output_used && !plain))
            throw std::invalid_argument("Noise handshake plaintext buffer too small");
        try { NoiseProtocol::noise_decrypt_hash(config, s, input + used, n, plain); }
        catch (const NoiseAuthenticationError &) { fail(s, true); throw; }
        catch (...) { fail(s); throw; }
        ++s.step;
    } catch (...) { error = std::current_exception(); }
    if (!error) {
        state = s;
        plain_used = output_used;
    }
    OPENSSL_cleanse(&s, sizeof(s));
    if (error) std::rethrow_exception(error);
}

inline size_t NoiseHandshake::remote_static(uint8_t *output, size_t output_size) const {
    if (!state.has_rs) return 0;
    if (!output) return config.dh_len;
    if (output_size < config.dh_len) throw std::invalid_argument("Noise remote static buffer too small");
    std::memcpy(output, state.rs, config.dh_len);
    return config.dh_len;
}

inline size_t NoiseHandshake::handshake_hash(uint8_t *output, size_t output_size) const {
    if (!complete()) throw std::logic_error("Noise handshake incomplete");
    if (!output) return config.hash_len;
    if (output_size < config.hash_len) throw std::invalid_argument("Noise handshake hash buffer too small");
    std::memcpy(output, state.h, config.hash_len);
    return config.hash_len;
}

inline NoiseTransport NoiseHandshake::split() {
    if (!complete() || split_done) throw std::logic_error("Noise handshake cannot split");
    if (state.auth_fail) throw std::logic_error("Noise handshake authentication failed");
    if (config.half_duplex != (config.nonce_protection == NoiseProtocol::NonceProtection::HalfDuplex))
        throw std::logic_error("Noise half-duplex protection mode mismatch");
    if (config.half_duplex && pattern.one_way) throw std::logic_error("Noise half-duplex requires an interactive pattern");
    NoiseTransport out(config);
    uint8_t key1[32]{}, key2[32]{};
    std::exception_ptr error;
    try {
        NoiseProtocol::noise_split(config, state, key1, key2);
        std::memcpy(out.tx, (config.half_duplex || initiator) ? key1 : key2, 32);
        std::memcpy(out.rx, (config.half_duplex || !initiator) ? key1 : key2, 32);
        if (pattern.one_way) { out.tx_enabled = initiator; out.rx_enabled = !initiator; }
    } catch (...) { error = std::current_exception(); }
    OPENSSL_cleanse(key1, sizeof(key1));
    OPENSSL_cleanse(key2, sizeof(key2));
    if (error) std::rethrow_exception(error);
    split_done = true;
    OPENSSL_cleanse(state.s, sizeof(state.s));
    OPENSSL_cleanse(state.e, sizeof(state.e));
    OPENSSL_cleanse(state.ck, sizeof(state.ck));
    OPENSSL_cleanse(state.k, sizeof(state.k));
    OPENSSL_cleanse(psk, sizeof(psk));
    return out;
}

inline NoiseTransport &NoiseTransport::operator=(NoiseTransport &&other) noexcept {
    if (this != &other) {
        OPENSSL_cleanse(tx, sizeof(tx));
        OPENSSL_cleanse(rx, sizeof(rx));
        config = other.config;
        std::memcpy(tx, other.tx, sizeof(tx));
        std::memcpy(rx, other.rx, sizeof(rx));
        tx_nonce = other.tx_nonce;
        rx_nonce = other.rx_nonce;
        rx_window = other.rx_window;
        tx_enabled = other.tx_enabled;
        rx_enabled = other.rx_enabled;
        OPENSSL_cleanse(other.tx, sizeof(other.tx));
        OPENSSL_cleanse(other.rx, sizeof(other.rx));
        other.tx_nonce = other.rx_nonce = other.rx_window = 0;
        other.tx_enabled = other.rx_enabled = false;
    }
    return *this;
}

inline void NoiseTransport::encrypt(uint64_t &nonce, const uint8_t *plain, size_t plain_size, uint8_t *cipher, size_t cipher_size, size_t &cipher_used) {
    cipher_used = 0;
    if (!tx_enabled) throw std::logic_error("Noise transmit cipher unavailable");
    if (plain_size > 65535 - 16 || (plain_size && !plain) || !cipher || cipher_size < plain_size + 16)
        throw std::invalid_argument("invalid Noise encryption buffer");
    if (config.nonce_protection == NoiseProtocol::NonceProtection::HalfDuplex && tx_nonce > rx_nonce)
        throw std::logic_error("Noise half-duplex expects a receive");
    if (tx_nonce >= UINT64_MAX - 1) throw std::runtime_error("Noise nonce exhausted");
    NoiseProtocol::noise_aead(config, true, tx, tx_nonce, nullptr, 0, plain, plain_size, cipher);
    nonce = tx_nonce;
    if (config.nonce_protection == NoiseProtocol::NonceProtection::HalfDuplex) {
        if (tx_nonce == 0 && rx_nonce == 0) rx_nonce = 1;
        tx_nonce += 2;
    } else {
        tx_nonce += 1;
    }
    cipher_used = plain_size + 16;
}

inline void NoiseTransport::decrypt(uint64_t nonce, const uint8_t *cipher, size_t cipher_size, uint8_t *plain, size_t plain_size, size_t &plain_used) {
    plain_used = 0;
    if (!rx_enabled) throw std::logic_error("Noise receive cipher unavailable");
    if (cipher_size < 16 || cipher_size > 65535 || !cipher || plain_size < cipher_size - 16 || (cipher_size > 16 && !plain))
        throw std::invalid_argument("invalid Noise decryption buffer");
    if (nonce >= UINT64_MAX - 1) throw std::runtime_error("Noise nonce exhausted");
    if (config.nonce_protection == NoiseProtocol::NonceProtection::Ordered && nonce < rx_nonce)
        throw std::invalid_argument("Noise nonce out of order");
    if (config.nonce_protection == NoiseProtocol::NonceProtection::Windowed && nonce < rx_nonce &&
        (rx_nonce - nonce > 64 || (rx_window & (uint64_t(1) << (rx_nonce - nonce - 1)))))
        throw std::invalid_argument("Noise nonce replayed or too old");
    if (config.nonce_protection == NoiseProtocol::NonceProtection::HalfDuplex) {
        if (rx_nonce > tx_nonce) throw std::logic_error("Noise half-duplex expects a send");
        if (nonce != rx_nonce) throw std::invalid_argument("Noise half-duplex nonce out of sequence");
    }
    NoiseProtocol::noise_aead(config, false, rx, nonce, nullptr, 0, cipher, cipher_size, plain);
    if (config.nonce_protection == NoiseProtocol::NonceProtection::HalfDuplex) {
        if (tx_nonce == 0 && rx_nonce == 0) tx_nonce = 1;
        rx_nonce += 2;
    } else {
        if (nonce >= rx_nonce) {
            uint64_t shift = nonce - rx_nonce + 1;
            rx_window = shift >= 64 ? 1 : (rx_window << shift) | 1;
        } else if (rx_nonce - nonce <= 64) {
            rx_window |= uint64_t(1) << (rx_nonce - nonce - 1);
        }
        rx_nonce = std::max(rx_nonce, nonce + 1);
    }
    plain_used = cipher_size - 16;
}
