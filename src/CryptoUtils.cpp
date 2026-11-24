#include "CryptoUtils.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <limits>

using byte = uint8_t;

namespace {

constexpr uint8_t ORE_MAGIC[4] = {'O', 'R', 'E', '1'};
constexpr uint8_t ORE_VERSION = 1;
constexpr uint8_t ORE_BLOCK_BITS = 4;
constexpr uint8_t ORE_BLOCK_COUNT = 64 / ORE_BLOCK_BITS;
constexpr uint8_t ORE_ALPHABET_SIZE = 1u << ORE_BLOCK_BITS;
constexpr uint8_t ORE_MODULUS = (2u * ORE_ALPHABET_SIZE) - 1u;
constexpr size_t ORE_HEADER_SIZE = 8;
constexpr size_t ORE_CIPHERTEXT_SIZE = ORE_HEADER_SIZE + ORE_BLOCK_COUNT;

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned char* res = HMAC(EVP_sha256(), key.data(), (int)key.size(), data.data(), data.size(), out.data(), &len);
    if (!res) throw std::runtime_error("HMAC failed");
    out.resize(len);
    return out;
}

void append_u64_be(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

std::vector<uint8_t> ascii_bytes(const char* s) {
    return std::vector<uint8_t>(s, s + std::strlen(s));
}

std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                 const std::vector<uint8_t>& salt,
                                 const std::vector<uint8_t>& info,
                                 size_t out_len) {
    std::vector<uint8_t> prk = hmac_sha256(salt, ikm);
    std::vector<uint8_t> okm;
    std::vector<uint8_t> t;
    uint8_t counter = 1;

    while (okm.size() < out_len) {
        std::vector<uint8_t> data;
        data.reserve(t.size() + info.size() + 1);
        data.insert(data.end(), t.begin(), t.end());
        data.insert(data.end(), info.begin(), info.end());
        data.push_back(counter++);

        t = hmac_sha256(prk, data);
        const size_t take = std::min(t.size(), out_len - okm.size());
        okm.insert(okm.end(), t.begin(), t.begin() + static_cast<std::ptrdiff_t>(take));
    }

    return okm;
}

std::vector<uint8_t> derive_ore_prf_key(const std::vector<uint8_t>& key) {
    if (key.empty()) throw std::invalid_argument("ORE key must not be empty");
    return hkdf_sha256(key,
                       ascii_bytes("CFA ORE v1 HKDF salt"),
                       ascii_bytes("CFA ORE v1 prefix PRF key"),
                       32);
}

uint8_t prf_mod31(const std::vector<uint8_t>& prf_key,
                  uint8_t block_index,
                  uint64_t prefix) {
    std::vector<uint8_t> input;
    input.reserve(32);
    const std::vector<uint8_t> domain = ascii_bytes("CFA ORE v1 block mask");
    input.insert(input.end(), domain.begin(), domain.end());
    input.push_back(ORE_BLOCK_BITS);
    input.push_back(block_index);
    append_u64_be(input, prefix);

    const uint64_t range = 1ULL << 32;
    const uint64_t limit = range - (range % ORE_MODULUS);
    for (uint8_t counter = 0;; ++counter) {
        std::vector<uint8_t> data = input;
        data.push_back(counter);
        const std::vector<uint8_t> digest = hmac_sha256(prf_key, data);
        const uint32_t sample =
            (static_cast<uint32_t>(digest[0]) << 24) |
            (static_cast<uint32_t>(digest[1]) << 16) |
            (static_cast<uint32_t>(digest[2]) << 8) |
            static_cast<uint32_t>(digest[3]);
        if (static_cast<uint64_t>(sample) < limit) {
            return static_cast<uint8_t>(sample % ORE_MODULUS);
        }
    }
}

bool is_valid_ore_ciphertext(const std::vector<uint8_t>& c) {
    if (c.size() != ORE_CIPHERTEXT_SIZE) return false;
    if (!std::equal(std::begin(ORE_MAGIC), std::end(ORE_MAGIC), c.begin())) return false;
    if (c[4] != ORE_VERSION ||
        c[5] != ORE_BLOCK_BITS ||
        c[6] != ORE_BLOCK_COUNT ||
        c[7] != ORE_MODULUS) {
        return false;
    }
    for (size_t i = ORE_HEADER_SIZE; i < c.size(); ++i) {
        if (c[i] >= ORE_MODULUS) return false;
    }
    return true;
}

} // namespace

static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

std::vector<uint8_t> CryptoEngine::PRF(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    return hmac_sha256(key, data);
}

std::vector<uint8_t> CryptoEngine::DfsHash(const std::vector<uint8_t>& dfs_bytes) {
    return sha256(dfs_bytes);
}

std::vector<uint8_t> CryptoEngine::FeatureRowId(
    const std::vector<uint8_t>& k3,
    const std::string& feature) {
    // ISO/IEC 7816-4 style padding makes the feature-to-block encoding
    // injective: even a 16-byte feature gets an additional terminator block.
    std::vector<uint8_t> encoded(feature.begin(), feature.end());
    encoded.push_back(0x80);
    encoded.resize(((encoded.size() + 15) / 16) * 16, 0x00);

    std::vector<uint8_t> row_id;
    row_id.reserve(encoded.size());
    for (size_t offset = 0; offset < encoded.size(); offset += 16) {
        const std::vector<uint8_t> block(encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                                         encoded.begin() + static_cast<std::ptrdiff_t>(offset + 16));
        const std::vector<uint8_t> permuted = PRP(k3, block);
        row_id.insert(row_id.end(), permuted.begin(), permuted.end());
    }
    return row_id;
}

std::vector<uint8_t> CryptoEngine::DfsEdMask(
    const std::vector<uint8_t>& k4,
    const std::vector<uint8_t>& dfs_bytes) {
    const std::vector<uint8_t> domain = ascii_bytes("ed_dfs");
    std::vector<uint8_t> input;
    input.reserve(domain.size() + 1 + dfs_bytes.size());
    input.insert(input.end(), domain.begin(), domain.end());
    input.push_back(0);
    input.insert(input.end(), dfs_bytes.begin(), dfs_bytes.end());
    return PRF(k4, input);
}

std::vector<uint8_t> CryptoEngine::DfsEdMask(
    const std::vector<uint8_t>& k4,
    const std::vector<uint8_t>& dfs_bytes,
    size_t out_len) {
    const std::vector<uint8_t> first = DfsEdMask(k4, dfs_bytes);
    std::vector<uint8_t> stream(
        first.begin(),
        first.begin() + static_cast<std::ptrdiff_t>(std::min(first.size(), out_len)));
    const std::vector<uint8_t> domain = ascii_bytes("ed_dfs_stream");
    for (uint64_t counter = 1; stream.size() < out_len; ++counter) {
        std::vector<uint8_t> input;
        input.insert(input.end(), domain.begin(), domain.end());
        input.push_back(0);
        input.insert(input.end(), dfs_bytes.begin(), dfs_bytes.end());
        append_u64_be(input, counter);
        const std::vector<uint8_t> block = PRF(k4, input);
        const size_t take = std::min(block.size(), out_len - stream.size());
        stream.insert(
            stream.end(), block.begin(),
            block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return stream;
}

std::vector<uint8_t> CryptoEngine::ClosureHeadFactor(
    const std::vector<uint8_t>& k5,
    const std::vector<uint8_t>& addr) {
    const std::vector<uint8_t> domain = ascii_bytes("closure_head");
    std::vector<uint8_t> input;
    input.reserve(domain.size() + 1 + addr.size());
    input.insert(input.end(), domain.begin(), domain.end());
    input.push_back(0);
    input.insert(input.end(), addr.begin(), addr.end());
    return PRF(k5, input);
}

std::vector<uint8_t> CryptoEngine::CfbiRowId(
    const std::vector<uint8_t>& k3_cfbi,
    const std::string& feature) {
    return FeatureRowId(k3_cfbi, feature);
}

std::vector<uint8_t> CryptoEngine::CfbiMask(
    const std::vector<uint8_t>& k8_cfbi,
    const std::vector<uint8_t>& protected_row_id,
    size_t out_len) {
    const std::vector<uint8_t> domain = ascii_bytes("cfbi_mask");
    std::vector<uint8_t> stream;
    stream.reserve(out_len);
    for (uint64_t counter = 0; stream.size() < out_len; ++counter) {
        std::vector<uint8_t> input;
        input.reserve(domain.size() + 8 + protected_row_id.size() + 8);
        input.insert(input.end(), domain.begin(), domain.end());
        append_u64_be(input, static_cast<uint64_t>(protected_row_id.size()));
        input.insert(input.end(), protected_row_id.begin(), protected_row_id.end());
        append_u64_be(input, counter);

        const std::vector<uint8_t> block = PRF(k8_cfbi, input);
        const size_t take = std::min(block.size(), out_len - stream.size());
        stream.insert(
            stream.end(), block.begin(),
            block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return stream;
}

std::vector<uint8_t> CryptoEngine::IftiMask(
    const std::vector<uint8_t>& k_ifti_mask,
    const std::vector<uint8_t>& protected_row_id,
    size_t out_len) {
    const std::vector<uint8_t> domain = ascii_bytes("ifti_mask");
    std::vector<uint8_t> stream;
    stream.reserve(out_len);
    for (uint64_t counter = 0; stream.size() < out_len; ++counter) {
        std::vector<uint8_t> input;
        input.insert(input.end(), domain.begin(), domain.end());
        append_u64_be(input, static_cast<uint64_t>(protected_row_id.size()));
        input.insert(input.end(), protected_row_id.begin(), protected_row_id.end());
        append_u64_be(input, counter);
        const std::vector<uint8_t> block = PRF(k_ifti_mask, input);
        const size_t take = std::min(block.size(), out_len - stream.size());
        stream.insert(
            stream.end(), block.begin(),
            block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return stream;
}

std::vector<uint8_t> CryptoEngine::TripletOreKey(
    const std::vector<uint8_t>& k6,
    const std::string& feature,
    size_t graph_size) {
    const std::vector<uint8_t> domain = ascii_bytes("triplet_ore");
    std::vector<uint8_t> input;
    input.reserve(domain.size() + 8 + feature.size() + 8);
    input.insert(input.end(), domain.begin(), domain.end());
    append_u64_be(input, static_cast<uint64_t>(feature.size()));
    input.insert(input.end(), feature.begin(), feature.end());
    append_u64_be(input, static_cast<uint64_t>(graph_size));
    return PRF(k6, input);
}

std::vector<uint8_t> CryptoEngine::GraphletOreKey(
    const std::vector<uint8_t>& k6,
    int graphlet_type) {
    if (graphlet_type < 0) {
        throw std::invalid_argument("graphlet type must be non-negative");
    }
    const std::vector<uint8_t> domain = ascii_bytes("graphlet_ore");
    std::vector<uint8_t> input;
    input.reserve(domain.size() + 1 + 8);
    input.insert(input.end(), domain.begin(), domain.end());
    input.push_back(0);
    append_u64_be(input, static_cast<uint64_t>(graphlet_type));
    return PRF(k6, input);
}

static std::vector<uint8_t> derive_aes256_key(const std::vector<uint8_t>& key) {
    if (key.size() == 32) return key;
    // derive 32-byte key via SHA256
    return sha256(key);
}

std::vector<uint8_t> CryptoEngine::PRP(const std::vector<uint8_t>& key, const std::vector<uint8_t>& index) {
    // Prepare a single 16-byte block from index (pad with zeros or truncate)
    uint8_t block[16] = {0};
    size_t copy_len = std::min<size_t>(index.size(), 16);
    if (copy_len > 0) std::memcpy(block, index.data(), copy_len);

    std::vector<uint8_t> aes_key = derive_aes256_key(key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int outlen = 0;
    std::vector<uint8_t> out(16);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key.data(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_EncryptUpdate(ctx, out.data(), &outlen, block, 16)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int tmplen = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, out.data() + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    outlen += tmplen;
    out.resize(outlen);

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<uint8_t> CryptoEngine::AES_Encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> aes_key = derive_aes256_key(key);

    std::vector<uint8_t> iv(16);
    if (1 != RAND_bytes(iv.data(), (int)iv.size())) throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    std::vector<uint8_t> out(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outlen1 = 0;
    if (1 != EVP_EncryptUpdate(ctx, out.data(), &outlen1, plaintext.data(), (int)plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int outlen2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, out.data() + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }

    out.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);

    // Prepend IV: ciphertext = IV || out
    std::vector<uint8_t> result;
    result.reserve(iv.size() + out.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), out.begin(), out.end());
    return result;
}

std::vector<uint8_t> CryptoEngine::AES_Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() < 16) return std::vector<uint8_t>();
    std::vector<uint8_t> aes_key = derive_aes256_key(key);

    const uint8_t* iv = ciphertext.data();
    const uint8_t* ct = ciphertext.data() + 16;
    size_t ct_len = ciphertext.size() - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::vector<uint8_t>();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> out(ct_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outlen1 = 0;
    if (1 != EVP_DecryptUpdate(ctx, out.data(), &outlen1, ct, (int)ct_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }

    int outlen2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, out.data() + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<uint8_t>();
    }

    out.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<uint8_t> CryptoEngine::XOR_Crypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& mask) {
    if (mask.empty()) throw std::invalid_argument("mask must not be empty");
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        out[i] = data[i] ^ mask[i % mask.size()];
    }
    return out;
}

std::vector<uint8_t> CryptoEngine::ORE_Encrypt(const std::vector<uint8_t>& key, uint64_t value) {
    const std::vector<uint8_t> prf_key = derive_ore_prf_key(key);

    std::vector<uint8_t> out;
    out.reserve(ORE_CIPHERTEXT_SIZE);
    out.insert(out.end(), std::begin(ORE_MAGIC), std::end(ORE_MAGIC));
    out.push_back(ORE_VERSION);
    out.push_back(ORE_BLOCK_BITS);
    out.push_back(ORE_BLOCK_COUNT);
    out.push_back(ORE_MODULUS);

    for (uint8_t i = 0; i < ORE_BLOCK_COUNT; ++i) {
        const uint8_t shift = static_cast<uint8_t>(64 - ORE_BLOCK_BITS * (i + 1));
        const uint8_t block = static_cast<uint8_t>((value >> shift) & (ORE_ALPHABET_SIZE - 1u));
        const uint64_t prefix = (i == 0) ? 0 : (value >> (64 - ORE_BLOCK_BITS * i));
        const uint8_t mask = prf_mod31(prf_key, i, prefix);
        out.push_back(static_cast<uint8_t>((mask + block) % ORE_MODULUS));
    }

    return out;
}

int CryptoEngine::ORE_Compare(const std::vector<uint8_t>& c1, const std::vector<uint8_t>& c2) {
    if (!is_valid_ore_ciphertext(c1) || !is_valid_ore_ciphertext(c2)) return 0;

    for (size_t i = 0; i < ORE_BLOCK_COUNT; ++i) {
        const uint8_t a = c1[ORE_HEADER_SIZE + i];
        const uint8_t b = c2[ORE_HEADER_SIZE + i];
        if (a == b) continue;

        const uint8_t delta = static_cast<uint8_t>((ORE_MODULUS + b - a) % ORE_MODULUS);
        if (delta > 0 && delta < ORE_ALPHABET_SIZE) return -1;
        return 1;
    }

    return 0;
}
