#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

class CryptoEngine {
public:
    // PRF: HMAC-SHA256
    static std::vector<uint8_t> PRF(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);

    // PRP: AES-ECB on one fixed-size block (16 bytes).
    static std::vector<uint8_t> PRP(const std::vector<uint8_t>& key, const std::vector<uint8_t>& index);

    // H(dfs): unkeyed SHA-256 equality hash used by T_I and exact trapdoors.
    static std::vector<uint8_t> DfsHash(const std::vector<uint8_t>& dfs_bytes);

    // E_x = pi_3(k3, x).  Features are encoded injectively into complete AES
    // blocks before applying the fixed-block PRP to every block.  This avoids
    // the truncation alias that a direct fixed-block PRP call would create.
    static std::vector<uint8_t> FeatureRowId(
        const std::vector<uint8_t>& k3,
        const std::string& feature);

    // Domain-separated TI, exact-trapdoor, fallback, and closure derivations.
    static std::vector<uint8_t> DfsEdMask(
        const std::vector<uint8_t>& k4,
        const std::vector<uint8_t>& dfs_bytes);
    static std::vector<uint8_t> DfsEdMask(
        const std::vector<uint8_t>& k4,
        const std::vector<uint8_t>& dfs_bytes,
        size_t out_len);
    static std::vector<uint8_t> ClosureHeadFactor(
        const std::vector<uint8_t>& k5,
        const std::vector<uint8_t>& addr);

    // E_x^CF = pi_3(k3^CF, x), and P_5(k8^CF, E_x^CF).
    static std::vector<uint8_t> CfbiRowId(
        const std::vector<uint8_t>& k3_cfbi,
        const std::string& feature);
    static std::vector<uint8_t> CfbiMask(
        const std::vector<uint8_t>& k8_cfbi,
        const std::vector<uint8_t>& protected_row_id,
        size_t out_len);
    static std::vector<uint8_t> IftiMask(
        const std::vector<uint8_t>& k_ifti_mask,
        const std::vector<uint8_t>& protected_row_id,
        size_t out_len);

    // Domain-separated ORE subkeys for triplet-count and graphlet-count data.
    static std::vector<uint8_t> TripletOreKey(
        const std::vector<uint8_t>& k6,
        const std::string& feature,
        size_t graph_size);
    static std::vector<uint8_t> GraphletOreKey(
        const std::vector<uint8_t>& k6_graphlet,
        int graphlet_type);

    // AES-256-CBC encrypt/decrypt. Encrypt returns IV || ciphertext.
    static std::vector<uint8_t> AES_Encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext);
    static std::vector<uint8_t> AES_Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext);

    // XOR mask (data XOR mask, mask cycles if shorter)
    static std::vector<uint8_t> XOR_Crypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& mask);

    // PRF-based ORE for uint64_t values. The ciphertext is comparable without
    // any secret key; ORE_Compare returns -1 if c1<c2, 0 if equal, 1 if c1>c2.
    static std::vector<uint8_t> ORE_Encrypt(const std::vector<uint8_t>& key, uint64_t value);
    static int ORE_Compare(const std::vector<uint8_t>& c1, const std::vector<uint8_t>& c2);
};
