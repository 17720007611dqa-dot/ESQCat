#pragma once

#include "CryptoUtils.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace GraphletMaskUtils {

inline void append_u64_be(std::vector<uint8_t>& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xFF));
    }
}

inline std::vector<uint8_t> suffixMaskInput(int type, uint64_t observed_count) {
    const std::string domain = "graphlet_suffix_mask";
    std::vector<uint8_t> input(domain.begin(), domain.end());
    input.push_back(0);
    append_u64_be(input, static_cast<uint64_t>(type));
    append_u64_be(input, observed_count);
    return input;
}

inline std::vector<uint8_t> derivePrfStream(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& input,
    size_t output_len) {
    std::vector<uint8_t> stream;
    stream.reserve(output_len);
    uint64_t counter = 0;
    while (stream.size() < output_len) {
        std::vector<uint8_t> block_input = input;
        append_u64_be(block_input, counter++);
        std::vector<uint8_t> block = CryptoEngine::PRF(key, block_input);
        const size_t take = std::min(block.size(), output_len - stream.size());
        stream.insert(stream.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return stream;
}

inline std::vector<uint8_t> deriveTreeId(const std::vector<uint8_t>& k3_graphlet, int type) {
    return CryptoEngine::PRP(k3_graphlet, std::vector<uint8_t>{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, static_cast<uint8_t>(type)});
}

inline std::vector<uint8_t> deriveSuffixMaskStream(
    const std::vector<uint8_t>& k8_graphlet,
    int type,
    uint64_t observed_count,
    size_t output_len) {
    return derivePrfStream(
        k8_graphlet,
        suffixMaskInput(type, observed_count),
        output_len);
}

} // namespace GraphletMaskUtils
