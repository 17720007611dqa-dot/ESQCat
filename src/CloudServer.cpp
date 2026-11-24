#include "CloudServer.h"
#include "IndexBuilder.h"
#include "CryptoUtils.h"
#include "DataStructures.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <set>

namespace {
constexpr size_t kTiAddressBytes = kTiProtectedAddressBytes;
constexpr size_t kClosurePayloadBytes = kClosurePointerPayloadBytes;
}

static std::vector<uint8_t> bitwise_or_vec(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = std::max(a.size(), b.size());
    std::vector<uint8_t> out(n, 0);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t av = i < a.size() ? a[i] : 0;
        const uint8_t bv = i < b.size() ? b[i] : 0;
        out[i] = static_cast<uint8_t>(av | bv);
    }
    return out;
}

static std::vector<uint8_t> bitwise_and_vec(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = std::max(a.size(), b.size());
    std::vector<uint8_t> out(n, 0);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t av = i < a.size() ? a[i] : 0;
        const uint8_t bv = i < b.size() ? b[i] : 0;
        out[i] = static_cast<uint8_t>(av & bv);
    }
    return out;
}

static std::vector<uint64_t> ids_from_bitvector(const std::vector<uint8_t>& bits) {
    std::vector<uint64_t> ids;
    for (size_t byte_idx = 0; byte_idx < bits.size(); ++byte_idx) {
        uint8_t b = bits[byte_idx];
        if (b == 0) continue;
        for (int bit = 0; bit < 8; ++bit) {
            if (b & static_cast<uint8_t>(1u << bit)) {
                ids.push_back(static_cast<uint64_t>(byte_idx * 8 + static_cast<size_t>(bit)));
            }
        }
    }
    return ids;
}

static std::vector<uint8_t> all_graph_ids_bitmap(const IndexBuilder& index) {
    std::vector<uint8_t> bits(index.dataset_size_bytes, 0xff);
    if (!bits.empty() && index.dataset_graph_count % 8 != 0) {
        bits.back() = static_cast<uint8_t>(
            (1u << (index.dataset_graph_count % 8)) - 1u);
    }
    return bits;
}

static std::vector<uint8_t> bitvector_from_ids(
    const std::vector<uint64_t>& ids,
    size_t bitvec_bytes) {
    std::vector<uint8_t> bits(bitvec_bytes, 0);
    for (uint64_t graph_id : ids) {
        const size_t byte_idx = static_cast<size_t>(graph_id / 8);
        const size_t bit_idx = static_cast<size_t>(graph_id % 8);
        if (byte_idx < bits.size()) {
            bits[byte_idx] |= static_cast<uint8_t>(1u << bit_idx);
        }
    }
    return bits;
}

static std::vector<uint8_t> u64_to_be_local(uint64_t v) {
    std::vector<uint8_t> b(8);
    for (int i = 7; i >= 0; --i) {
        b[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
    return b;
}

static uint64_t be_to_u64_local(const std::vector<uint8_t>& bytes) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8 && i < bytes.size(); ++i) {
        v = (v << 8) | bytes[i];
    }
    return v;
}

static std::vector<std::vector<uint8_t>> deserialize_address_set(
    const std::vector<uint8_t>& serialized) {
    std::vector<std::vector<uint8_t>> addresses;
    if (serialized.size() < 8) return addresses;
    const uint64_t count = be_to_u64_local(serialized);
    if ((serialized.size() - 8) % kTiAddressBytes != 0) return {};
    const size_t available = (serialized.size() - 8) / kTiAddressBytes;
    if (count > available) return {};
    addresses.reserve(static_cast<size_t>(count));
    size_t offset = 8;
    for (uint64_t i = 0; i < count; ++i) {
        addresses.emplace_back(
            serialized.begin() + static_cast<std::ptrdiff_t>(offset),
            serialized.begin() + static_cast<std::ptrdiff_t>(offset + kTiAddressBytes));
        offset += kTiAddressBytes;
    }
    return addresses;
}

static std::vector<uint8_t> recover_graphlet_filter_bitmap(
    const Trapdoor& trapdoor,
    const IndexBuilder& index) {
    if (trapdoor.graphlet_impossible) {
        return std::vector<uint8_t>(index.dataset_size_bytes, 0);
    }

    std::vector<uint8_t> graphlet_filter_bits = all_graph_ids_bitmap(index);
    if (trapdoor.T_Graphlet.empty()) return graphlet_filter_bits;
    for (const auto& g_trap : trapdoor.T_Graphlet) {
        const auto it_tree = index.graphlet_bplus_trees.find(g_trap.tree_tag);
        if (it_tree == index.graphlet_bplus_trees.end() || it_tree->second.empty()) {
            graphlet_filter_bits.assign(index.dataset_size_bytes, 0);
            break;
        }

        std::vector<uint8_t> masked_suffix;
        if (!it_tree->second.lookup_equal_masked_bitmap(g_trap.ore_key, masked_suffix)) {
            graphlet_filter_bits.assign(index.dataset_size_bytes, 0);
            break;
        }
        std::vector<uint8_t> graphlet_bits =
            CryptoEngine::XOR_Crypt(masked_suffix, g_trap.bitmap_mask_stream);
        graphlet_bits.resize(index.dataset_size_bytes, 0);
        graphlet_filter_bits = bitwise_and_vec(graphlet_filter_bits, graphlet_bits);
    }

    return graphlet_filter_bits;
}

static void apply_graphlet_filter(QueryResult& qr, const Trapdoor& trapdoor, const IndexBuilder& index) {
    if (trapdoor.T_Graphlet.empty() && !trapdoor.graphlet_impossible) return;
    const std::vector<uint8_t> graphlet_filter_bits = recover_graphlet_filter_bitmap(trapdoor, index);

    std::vector<uint8_t> semantic_bits = qr.aggregated_bitvector;
    if (semantic_bits.empty()) {
        semantic_bits = bitvector_from_ids(qr.matched_ids, index.dataset_size_bytes);
    }
    semantic_bits.resize(index.dataset_size_bytes, 0);
    const std::vector<uint8_t> filtered_bits =
        bitwise_and_vec(semantic_bits, graphlet_filter_bits);

    qr.aggregated_bitvector = filtered_bits;
    qr.matched_ids = ids_from_bitvector(filtered_bits);
}

QueryResult CloudServer::query(const Trapdoor& trapdoor, const IndexBuilder& index) {
    QueryResult qr;

    // Algorithm 5 FG initial trapdoor: τ_T is bundled once and contains every
    // applicable graph-size slice.  A miss in one slice is local to that
    // slice; only an exact hit returns early, otherwise all slices are
    // exhausted before the caller may generate supplementary fallback tokens.
    if (!trapdoor.fg_size_slices.empty()) {
        return continue_bundled_fg_query(trapdoor, index, 0);
    }

    std::vector<uint8_t> ife_intersection_bits;
    bool has_ife_condition = false;
    const size_t bitvec_bytes = index.dataset_size_bytes;

    for (const auto& edge_info : trapdoor.T_Edge) {
        const auto& row_key = std::get<0>(edge_info);
        const auto& key_material = std::get<2>(edge_info);

        auto ife_it = index.ife_table.find(row_key);
        if (ife_it != index.ife_table.end()) {

            has_ife_condition = true;
            const std::vector<uint8_t>& payload_stream = ife_it->second;
            if (bitvec_bytes == 0) continue;

            std::vector<uint8_t> row_bits(bitvec_bytes, 0);
            for (size_t off = 0; off + bitvec_bytes <= payload_stream.size(); off += bitvec_bytes) {
                std::vector<uint8_t> chunk(payload_stream.begin() + static_cast<std::ptrdiff_t>(off),
                                           payload_stream.begin() + static_cast<std::ptrdiff_t>(off + bitvec_bytes));
                std::vector<uint8_t> bits = CryptoEngine::XOR_Crypt(chunk, key_material);
                row_bits = bitwise_or_vec(row_bits, bits);

            }

            if (ife_intersection_bits.empty()) {
                ife_intersection_bits = std::move(row_bits);
            } else {
                ife_intersection_bits = bitwise_and_vec(ife_intersection_bits, row_bits);
            }
            continue;
        }

        return qr;
    }

    if (has_ife_condition) {
        qr.aggregated_bitvector = ife_intersection_bits;
        qr.matched_ids = ids_from_bitvector(ife_intersection_bits);
    }
    apply_graphlet_filter(qr, trapdoor, index);
    return qr;
}

QueryResult CloudServer::continue_bundled_fg_query(
    const Trapdoor& trapdoor,
    const IndexBuilder& index,
    size_t first_slice_index) {
    QueryResult qr;
    for (size_t slice_index = first_slice_index;
         slice_index < trapdoor.fg_size_slices.size(); ++slice_index) {
        const FgSizeSliceTrapdoor& slice = trapdoor.fg_size_slices[slice_index];
            QueryResult slice_result;
            std::map<std::vector<uint8_t>, int> addr_hit_counts;
            size_t num_conditions = 0;
            bool slice_has_empty_condition = false;

            for (const FeatureTrapdoorToken& edge_info : slice.feature_tokens) {
                const auto& row_key = std::get<0>(edge_info);
                const auto& ore_limit = std::get<1>(edge_info);
                const auto& key_material = std::get<2>(edge_info);
                const auto row_it = index.trip_table.find(row_key);
                if (row_it == index.trip_table.end()) {
                    slice_has_empty_condition = true;
                    break;
                }

                std::vector<std::vector<uint8_t>> addresses;
                const auto size_it = row_it->second.size_slices.find(slice.graph_size);
                if (size_it != row_it->second.size_slices.end()) {
                    for (const TripCell& cell : size_it->second) {
                        if (CryptoEngine::ORE_Compare(cell.ORE_limit, ore_limit) < 0) continue;
                        const std::vector<uint8_t> payload =
                            CryptoEngine::AES_Decrypt(key_material, cell.AES_addr);
                        const auto address_set = deserialize_address_set(payload);
                        addresses.insert(addresses.end(), address_set.begin(), address_set.end());
                    }
                }
                if (addresses.empty()) {
                    slice_has_empty_condition = true;
                    break;
                }
                std::sort(addresses.begin(), addresses.end());
                addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
                ++num_conditions;
                for (const auto& address : addresses) ++addr_hit_counts[address];
            }

            if (slice_has_empty_condition || num_conditions != slice.feature_tokens.size()) continue;

            for (const auto& item : addr_hit_counts) {
                if (static_cast<size_t>(item.second) != num_conditions) continue;
                const auto ti_it = index.ti_table.find(item.first);

                if (ti_it != index.ti_table.end() &&
                    ti_it->second.H_dfs == trapdoor.T_Exact.H_dfs) {
                    slice_result.aggregated_bitvector = CryptoEngine::XOR_Crypt(
                        ti_it->second.ED, trapdoor.T_Exact.K_xor);
                    slice_result.matched_ids = ids_from_bitvector(slice_result.aggregated_bitvector);

                    return slice_result;
                }
                // A root whose EA is plaintext NULL has no CLOS and therefore
                // needs neither a closure request nor a k5-derived factor.
                if (ti_it != index.ti_table.end() && !ti_it->second.EA.empty()) {
                    slice_result.unresolved_addrs.push_back(item.first);
                }
            }

            if (!slice_result.unresolved_addrs.empty()) {
                slice_result.closure_authorization_required = true;
                slice_result.next_fg_slice_index = slice_index + 1;

                return slice_result;
            }
        }
        return qr;
    }

std::vector<uint8_t> CloudServer::query_clos(
    const std::vector<std::vector<uint8_t>>& Si_addrs,
    const std::vector<std::vector<uint8_t>>& tau2,
    const Trapdoor& trapdoor,
    const IndexBuilder& index)
{
    for (size_t i = 0; i < Si_addrs.size() && i < tau2.size(); ++i) {
        const std::vector<uint8_t>& addr = Si_addrs[i];
        std::vector<uint8_t> alpha = tau2[i];

        auto it = index.ti_table.find(addr);
        if (it == index.ti_table.end()) continue; // malformed root address
        if (it->second.EA.empty()) continue; // plaintext NULL: root has no CLOS

        std::vector<uint8_t> alpha_pad = alpha;
        alpha_pad.resize(it->second.EA.size(), 0);
        std::vector<uint8_t> ctr_add = CryptoEngine::XOR_Crypt(it->second.EA, alpha_pad);

        if (ctr_add.size() != kClosurePayloadBytes) continue;

        uint64_t curr_ctr = be_to_u64_local(ctr_add);
        std::vector<uint8_t> next_add(ctr_add.begin() + 8, ctr_add.end());

        auto next_it = index.ti_table.find(next_add);
        if (next_it == index.ti_table.end()) continue; // malformed protected pointer

        if (next_it->second.H_dfs == trapdoor.T_Exact.H_dfs) {
            return CryptoEngine::XOR_Crypt(next_it->second.ED, trapdoor.T_Exact.K_xor);
        }

        std::vector<uint8_t> curr_add = next_add;
        std::set<std::vector<uint8_t>> visited{addr};
        while (visited.insert(curr_add).second) {
            std::vector<uint8_t> ctr_input = u64_to_be_local(curr_ctr);
            std::vector<uint8_t> p2_alpha_ctr = CryptoEngine::PRF(alpha, ctr_input);

            auto curr_it = index.ti_table.find(curr_add);
            if (curr_it == index.ti_table.end() || curr_it->second.EA.empty()) break; // malformed chain

            std::vector<uint8_t> pad_alpha = p2_alpha_ctr;
            pad_alpha.resize(curr_it->second.EA.size(), 0);
            std::vector<uint8_t> ctr_add_prime = CryptoEngine::XOR_Crypt(curr_it->second.EA, pad_alpha);

            if (ctr_add_prime.size() != kClosurePayloadBytes) break;

            if (IsCanonicalClosureNullPayload(ctr_add_prime)) break;

            std::vector<uint8_t> add_prime(ctr_add_prime.begin() + 8, ctr_add_prime.end());
            auto prime_it = index.ti_table.find(add_prime);
            if (prime_it == index.ti_table.end()) break; // malformed chain, never normal termination

            if (prime_it->second.H_dfs == trapdoor.T_Exact.H_dfs) {
                return CryptoEngine::XOR_Crypt(prime_it->second.ED, trapdoor.T_Exact.K_xor);
            }

            alpha = p2_alpha_ctr;
            curr_ctr = be_to_u64_local(ctr_add_prime);
            curr_add = add_prime;
        }
    }
    return std::vector<uint8_t>();
}

QueryResult CloudServer::complete_feature_fallback_query(
    const CompleteFeatureFallbackTrapdoor& trapdoor,
    const IndexBuilder& index,
    const Trapdoor& full_query_trapdoor) {
    QueryResult result;
    result.aggregated_bitvector.assign(index.dataset_size_bytes, 0);
    if (trapdoor.entries.empty()) {
        std::cerr << "[CloudServer] WARNING: CFBI fallback trapdoor has no feature rows"
                  << std::endl;
        return result;
    }

    std::vector<uint8_t> semantic_bits = all_graph_ids_bitmap(index);
    for (const auto& entry : trapdoor.entries) {
        if (entry.unmasking_factor.size() != index.dataset_size_bytes) {
            std::cerr << "[CloudServer] WARNING: CFBI unmasking factor length is invalid"
                      << std::endl;
            return result;
        }
        const auto row_it =
            index.complete_feature_bitmap_index.find(entry.feature_tag);
        if (row_it == index.complete_feature_bitmap_index.end()) {
            std::cerr << "[CloudServer] WARNING: required CFBI feature row is missing"
                      << std::endl;
            return result;
        }
        if (row_it->second.size() != index.dataset_size_bytes) {
            std::cerr << "[CloudServer] WARNING: CFBI row bitmap length is invalid"
                      << std::endl;
            return result;
        }

        std::vector<uint8_t> feature_bits = CryptoEngine::XOR_Crypt(
            row_it->second, entry.unmasking_factor);
        feature_bits.resize(index.dataset_size_bytes, 0);
        semantic_bits = bitwise_and_vec(semantic_bits, feature_bits);
    }

    const std::vector<uint8_t> graphlet_bits = recover_graphlet_filter_bitmap(
        full_query_trapdoor, index);
    const std::vector<uint8_t> final_bits =
        bitwise_and_vec(semantic_bits, graphlet_bits);

    result.aggregated_bitvector = final_bits;
    result.matched_ids = ids_from_bitvector(final_bits);
    return result;
}
