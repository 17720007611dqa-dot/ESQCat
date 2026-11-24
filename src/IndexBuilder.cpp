#include "IndexBuilder.h"
#include "GraphletUtils.h"
#include "GraphletMaskUtils.h"
#include "GSpanMiner.h"
#include "SubgraphUtils.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace {
constexpr size_t kTiAddressBytes = 16;
}

static std::vector<uint8_t> u64_to_be_local(uint64_t v) {
    std::vector<uint8_t> b(8);
    for (int i = 7; i >= 0; --i) {
        b[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
    return b;
}

static std::vector<uint8_t> label_size_input_local(const std::string& label, size_t graph_size) {
    std::vector<uint8_t> input(label.begin(), label.end());
    const std::vector<uint8_t> size_bytes = u64_to_be_local(static_cast<uint64_t>(graph_size));
    input.insert(input.end(), size_bytes.begin(), size_bytes.end());
    return input;
}

static std::vector<uint8_t> serialize_address_set_local(
    std::vector<std::vector<uint8_t>> addresses) {
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
    addresses.erase(
        std::remove_if(addresses.begin(), addresses.end(), [](const auto& addr) {
            return addr.size() != kTiAddressBytes;
        }),
        addresses.end());
    std::vector<uint8_t> out = u64_to_be_local(static_cast<uint64_t>(addresses.size()));
    out.reserve(8 + addresses.size() * kTiAddressBytes);
    for (const auto& addr : addresses) {
        out.insert(out.end(), addr.begin(), addr.end());
    }
    return out;
}


static void set_bitmap_bit_local(std::vector<uint8_t>& bitmap, size_t graph_idx) {
    const size_t byte_idx = graph_idx / 8;
    const size_t bit_idx = graph_idx % 8;
    if (byte_idx < bitmap.size()) {
        bitmap[byte_idx] |= static_cast<uint8_t>(1u << bit_idx);
    }
}

static void or_bitmap_local(std::vector<uint8_t>& destination, const std::vector<uint8_t>& source) {
    const size_t n = std::min(destination.size(), source.size());
    for (size_t i = 0; i < n; ++i) {
        destination[i] = static_cast<uint8_t>(destination[i] | source[i]);
    }
}

static std::vector<uint8_t> graphlet_suffix_mask(
    const std::vector<uint8_t>& k8_graphlet,
    int type,
    uint64_t observed_count,
    size_t output_len) {
    return GraphletMaskUtils::deriveSuffixMaskStream(
        k8_graphlet,
        type,
        observed_count,
        output_len);
}

static std::unordered_map<std::string, int> extract_edge_features_local(
    const Graph& g) {
    std::unordered_map<std::string, int> feature_counts;
    auto edges = boost::edges(g);
    for (auto it = edges.first; it != edges.second; ++it) {
        auto u = boost::source(*it, g);
        auto v = boost::target(*it, g);
        std::string lu = g[u].label;
        std::string lv = g[v].label;
        std::string min_node = std::min(lu, lv);
        std::string max_node = std::max(lu, lv);
        std::ostringstream oss;
        oss << min_node << "|" << g[*it].label << "|" << max_node;
        feature_counts[oss.str()]++;
    }
    return feature_counts;
}

static std::unordered_map<std::string, int> vertex_label_counts_local(const Graph& g) {
    std::unordered_map<std::string, int> counts;
    auto vertices = boost::vertices(g);
    for (auto it = vertices.first; it != vertices.second; ++it) {
        counts[g[*it].label]++;
    }
    return counts;
}

static bool covers_multiset_local(
    const std::unordered_map<std::string, int>& container,
    const std::unordered_map<std::string, int>& required) {
    for (const auto& kv : required) {
        const auto it = container.find(kv.first);
        if (it == container.end() || it->second < kv.second) return false;
    }
    return true;
}

struct FrequentGraphMetaLocal {
    size_t edge_count = 0;
    size_t vertex_count = 0;
    std::unordered_map<std::string, int> vertex_labels;
    std::unordered_map<std::string, int> edge_features;
};

static FrequentGraphMetaLocal make_fg_meta_local(
    const FrequentGraph& fg) {
    FrequentGraphMetaLocal meta;
    meta.edge_count = boost::num_edges(fg.g);
    meta.vertex_count = boost::num_vertices(fg.g);
    meta.vertex_labels = vertex_label_counts_local(fg.g);
    meta.edge_features = extract_edge_features_local(fg.g);
    return meta;
}

static bool can_cover_before_vf2_local(
    const FrequentGraphMetaLocal& small,
    const FrequentGraphMetaLocal& large) {
    if (small.vertex_count > large.vertex_count) return false;
    if (small.edge_count > large.edge_count) return false;
    if (!covers_multiset_local(large.vertex_labels, small.vertex_labels)) return false;
    if (!covers_multiset_local(large.edge_features, small.edge_features)) return false;
    return true;
}


// Exact non-induced, label-preserving subgraph containment.
static bool is_subgraph_real(const Graph& small_g, const Graph& large_g) {
    return SubgraphUtils::isLabelPreservingSubgraph(small_g, large_g);
}

static std::string paper_dfs_code_string(const Graph& g) {
    return GSpanMiner::dfsCodeToString(GSpanMiner::buildMinDFSCode(g));
}

static void extract_delta_tcfg_algorithm3_local(
    std::vector<FrequentGraph>& fgs,
    const std::vector<FrequentGraphMetaLocal>& fg_meta,
    const std::map<size_t, std::vector<size_t>>& fgs_by_edge_count,
    double delta_tolerance) {
    for (size_t i = 0; i < fgs.size(); ++i) {
        fgs[i].is_delta_tcfg = true;
        const auto bucket_it = fgs_by_edge_count.find(fg_meta[i].edge_count + 1);
        if (bucket_it == fgs_by_edge_count.end()) continue;

        const double threshold =
            (1.0 - delta_tolerance) * static_cast<double>(fgs[i].frequency);
        int previous_frequency = std::numeric_limits<int>::max();
        for (size_t j : bucket_it->second) {
            if (fgs[j].frequency > previous_frequency) {
                throw std::logic_error(
                    "delta-TCFG candidate bucket is not support-descending");
            }
            previous_frequency = fgs[j].frequency;

            // Non-strict support predicate. Equality remains qualified.
            // Because this bucket is support-descending, once a candidate is
            // below threshold every later candidate is also ineligible.
            if (static_cast<double>(fgs[j].frequency) < threshold) break;
            if (!can_cover_before_vf2_local(fg_meta[i], fg_meta[j])) continue;
            if (!is_subgraph_real(fgs[i].g, fgs[j].g)) continue;

            fgs[i].is_delta_tcfg = false;
            break;
        }
    }
}

static std::map<size_t, std::vector<size_t>> assign_closest_delta_tcfg_clos_local(
    std::vector<FrequentGraph>& fgs,
    const std::vector<FrequentGraphMetaLocal>& fg_meta) {
    std::map<size_t, std::vector<size_t>> chains;
    for (size_t f_idx = 0; f_idx < fgs.size(); ++f_idx) {
        if (fgs[f_idx].is_delta_tcfg) continue;

        bool assigned = false;
        for (size_t t_idx = 0; t_idx < fgs.size(); ++t_idx) {
            if (!fgs[t_idx].is_delta_tcfg) continue;
            if (fg_meta[t_idx].edge_count <= fg_meta[f_idx].edge_count) continue;
            if (!can_cover_before_vf2_local(fg_meta[f_idx], fg_meta[t_idx])) continue;
            if (!is_subgraph_real(fgs[f_idx].g, fgs[t_idx].g)) continue;

            chains[t_idx].push_back(f_idx);
            assigned = true;
            break;
        }

        if (!assigned) {
            std::cerr << "[IndexBuilder] WARNING: non-delta FG order_id="
                      << fgs[f_idx].order_id
                      << " has no closest delta-TCFG supergraph; marking it as delta-TCFG."
                      << std::endl;
            fgs[f_idx].is_delta_tcfg = true;
        }
    }
    for (auto& kv : chains) {
        auto& chain = kv.second;
        std::sort(chain.begin(), chain.end(), [&](size_t lhs, size_t rhs) {
            return graph_set_order_less(fgs[lhs], fgs[rhs]);
        });
    }
    return chains;
}

static void build_ifti_from_delta_feature_complement_local(
    const std::vector<Graph>& dataset,
    const std::unordered_set<std::string>& delta_triplet_features,
    size_t dataset_size_bytes,
    const std::vector<uint8_t>& k3,
    const std::vector<uint8_t>& k8,
    std::unordered_map<std::vector<uint8_t>, std::vector<uint8_t>,
                       VectorUint8Hash, VectorUint8Eq>& ife_table) {
    std::unordered_map<std::string, std::vector<uint8_t>> plaintext_rows;
    for (size_t graph_idx = 0; graph_idx < dataset.size(); ++graph_idx) {
        const auto features = extract_edge_features_local(dataset[graph_idx]);
        for (const auto& feature : features) {
            if (delta_triplet_features.find(feature.first) !=
                delta_triplet_features.end()) {
                continue;
            }
            auto& bitmap = plaintext_rows[feature.first];
            if (bitmap.empty()) bitmap.assign(dataset_size_bytes, 0);
            set_bitmap_bit_local(bitmap, graph_idx);
        }
    }

    for (const auto& row : plaintext_rows) {
        const std::vector<uint8_t> row_key = CryptoEngine::FeatureRowId(k3, row.first);
        const std::vector<uint8_t> mask =
            CryptoEngine::IftiMask(k8, row_key, dataset_size_bytes);
        ife_table.emplace(row_key, CryptoEngine::XOR_Crypt(row.second, mask));
    }
}

static void build_fei_paper_buckets_local(
    const std::vector<FrequentGraph>& fgs,
    const std::vector<FrequentGraphMetaLocal>& fg_meta,
    const std::vector<std::vector<uint8_t>>& fg_addrs,
    const std::unordered_set<std::string>& frequent_labels,
    const std::vector<uint8_t>& k3,
    const std::vector<uint8_t>& k6,
    const std::vector<uint8_t>& k7,
    uint64_t alpha_T,
    uint64_t beta_T,
    std::unordered_map<std::vector<uint8_t>, TripRow, VectorUint8Hash, VectorUint8Eq>& trip_table) {
    std::map<std::string, std::map<int, std::map<int, std::vector<std::vector<uint8_t>>>>> fei_buckets;
    size_t msize_t = 0;
    for (size_t i = 0; i < fgs.size(); ++i) {
        if (!fgs[i].is_delta_tcfg) continue;
        msize_t = std::max(msize_t, fg_meta[i].edge_count);
        const size_t graph_size = fg_meta[i].edge_count;
        for (const auto& kv : fg_meta[i].edge_features) {
            if (frequent_labels.find(kv.first) == frequent_labels.end()) continue;
            fei_buckets[kv.first][static_cast<int>(graph_size)][kv.second].push_back(fg_addrs[i]);
        }
    }

    size_t cells_per_size = 0;
    for (const auto& label_kv : fei_buckets) {
        for (const auto& size_kv : label_kv.second) {
            cells_per_size = std::max(cells_per_size, size_kv.second.size());
        }
    }
    if (!frequent_labels.empty() && msize_t > 0) {
        cells_per_size = std::max<size_t>(cells_per_size, 1);
    }
    for (const auto& label : frequent_labels) {
        const std::vector<uint8_t> row_key = CryptoEngine::FeatureRowId(k3, label);

        for (size_t size_value = 1; size_value <= msize_t; ++size_value) {
            const int graph_size = static_cast<int>(size_value);
            const std::vector<uint8_t> label_size_input =
                label_size_input_local(label, static_cast<size_t>(graph_size));
            const std::vector<uint8_t> ore_key =
                CryptoEngine::TripletOreKey(k6, label, static_cast<size_t>(graph_size));
            const std::vector<uint8_t> addr_set_key = CryptoEngine::PRF(k7, label_size_input);

            auto& cells = trip_table[row_key].size_slices[graph_size];
            const auto label_it = fei_buckets.find(label);
            if (label_it != fei_buckets.end()) {
                const auto size_it = label_it->second.find(graph_size);
                if (size_it != label_it->second.end()) {
                    for (const auto& count_kv : size_it->second) {
                        const uint64_t obf_count =
                            alpha_T * static_cast<uint64_t>(count_kv.first) + beta_T;
                        TripCell tc;
                        std::vector<std::vector<uint8_t>> real_addresses = count_kv.second;
                        std::sort(real_addresses.begin(), real_addresses.end());
                        real_addresses.erase(
                            std::unique(real_addresses.begin(), real_addresses.end()),
                            real_addresses.end());
                        tc.ORE_limit = CryptoEngine::ORE_Encrypt(ore_key, obf_count);
                        tc.AES_addr = CryptoEngine::AES_Encrypt(
                            addr_set_key,
                            serialize_address_set_local(real_addresses));
                        cells.push_back(std::move(tc));
                    }
                }
            }
            while (cells.size() < cells_per_size) {
                const uint64_t dummy_obf_count = beta_T;
                TripCell dummy_cell;
                dummy_cell.ORE_limit = CryptoEngine::ORE_Encrypt(ore_key, dummy_obf_count);
                dummy_cell.AES_addr = CryptoEngine::AES_Encrypt(
                    addr_set_key,
                    serialize_address_set_local({}));
                cells.push_back(std::move(dummy_cell));
            }
        }
    }
}

std::unordered_map<std::string, int> IndexBuilder::extractEdgeTriplets(const Graph& g) const {
    return extract_edge_features_local(g);
}

void IndexBuilder::buildIndex(const std::vector<Graph>& dataset, std::vector<FrequentGraph>& fgs) {
    if (k3_cfbi.empty() || k8_cfbi.empty()) {
        throw std::logic_error("CFBI requires independent k3_cfbi and k8_cfbi");
    }
    if (k3_graphlet.empty() || k6_graphlet.empty() || k8_graphlet.empty()) {
        throw std::logic_error("Graphlet requires independent k3_graphlet, k6_graphlet, and k8_graphlet");
    }
    ti_table.clear();
    trip_table.clear();
    ife_table.clear();
    complete_feature_bitmap_index.clear();
    graphlet_bplus_trees.clear();
    graphlet_tree_tags_by_type.clear();
    graphlet_leaf_counts_by_type.clear();
    dataset_graph_count = dataset.size();
    dataset_size_bytes = (dataset_graph_count + 7) / 8;

    {
        std::unordered_map<std::string, std::vector<uint8_t>> plaintext_cfbi;
        for (size_t graph_idx = 0; graph_idx < dataset.size(); ++graph_idx) {
            const auto feature_counts = extractEdgeTriplets(dataset[graph_idx]);
            for (const auto& feature_count : feature_counts) {
                auto& bitmap = plaintext_cfbi[feature_count.first];
                if (bitmap.empty()) bitmap.assign(dataset_size_bytes, 0);
                set_bitmap_bit_local(bitmap, graph_idx);
            }
        }
        for (const auto& feature_bitmap : plaintext_cfbi) {
            const std::vector<uint8_t> tag =
                CryptoEngine::CfbiRowId(k3_cfbi, feature_bitmap.first);
            const std::vector<uint8_t> mask =
                CryptoEngine::CfbiMask(
                    k8_cfbi, tag, dataset_size_bytes);
            assert(mask.size() == feature_bitmap.second.size());
            const std::vector<uint8_t> masked_bitmap =
                CryptoEngine::XOR_Crypt(feature_bitmap.second, mask);
            const auto inserted = complete_feature_bitmap_index.emplace(tag, masked_bitmap);
            if (!inserted.second) {
                throw std::runtime_error("CFBI protected feature-token collision");
            }
        }
    }

    {
        // Each topology type has its own B+ tree of masked suffix vectors.
        // We cannot OR masked exact buckets, because (B1 xor M1) OR (B2 xor M2)
        // is not equal to (B1 OR B2) xor M. Instead, the owner materializes
        // count >= threshold suffix vectors at build time. Each query condition
        // then needs exactly one per-threshold mask token.
        std::unordered_map<int, std::map<int, std::vector<uint8_t>>> exact_buckets;
        for (int type = 1; type <= 8; ++type) {
            exact_buckets.emplace(type, std::map<int, std::vector<uint8_t>>());
        }
        for (size_t graph_idx = 0; graph_idx < dataset.size(); ++graph_idx) {
            const auto g_counts = GraphletUtils::extractGraphletCounts(dataset[graph_idx]);
            for (int type = 1; type <= 8; ++type) {
                const int count = g_counts.at(type);
                auto& bitmap = exact_buckets[type][count];
                if (bitmap.empty()) bitmap.assign(dataset_size_bytes, 0);
                set_bitmap_bit_local(bitmap, graph_idx);
            }
        }

        for (int type = 1; type <= 8; ++type) {
            std::vector<uint8_t> tree_tag =
                GraphletMaskUtils::deriveTreeId(k3_graphlet, type);
            const std::vector<uint8_t> ore_key =
                CryptoEngine::GraphletOreKey(k6_graphlet, type);
            graphlet_tree_tags_by_type[type] = tree_tag;

            std::vector<int> actual_counts;
            actual_counts.reserve(exact_buckets[type].size());
            for (const auto& bucket : exact_buckets[type]) {
                actual_counts.push_back(bucket.first);
            }
            graphlet_leaf_counts_by_type[type] = actual_counts;

            std::vector<GraphletBPlusEntry> entries;
            entries.reserve(actual_counts.size());
            std::vector<uint8_t> running_suffix(dataset_size_bytes, 0);
            for (auto it = actual_counts.rbegin(); it != actual_counts.rend(); ++it) {
                const int threshold = *it;
                or_bitmap_local(running_suffix, exact_buckets[type].at(threshold));
                const uint64_t obfuscated =
                    alpha_G * static_cast<uint64_t>(threshold) + beta_G;
                const std::vector<uint8_t> mask =
                    graphlet_suffix_mask(k8_graphlet, type, threshold, dataset_size_bytes);
                entries.push_back({
                    CryptoEngine::ORE_Encrypt(ore_key, obfuscated),
                    CryptoEngine::XOR_Crypt(running_suffix, mask)
                });
            }
            GraphletBPlusTree tree;
            tree.bulk_load(std::move(entries));
            graphlet_bplus_trees.emplace(std::move(tree_tag), std::move(tree));
        }
    }

    std::unordered_set<std::string> frequent_labels;
    if (fgs.empty()) {
        build_ifti_from_delta_feature_complement_local(
            dataset, frequent_labels, dataset_size_bytes, k3, k8, ife_table);
        return;
    }

    // Rebuild Definition 4 order deterministically before CLOS or encrypted
    // address assignment. canonical_label is not uploaded as a cloud index item.
    std::sort(fgs.begin(), fgs.end(), graph_set_order_less);
    for (size_t i = 0; i < fgs.size(); ++i) {
        fgs[i].order_id = static_cast<int>(i + 1);
    }

    // Metadata used to prune paper Algorithm 3 and CLOS VF2 checks.
    std::vector<FrequentGraphMetaLocal> fg_meta;
    fg_meta.reserve(fgs.size());
    std::map<size_t, std::vector<size_t>> fgs_by_edge_count;
    for (size_t i = 0; i < fgs.size(); ++i) {
        fg_meta.push_back(make_fg_meta_local(fgs[i]));
        fgs_by_edge_count[fg_meta.back().edge_count].push_back(i);
    }

    extract_delta_tcfg_algorithm3_local(fgs, fg_meta, fgs_by_edge_count, delta_factor);
    const auto clos_chains = assign_closest_delta_tcfg_clos_local(fgs, fg_meta);

    // Paper L_F is the union of triplet features appearing in the finalized
    // delta-TCFG root set, not the set of database-supported triplets.
    for (size_t i = 0; i < fgs.size(); ++i) {
        if (!fgs[i].is_delta_tcfg) continue;
        for (const auto& feature : fg_meta[i].edge_features) {
            frequent_labels.insert(feature.first);
        }
    }

    build_ifti_from_delta_feature_complement_local(
        dataset, frequent_labels, dataset_size_bytes, k3, k8, ife_table);

    std::vector<std::vector<uint8_t>> fg_addrs(fgs.size());
    for (size_t i = 0; i < fgs.size(); ++i) {
        const std::vector<uint8_t> order_bytes =
            u64_to_be_local(static_cast<uint64_t>(fgs[i].order_id));
        fg_addrs[i] = CryptoEngine::PRP(k1, order_bytes);
    }

    build_fei_paper_buckets_local(
        fgs,
        fg_meta,
        fg_addrs,
        frequent_labels,
        k3,
        k6,
        k7,
        alpha_T,
        beta_T,
        trip_table);

    for (size_t i = 0; i < fgs.size(); ++i) {
        const FrequentGraph& fg = fgs[i];
        const std::string dfs_code = paper_dfs_code_string(fg.g);
        const std::vector<uint8_t> dfs_bytes(
            dfs_code.begin(), dfs_code.end());

        TICell cell;
        cell.H_dfs = CryptoEngine::DfsHash(dfs_bytes);
        const std::vector<uint8_t> ed_mask =
            CryptoEngine::DfsEdMask(k4, dfs_bytes, fg.bit_vector.size());
        cell.ED = CryptoEngine::XOR_Crypt(fg.bit_vector, ed_mask);
        ti_table[fg_addrs[i]] = std::move(cell);
    }
    // Build CLOS chains from the closest delta-TCFG assignments computed above.
    for (const auto& kv : clos_chains) {
        size_t head_idx = kv.first;
        const std::vector<size_t>& chain_tail = kv.second;

        if (chain_tail.empty()) continue;

        const std::vector<uint8_t>& head_addr = fg_addrs[head_idx];

        uint64_t ctr = 1;
        std::vector<uint8_t> g1_addr = fg_addrs[chain_tail[0]];
        std::vector<uint8_t> ctr_addr_1;
        std::vector<uint8_t> ctr_bytes = u64_to_be_local(ctr);
        ctr_addr_1.insert(ctr_addr_1.end(), ctr_bytes.begin(), ctr_bytes.end());
        ctr_addr_1.insert(ctr_addr_1.end(), g1_addr.begin(), g1_addr.end());

        std::vector<uint8_t> p2_k5_head =
            CryptoEngine::ClosureHeadFactor(k5, head_addr);
        p2_k5_head.resize(ctr_addr_1.size(), 0);
        ti_table[head_addr].EA = CryptoEngine::XOR_Crypt(ctr_addr_1, p2_k5_head);

        std::vector<uint8_t> alpha =
            CryptoEngine::ClosureHeadFactor(k5, head_addr);

        for (size_t j = 1; j < chain_tail.size(); ++j) {
            std::vector<uint8_t> gj_addr = fg_addrs[chain_tail[j]];
            std::vector<uint8_t> ctr_addr_j;
            std::vector<uint8_t> next_ctr_bytes = u64_to_be_local(ctr + 1);
            ctr_addr_j.insert(ctr_addr_j.end(), next_ctr_bytes.begin(), next_ctr_bytes.end());
            ctr_addr_j.insert(ctr_addr_j.end(), gj_addr.begin(), gj_addr.end());

            std::vector<uint8_t> ctr_input = u64_to_be_local(ctr);
            std::vector<uint8_t> p2_alpha_ctr = CryptoEngine::PRF(alpha, ctr_input);
            p2_alpha_ctr.resize(ctr_addr_j.size(), 0);

            std::vector<uint8_t> prev_addr = fg_addrs[chain_tail[j - 1]];
            ti_table[prev_addr].EA = CryptoEngine::XOR_Crypt(ctr_addr_j, p2_alpha_ctr);

            alpha = CryptoEngine::PRF(alpha, ctr_input);
            ctr = ctr + 1;
        }

        std::vector<uint8_t> ctr_input_m = u64_to_be_local(ctr);
        std::vector<uint8_t> p2_alpha_ctr_m = CryptoEngine::PRF(alpha, ctr_input_m);

        std::vector<uint8_t> gm_addr = fg_addrs[chain_tail.back()];
        ti_table[gm_addr].EA = CryptoEngine::XOR_Crypt(
            CanonicalClosureNullPayload(), p2_alpha_ctr_m);
    }

}
