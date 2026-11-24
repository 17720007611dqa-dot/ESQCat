#pragma once

#include "CryptoUtils.h"
#include "DataStructures.h"
#include "GraphletBPlusTree.h"
#include "GraphTypes.h"

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>


struct FrequentGraph {
    Graph g;                           // 图的拓扑
    int frequency = 0;                 // 在数据库中出现的频率
    std::vector<uint8_t> bit_vector;   // N-bit 标识符向量
    bool is_delta_tcfg = false;        // 是否为 delta-TCFG
    int order_id = 0;                  // 排序编号
    // Stable pre-encryption tie-breaker; not stored in the encrypted cloud index.
    std::string canonical_label;
};

inline bool graph_set_order_less(const FrequentGraph& a, const FrequentGraph& b) {
    const auto size_a = boost::num_edges(a.g);
    const auto size_b = boost::num_edges(b.g);
    if (size_a != size_b) return size_a < size_b;
    if (a.frequency != b.frequency) return a.frequency > b.frequency;
    if (a.canonical_label != b.canonical_label) return a.canonical_label < b.canonical_label;
    return a.order_id < b.order_id;
}

class IndexBuilder {
public:
    std::vector<uint8_t> k1, k3, k4, k5, k6, k7, k8;
    std::vector<uint8_t> k3_cfbi, k8_cfbi;
    std::vector<uint8_t> k3_graphlet, k6_graphlet, k8_graphlet;
    uint64_t alpha_T = 0;
    uint64_t beta_T = 0;
    uint64_t alpha_G = 0;
    uint64_t beta_G = 0;
    double delta_factor = 0.1;

    // Tables
    size_t dataset_graph_count = 0;
    size_t dataset_size_bytes = 0;
    TITableVecKey ti_table; // TI table keyed by binary address
    std::unordered_map<std::vector<uint8_t>, TripRow, VectorUint8Hash, VectorUint8Eq> trip_table;
    std::unordered_map<std::vector<uint8_t>, std::vector<uint8_t>, VectorUint8Hash, VectorUint8Eq> ife_table;
    // T_CFBI: complete data-graph-level feature-presence bitmaps, masked at
    // rest and keyed by protected feature tokens.
    CompleteFeatureBitmapIndex complete_feature_bitmap_index;
    // One Graphlet B+ tree per PRF tree tag, hiding the plaintext type id from
    // the cloud-side map key.
    std::unordered_map<std::vector<uint8_t>, GraphletBPlusTree, VectorUint8Hash, VectorUint8Eq>
        graphlet_bplus_trees;
    // Client-side metadata for trapdoor generation. In a real deployment this
    // would be provisioned to authorized users, not treated as cloud index data.
    std::unordered_map<int, std::vector<uint8_t>> graphlet_tree_tags_by_type;
    std::unordered_map<int, std::vector<int>> graphlet_leaf_counts_by_type;
    // Initialize with keys and scalars
    void init_keys(const std::vector<uint8_t>& K1,
                   const std::vector<uint8_t>& K3,
                   const std::vector<uint8_t>& K4,
                   const std::vector<uint8_t>& K5,
                   const std::vector<uint8_t>& K6,
                   const std::vector<uint8_t>& K7,
                   const std::vector<uint8_t>& K8,
                   uint64_t a, uint64_t b, double df,
                   const std::vector<uint8_t>& K3CF,
                   const std::vector<uint8_t>& K8CF,
                   const std::vector<uint8_t>& K3G,
                   const std::vector<uint8_t>& K6G,
                   const std::vector<uint8_t>& K8G) {
        k1 = K1; k3 = K3; k4 = K4; k5 = K5; k6 = K6; k7 = K7; k8 = K8;
        alpha_T = a; beta_T = b;
        alpha_G = a; beta_G = b;
        delta_factor = df;
        init_independent_index_keys(K3CF, K8CF, K3G, K6G, K8G);
    }

    void init_independent_index_keys(
        const std::vector<uint8_t>& K3CF, const std::vector<uint8_t>& K8CF,
        const std::vector<uint8_t>& K3G, const std::vector<uint8_t>& K6G,
        const std::vector<uint8_t>& K8G) {
        k3_cfbi = K3CF; k8_cfbi = K8CF;
        k3_graphlet = K3G; k6_graphlet = K6G; k8_graphlet = K8G;
    }

    std::unordered_map<std::string, int> extractEdgeTriplets(const Graph& g) const;

    // Build index from mined frequent subgraphs (sorted by edge size asc)
    // Must pass the complete dataset to build L_all-dependent IFTI/CFBI rows.
    // L_F itself is derived only from triplets appearing in finalized delta-TCFGs.
    void buildIndex(const std::vector<Graph>& dataset, std::vector<FrequentGraph>& fgs);

};
