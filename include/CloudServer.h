#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <tuple>

// Forward declare IndexBuilder to avoid circular dependency
class IndexBuilder;

struct QueryResult {
    std::vector<uint64_t> matched_ids;
    std::vector<uint8_t> aggregated_bitvector;
    std::vector<std::vector<uint8_t>> unresolved_addrs;
    // A bundled FG exact lookup pauses here when the Cloud has actual
    // non-empty-CLOS roots that require Graph-User P2(k5, address)
    // authorization.  The Cloud never derives those factors itself.
    bool closure_authorization_required = false;
    size_t next_fg_slice_index = 0;
};

struct GraphletTrap {
    std::vector<uint8_t> tree_tag;            // PRP-derived protected graphlet-tree identifier Gamma_t.
    std::vector<uint8_t> ore_key;             // ORE ciphertext for the selected obfuscated threshold.
    // Per-leaf stream with length equal to the dataset bitmap byte length. This
    // authorizes only the one masked suffix vector named by ore_key.
    std::vector<uint8_t> bitmap_mask_stream;
};

struct CompleteFeatureFallbackTrapdoorEntry {
    std::vector<uint8_t> feature_tag;
    std::vector<uint8_t> unmasking_factor;
};

struct CompleteFeatureFallbackTrapdoor {
    std::vector<CompleteFeatureFallbackTrapdoorEntry> entries;
};

// One τ_T(s) component of the Algorithm 5 FG initial trapdoor.  The row id
// is shared across sizes, while the ORE token and address-set key are bound to
// this exact graph-size slice.
using FeatureTrapdoorToken = std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>;

struct FgSizeSliceTrapdoor {
    int graph_size = 0;
    std::vector<FeatureTrapdoorToken> feature_tokens;
};

// Trapdoor structure for encrypted query
struct Trapdoor {
    // Query graph size (number of edges)
    int query_size = 0;

    // [ALGORITHM 5.4] 标记该陷门是否为纯 IFG 陷门（包含非频繁标签）
    bool is_IFG_trapdoor = false;

    std::vector<GraphletTrap> T_Graphlet;
    bool graphlet_impossible = false;
    // Graphlet B+ tree leaves contain masked suffix identifier vectors. No
    // long-lived graph-id decryption key or raw k9 is carried in this trapdoor.

    // IFG tokens. FG initial trapdoors use fg_size_slices instead.
    std::vector<FeatureTrapdoorToken> T_Edge;

    // Algorithm 5 τ_T = {τ_T(s) | |q| <= s <= Msize(T)}.  A non-empty
    // vector denotes one bundled FG initial protocol message.
    std::vector<FgSizeSliceTrapdoor> fg_size_slices;

    // T_Exact: exact matching info
    struct {
        std::vector<uint8_t> H_dfs;      // DfsHash(dfs_code)
        std::vector<uint8_t> K_xor;      // DfsEdMask(k4, dfs_code)
    } T_Exact;
};

class CloudServer {
public:
    CloudServer() = default;

    // Execute query on encrypted index
    QueryResult query(const Trapdoor& trapdoor, const IndexBuilder& index);

    // Continue one already-received bundled Algorithm 5 FG trapdoor after
    // Graph-User closure authorization for a prior slice did not match.  This
    // is a Cloud-side continuation, not another per-size protocol message.
    QueryResult continue_bundled_fg_query(const Trapdoor& trapdoor,
                                          const IndexBuilder& index,
                                          size_t first_slice_index);

    std::vector<uint8_t> query_clos(const std::vector<std::vector<uint8_t>>& Si_addrs,
                                    const std::vector<std::vector<uint8_t>>& tau2,
                                    const Trapdoor& trapdoor,
                                    const IndexBuilder& index);

    // Official fourth-case candidate source: intersect complete data-graph
    // feature-presence bitmaps, then apply the graphlet filter if enabled.
    QueryResult complete_feature_fallback_query(
        const CompleteFeatureFallbackTrapdoor& trapdoor,
        const IndexBuilder& index,
        const Trapdoor& full_query_trapdoor);

};
