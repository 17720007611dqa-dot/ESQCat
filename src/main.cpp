#include "CloudServer.h"
#include "CryptoUtils.h"
#include "DataLoader.h"
#include "GraphletMaskUtils.h"
#include "GraphletUtils.h"
#include "GSpanMiner.h"
#include "IndexBuilder.h"
#include "SubgraphUtils.h"

#include <openssl/rand.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

struct Options {
    std::string dataset_path;
    std::string query_path;
    double sigma = 0.1;
    double delta = 0.1;
    bool hide_graphlet_type_access = false;
};

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " --dataset <data.tve> --query <queries.tve>\n"
              << "       [--sigma <positive support ratio>] [--delta <nonnegative tolerance>]\n"
              << "       [--hide-graphlet-type-access]\n";
}

Options parse_args(int argc, char* argv[]) {
    Options options;
    auto require_value = [&](int& i, const std::string& option) -> std::string {
        if (i + 1 >= argc) throw std::invalid_argument("Missing value for " + option);
        return argv[++i];
    };

    for (int i = 1; i < argc; ++i) {
        const std::string option = argv[i];
        if (option == "--dataset") {
            options.dataset_path = require_value(i, option);
        } else if (option == "--query") {
            options.query_path = require_value(i, option);
        } else if (option == "--sigma") {
            options.sigma = std::stod(require_value(i, option));
        } else if (option == "--delta") {
            options.delta = std::stod(require_value(i, option));
        } else if (option == "--hide-graphlet-type-access") {
            options.hide_graphlet_type_access = true;
        } else {
            throw std::invalid_argument("Unknown option: " + option);
        }
    }

    if (options.dataset_path.empty() || options.query_path.empty()) {
        throw std::invalid_argument("--dataset and --query are required");
    }
    if (!std::isfinite(options.sigma) || options.sigma <= 0.0) {
        throw std::invalid_argument("--sigma must be positive and finite");
    }
    if (!std::isfinite(options.delta) || options.delta < 0.0) {
        throw std::invalid_argument("--delta must be non-negative and finite");
    }
    return options;
}

static int support_threshold_from_sigma(size_t graph_count, double sigma) {
    const double scaled = sigma * 100.0;
    const long long numerator = std::llround(scaled);
    if (numerator > 0 && std::abs(scaled - static_cast<double>(numerator)) < 1e-9) {
        const uint64_t n = static_cast<uint64_t>(graph_count);
        const uint64_t threshold = (n * static_cast<uint64_t>(numerator) + 100ULL - 1ULL) / 100ULL;
        return std::max(1, static_cast<int>(threshold));
    }
    return std::max(1, static_cast<int>(std::ceil(static_cast<double>(graph_count) * sigma)));
}

static std::vector<uint8_t> random_bytes(size_t len) {
    std::vector<uint8_t> b(len);
    if (1 != RAND_bytes(b.data(), static_cast<int>(len))) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return b;
}

static void load_or_generate_keys(const std::string& path, std::vector<std::vector<uint8_t>>& keys) {
    if (keys.size() != 14) throw std::logic_error("main requires 14 independent index keys");
    std::ifstream in(path, std::ios::binary);
    if (in) {
        for (auto& k : keys) {
            k.resize(32);
            in.read(reinterpret_cast<char*>(k.data()), 32);
            if (in.gcount() != 32) {
                throw std::runtime_error("Key file is not a 14-key v2 file: " + path);
            }
        }
        if (in.peek() != EOF) throw std::runtime_error("Key file has unexpected trailing data: " + path);
    } else {
        std::ofstream out(path, std::ios::binary);
        if (!out) throw std::runtime_error("Cannot create key file: " + path);
        for (auto& k : keys) {
            k = random_bytes(32);
            out.write(reinterpret_cast<const char*>(k.data()), 32);
        }
    }
}

static std::vector<uint8_t> u64_to_be(uint64_t v) {
    std::vector<uint8_t> b(8);
    for (int i = 7; i >= 0; --i) {
        b[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
    return b;
}

static std::vector<uint64_t> ids_from_bitvector(const std::vector<uint8_t>& bits) {
    std::vector<uint64_t> ids;
    for (size_t byte_idx = 0; byte_idx < bits.size(); ++byte_idx) {
        const uint8_t b = bits[byte_idx];
        if (b == 0) continue;
        for (int bit = 0; bit < 8; ++bit) {
            if (b & static_cast<uint8_t>(1u << bit)) {
                ids.push_back(static_cast<uint64_t>(byte_idx * 8 + static_cast<size_t>(bit)));
            }
        }
    }
    return ids;
}

static std::vector<uint64_t> sorted_unique_ids(std::vector<uint64_t> ids) {
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

static std::string paper_dfs_code_string_main(const Graph& g) {
    return GSpanMiner::dfsCodeToString(GSpanMiner::buildMinDFSCode(g));
}

static int fti_msize_t(const IndexBuilder& builder) {
    int msize_t = 0;
    for (const auto& kv : builder.trip_table) {
        for (const auto& size_slice : kv.second.size_slices) {
            msize_t = std::max(msize_t, size_slice.first);
        }
    }
    return msize_t;
}

static std::string paper_dfs_code_string(const Graph& g) {
    return paper_dfs_code_string_main(g);
}

static void append_graphlet_trapdoor(
    Trapdoor& trapdoor,
    const Graph& query_graph,
    const IndexBuilder& builder,
    bool hide_graphlet_type_access) {
    trapdoor.T_Graphlet.clear();
    trapdoor.graphlet_impossible = false;

    // Default mode skips q_count == 0 because data_count >= 0 is always true.
    // The optional all-tree mode hides which graphlet types are activated.
    const auto g_counts = GraphletUtils::extractGraphletCounts(query_graph);
    for (int type = 1; type <= 8; ++type) {
        const int q_count = g_counts.at(type);
        if (!hide_graphlet_type_access && q_count == 0) continue;

        const auto tag_it = builder.graphlet_tree_tags_by_type.find(type);
        const auto counts_it = builder.graphlet_leaf_counts_by_type.find(type);
        if (tag_it == builder.graphlet_tree_tags_by_type.end() ||
            counts_it == builder.graphlet_leaf_counts_by_type.end()) {
            trapdoor.graphlet_impossible = true;
            trapdoor.T_Graphlet.clear();
            return;
        }

        const std::vector<int>& actual_counts = counts_it->second;
        const auto lb = std::lower_bound(actual_counts.begin(), actual_counts.end(), q_count);
        if (lb == actual_counts.end()) {
            trapdoor.graphlet_impossible = true;
            trapdoor.T_Graphlet.clear();
            return;
        }

        const int selected_threshold = *lb;
        const uint64_t obfuscated =
            builder.alpha_G * static_cast<uint64_t>(selected_threshold) + builder.beta_G;
        const std::vector<uint8_t> graphlet_ore_key =
            CryptoEngine::GraphletOreKey(builder.k6_graphlet, type);
        std::vector<uint8_t> ore_ciphertext =
            CryptoEngine::ORE_Encrypt(graphlet_ore_key, obfuscated);
        std::vector<uint8_t> mask_stream =
            GraphletMaskUtils::deriveSuffixMaskStream(
                builder.k8_graphlet, type, static_cast<uint64_t>(selected_threshold), builder.dataset_size_bytes);
        trapdoor.T_Graphlet.push_back({
            tag_it->second,
            std::move(ore_ciphertext),
            std::move(mask_stream)
        });
    }
}

static Trapdoor make_ifg_trapdoor(
    const Graph& query_graph,
    int query_edges,
    const IndexBuilder& builder) {
    Trapdoor trapdoor;
    trapdoor.query_size = query_edges;
    trapdoor.is_IFG_trapdoor = true;
    const auto q_edge_counts = builder.extractEdgeTriplets(query_graph);
    for (const auto& p : q_edge_counts) {
        const std::vector<uint8_t> row_key = CryptoEngine::FeatureRowId(builder.k3, p.first);
        if (builder.trip_table.find(row_key) == builder.trip_table.end()) {
            trapdoor.T_Edge.emplace_back(row_key, std::vector<uint8_t>{},
                                        CryptoEngine::IftiMask(builder.k8, row_key, builder.dataset_size_bytes));
        }
    }
    return trapdoor;
}

static Trapdoor make_bundled_fg_initial_trapdoor(
    const Graph& query_graph,
    const IndexBuilder& builder) {
    Trapdoor trapdoor;
    trapdoor.query_size = static_cast<int>(boost::num_edges(query_graph));
    trapdoor.is_IFG_trapdoor = false;

    const std::string query_dfs = paper_dfs_code_string(query_graph);
    const std::vector<uint8_t> dfs_bytes(query_dfs.begin(), query_dfs.end());
    trapdoor.T_Exact.H_dfs = CryptoEngine::DfsHash(dfs_bytes);
    trapdoor.T_Exact.K_xor = CryptoEngine::DfsEdMask(
        builder.k4, dfs_bytes, builder.dataset_size_bytes);

    const auto features = builder.extractEdgeTriplets(query_graph);
    const int max_size = fti_msize_t(builder);
    for (int size = trapdoor.query_size; size <= max_size; ++size) {
        FgSizeSliceTrapdoor slice;
        slice.graph_size = size;
        slice.feature_tokens.reserve(features.size());
        for (const auto& feature : features) {
            const std::vector<uint8_t> row_key =
                CryptoEngine::FeatureRowId(builder.k3, feature.first);
            if (builder.trip_table.find(row_key) == builder.trip_table.end()) {
                throw std::runtime_error("FG query has no FTI row for feature");
            }
            std::vector<uint8_t> feature_and_size(feature.first.begin(), feature.first.end());
            const std::vector<uint8_t> size_bytes = u64_to_be(static_cast<uint64_t>(size));
            feature_and_size.insert(
                feature_and_size.end(), size_bytes.begin(), size_bytes.end());
            const uint64_t obfuscated =
                builder.alpha_T * static_cast<uint64_t>(feature.second) + builder.beta_T;
            slice.feature_tokens.emplace_back(
                row_key,
                CryptoEngine::ORE_Encrypt(
                    CryptoEngine::TripletOreKey(builder.k6, feature.first, static_cast<size_t>(size)),
                    obfuscated),
                CryptoEngine::PRF(builder.k7, feature_and_size));
        }
        trapdoor.fg_size_slices.push_back(std::move(slice));
    }
    // FG initial τ_T deliberately carries neither τ_CF nor τ_G.
    return trapdoor;
}

static CompleteFeatureFallbackTrapdoor make_complete_feature_fallback_trapdoor(
    const Graph& query_graph,
    const IndexBuilder& builder) {
    CompleteFeatureFallbackTrapdoor trapdoor;
    const auto feature_counts = builder.extractEdgeTriplets(query_graph);
    std::vector<std::string> distinct_features;
    distinct_features.reserve(feature_counts.size());
    for (const auto& feature_count : feature_counts) {
        distinct_features.push_back(feature_count.first);
    }
    std::sort(distinct_features.begin(), distinct_features.end());

    trapdoor.entries.reserve(distinct_features.size());
    for (const auto& feature : distinct_features) {
        trapdoor.entries.push_back({
            CryptoEngine::CfbiRowId(builder.k3_cfbi, feature),
            CryptoEngine::CfbiMask(
                builder.k8_cfbi, CryptoEngine::CfbiRowId(builder.k3_cfbi, feature), builder.dataset_size_bytes)
        });
    }
    return trapdoor;
}

static std::vector<std::vector<uint8_t>> make_closure_authorization(
    const std::vector<std::vector<uint8_t>>& addresses, const IndexBuilder& builder) {
    std::vector<std::vector<uint8_t>> factors;
    factors.reserve(addresses.size());
    for (const auto& address : addresses) {
        factors.push_back(CryptoEngine::ClosureHeadFactor(builder.k5, address));
    }
    return factors;
}

static QueryResult execute_encrypted_query(
    const Graph& query_graph,
    const IndexBuilder& builder,
    bool hide_graphlet_type_access) {
    CloudServer cloud;
    const int query_edges = static_cast<int>(boost::num_edges(query_graph));
    const bool is_ifg = [&]() {
        for (const auto& feature : builder.extractEdgeTriplets(query_graph)) {
            if (builder.trip_table.find(
                    CryptoEngine::FeatureRowId(builder.k3, feature.first)) ==
                builder.trip_table.end()) return true;
        }
        return false;
    }();

    Trapdoor initial_trapdoor = is_ifg
        ? make_ifg_trapdoor(query_graph, query_edges, builder)
        : make_bundled_fg_initial_trapdoor(query_graph, builder);
    if (initial_trapdoor.is_IFG_trapdoor) {
        append_graphlet_trapdoor(initial_trapdoor, query_graph, builder, hide_graphlet_type_access);
        return cloud.query(initial_trapdoor, builder);
    }

    QueryResult qres = cloud.query(initial_trapdoor, builder);
    while (true) {
        if (!qres.matched_ids.empty() && !qres.aggregated_bitvector.empty()) return qres;
        if (!qres.closure_authorization_required) break;
        const auto factors = make_closure_authorization(qres.unresolved_addrs, builder);
        const auto matched_bits = cloud.query_clos(qres.unresolved_addrs, factors, initial_trapdoor, builder);
        if (!matched_bits.empty()) {
            qres.aggregated_bitvector = matched_bits;
            qres.matched_ids = ids_from_bitvector(matched_bits);
            return qres;
        }
        qres = cloud.continue_bundled_fg_query(initial_trapdoor, builder, qres.next_fg_slice_index);
    }

    const CompleteFeatureFallbackTrapdoor cfbi_trapdoor =
        make_complete_feature_fallback_trapdoor(query_graph, builder);
    Trapdoor fallback_graphlet_trapdoor;
    fallback_graphlet_trapdoor.query_size = query_edges;
    append_graphlet_trapdoor(fallback_graphlet_trapdoor, query_graph, builder, hide_graphlet_type_access);
    return cloud.complete_feature_fallback_query(cfbi_trapdoor, builder, fallback_graphlet_trapdoor);
}

void print_ids(const std::vector<uint64_t>& ids) {
    if (ids.empty()) std::cout << '-';
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i != 0) std::cout << ',';
        std::cout << ids[i];
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        print_usage(argv[0]);
        return 0;
    }

    try {
        const Options options = parse_args(argc, argv);
        const auto dataset = DataLoader::loadGraphs(options.dataset_path);
        if (dataset.empty()) throw std::runtime_error("Dataset is empty");
        const auto queries = DataLoader::loadGraphs(options.query_path);
        if (queries.empty()) throw std::runtime_error("Query file is empty");

        std::vector<std::vector<uint8_t>> keys(14);
        load_or_generate_keys("keys_v2.bin", keys);
        const int support = support_threshold_from_sigma(dataset.size(), options.sigma);
        auto features = GSpanMiner::mine(dataset, support, -1);
        IndexBuilder builder;
        // Keep the original v2 key-file slots and the active key assignments.
        builder.init_keys(keys[0], keys[2], keys[3], keys[4], keys[5], keys[6], keys[7],
                          1, 0, options.delta, keys[9], keys[10], keys[11], keys[12], keys[13]);
        builder.buildIndex(dataset, features);

        std::cout << "query_id\tcandidate_ids\tmatch_ids\n";
        for (size_t i = 0; i < queries.size(); ++i) {
            const auto& query_graph = queries[i];
            auto result = execute_encrypted_query(query_graph, builder, options.hide_graphlet_type_access);
            const auto candidates = sorted_unique_ids(std::move(result.matched_ids));
            std::vector<uint64_t> matches;
            for (uint64_t id : candidates) {
                if (id < dataset.size() &&
                    SubgraphUtils::isLabelPreservingSubgraph(query_graph, dataset[static_cast<size_t>(id)])) {
                    matches.push_back(id);
                }
            }
            std::cout << i << '\t';
            print_ids(candidates);
            std::cout << '\t';
            print_ids(matches);
            std::cout << '\n';
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << '\n';
        return 1;
    }
}
