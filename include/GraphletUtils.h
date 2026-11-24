#pragma once

#include "GraphTypes.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace GraphletUtils {

inline long long choose2(long long n) {
    return n >= 2 ? n * (n - 1) / 2 : 0;
}

inline long long choose3(long long n) {
    return n >= 3 ? n * (n - 1) * (n - 2) / 6 : 0;
}

inline int popcount64(uint64_t value) {
#if defined(__GNUG__) || defined(__clang__)
    return __builtin_popcountll(value);
#else
    int count = 0;
    while (value != 0) {
        value &= value - 1;
        ++count;
    }
    return count;
#endif
}

struct PreparedSimpleGraph {
    size_t n = 0;
    std::vector<std::pair<int, int>> edges;
    std::vector<int> degree;
    std::vector<std::vector<uint64_t>> adj_bits;
};

inline PreparedSimpleGraph prepareSimpleTopologyGraph(const Graph& g) {
    PreparedSimpleGraph prepared;

    std::vector<size_t> vertices;
    vertices.reserve(boost::num_vertices(g));
    for (auto it = boost::vertices(g).first; it != boost::vertices(g).second; ++it) {
        vertices.push_back(static_cast<size_t>(*it));
    }
    prepared.n = vertices.size();
    if (prepared.n == 0) return prepared;

    std::unordered_map<size_t, int> vertex_to_idx;
    vertex_to_idx.reserve(vertices.size());
    for (size_t i = 0; i < vertices.size(); ++i) {
        vertex_to_idx.emplace(vertices[i], static_cast<int>(i));
    }

    std::unordered_set<uint64_t> unique_edges;
    unique_edges.reserve(boost::num_edges(g) * 2 + 1);
    for (auto it = boost::edges(g).first; it != boost::edges(g).second; ++it) {
        const size_t raw_u = static_cast<size_t>(boost::source(*it, g));
        const size_t raw_v = static_cast<size_t>(boost::target(*it, g));
        if (raw_u == raw_v) continue;
        const auto it_u = vertex_to_idx.find(raw_u);
        const auto it_v = vertex_to_idx.find(raw_v);
        if (it_u == vertex_to_idx.end() || it_v == vertex_to_idx.end()) continue;

        int u = it_u->second;
        int v = it_v->second;
        if (u > v) std::swap(u, v);
        const uint64_t key =
            static_cast<uint64_t>(u) * static_cast<uint64_t>(prepared.n) +
            static_cast<uint64_t>(v);
        if (unique_edges.insert(key).second) {
            prepared.edges.emplace_back(u, v);
        }
    }

    prepared.degree.assign(prepared.n, 0);
    const size_t blocks = (prepared.n + 63) / 64;
    prepared.adj_bits.assign(prepared.n, std::vector<uint64_t>(blocks, 0));
    for (const auto& edge : prepared.edges) {
        const int u = edge.first;
        const int v = edge.second;
        ++prepared.degree[static_cast<size_t>(u)];
        ++prepared.degree[static_cast<size_t>(v)];
        prepared.adj_bits[static_cast<size_t>(u)][static_cast<size_t>(v) / 64] |=
            uint64_t{1} << (static_cast<size_t>(v) % 64);
        prepared.adj_bits[static_cast<size_t>(v)][static_cast<size_t>(u) / 64] |=
            uint64_t{1} << (static_cast<size_t>(u) % 64);
    }
    return prepared;
}

inline bool isEdge(const PreparedSimpleGraph& g, int u, int v) {
    if (u < 0 || v < 0 ||
        static_cast<size_t>(u) >= g.n ||
        static_cast<size_t>(v) >= g.n) {
        return false;
    }
    return (g.adj_bits[static_cast<size_t>(u)][static_cast<size_t>(v) / 64] &
            (uint64_t{1} << (static_cast<size_t>(v) % 64))) != 0;
}

inline int commonNeighborCount(const PreparedSimpleGraph& g, int u, int v) {
    int count = 0;
    const auto& bits_u = g.adj_bits[static_cast<size_t>(u)];
    const auto& bits_v = g.adj_bits[static_cast<size_t>(v)];
    for (size_t block = 0; block < bits_u.size(); ++block) {
        count += popcount64(bits_u[block] & bits_v[block]);
    }
    return count;
}

inline std::vector<int> commonNeighborList(const PreparedSimpleGraph& g, int u, int v) {
    std::vector<int> common;
    const auto& bits_u = g.adj_bits[static_cast<size_t>(u)];
    const auto& bits_v = g.adj_bits[static_cast<size_t>(v)];
    for (size_t block = 0; block < bits_u.size(); ++block) {
        uint64_t bits = bits_u[block] & bits_v[block];
        while (bits != 0) {
            const int offset =
#if defined(__GNUG__) || defined(__clang__)
                __builtin_ctzll(bits);
#else
                [&]() {
                    int local_offset = 0;
                    uint64_t tmp = bits;
                    while ((tmp & uint64_t{1}) == 0) {
                        tmp >>= 1;
                        ++local_offset;
                    }
                    return local_offset;
                }();
#endif
            const size_t vertex = block * 64 + static_cast<size_t>(offset);
            if (vertex < g.n) common.push_back(static_cast<int>(vertex));
            bits &= bits - 1;
        }
    }
    return common;
}

inline std::unordered_map<int, int> countsToPublicMap(const std::vector<long long>& raw) {
    std::unordered_map<int, int> counts;
    for (int type = 1; type <= 8; ++type) {
        const long long value = raw[static_cast<size_t>(type)];
        if (value > static_cast<long long>(std::numeric_limits<int>::max())) {
            throw std::overflow_error("Graphlet count exceeds int range");
        }
        counts[type] = static_cast<int>(value);
    }
    return counts;
}

// Counts non-induced, inclusion-expanded graphlet topology patterns.
// A denser topology contributes to every weaker topology pattern it contains.
// Example: a triangle contributes one triangle pattern and three 2-star/path patterns.
// This monotone definition is required by the Graphlet filter:
// if q is subgraph-isomorphic to G, then for every type t,
// count(q,t) <= count(G,t).
//
// Types: 1=P3/2-star, 2=triangle, 3=K1,3/3-star, 4=P4,
// 5=triangle-tail, 6=C4, 7=diamond (K4 minus one edge), 8=K4.
inline std::unordered_map<int, int> extractGraphletCounts(const Graph& g) {
    // PGD/ESCAPE-inspired exact combinatorial counter for 3/4-node ordinary
    // graphlet topology counts. This is not a full PGD or ESCAPE system.
    const PreparedSimpleGraph pg = prepareSimpleTopologyGraph(g);
    std::vector<long long> counts(9, 0);

    if (pg.n < 3) return countsToPublicMap(counts);

    for (int degree : pg.degree) {
        counts[1] += choose2(degree);
        counts[3] += choose3(degree);
    }

    long long triangle_count = 0;
    long long k4_edge_sum = 0;
    for (const auto& edge : pg.edges) {
        const int u = edge.first;
        const int v = edge.second;
        const int common_count = commonNeighborCount(pg, u, v);
        counts[4] +=
            static_cast<long long>(pg.degree[static_cast<size_t>(u)] - 1) *
            static_cast<long long>(pg.degree[static_cast<size_t>(v)] - 1) -
            common_count;
        counts[7] += choose2(common_count);

        const std::vector<int> common = commonNeighborList(pg, u, v);
        for (int w : common) {
            if (v < w) {
                ++triangle_count;
                counts[5] +=
                    static_cast<long long>(pg.degree[static_cast<size_t>(u)]) +
                    static_cast<long long>(pg.degree[static_cast<size_t>(v)]) +
                    static_cast<long long>(pg.degree[static_cast<size_t>(w)]) - 6;
            }
        }
        for (size_t i = 0; i < common.size(); ++i) {
            for (size_t j = i + 1; j < common.size(); ++j) {
                if (isEdge(pg, common[i], common[j])) {
                    ++k4_edge_sum;
                }
            }
        }
    }
    counts[2] = triangle_count;

    long long c4_pair_sum = 0;
    for (size_t u = 0; u < pg.n; ++u) {
        for (size_t v = u + 1; v < pg.n; ++v) {
            c4_pair_sum += choose2(commonNeighborCount(pg, static_cast<int>(u), static_cast<int>(v)));
        }
    }
    counts[6] = c4_pair_sum / 2;
    counts[8] = k4_edge_sum / 6;

    return countsToPublicMap(counts);
}


}  // namespace GraphletUtils
