#pragma once

#include "GraphTypes.h"

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/vf2_sub_graph_iso.hpp>

namespace SubgraphUtils {

struct StopAfterFirstMatch {
    bool& found;

    template <typename Map1To2, typename Map2To1>
    bool operator()(const Map1To2&, const Map2To1&) const {
        found = true;
        return false;
    }
};

// Paper subgraph containment is non-induced: every labeled query edge must be
// preserved, while extra data-graph edges between mapped vertices are allowed.
inline bool isLabelPreservingSubgraph(const Graph& query, const Graph& data) {
    using namespace boost;
    if (num_vertices(query) > num_vertices(data)) return false;
    if (num_edges(query) > num_edges(data)) return false;
    if (num_vertices(query) == 0) return true;

    auto vertex_comp = [&](auto query_vertex, auto data_vertex) {
        return query[query_vertex].label == data[data_vertex].label;
    };
    auto edge_comp = [&](auto query_edge, auto data_edge) {
        return query[query_edge].label == data[data_edge].label;
    };

    try {
        bool found = false;
        vf2_subgraph_mono(
            query,
            data,
            StopAfterFirstMatch{found},
            vertex_order_by_mult(query),
            edges_equivalent(edge_comp).vertices_equivalent(vertex_comp));
        return found;
    } catch (...) {
        return false;
    }
}

}  // namespace SubgraphUtils
