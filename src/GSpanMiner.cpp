#include "GSpanMiner.h"

#include <boost/graph/graph_traits.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <numeric>
#include <queue>
#include <set>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

bool operator<(const DFSEdge& lhs, const DFSEdge& rhs) {
    const bool lhs_forward = lhs.from < lhs.to;
    const bool rhs_forward = rhs.from < rhs.to;
    if (lhs_forward != rhs_forward) return !lhs_forward;

    if (lhs_forward) {
        if (lhs.to != rhs.to) return lhs.to < rhs.to;
        if (lhs.from != rhs.from) return lhs.from > rhs.from;
    } else {
        if (lhs.from != rhs.from) return lhs.from < rhs.from;
        if (lhs.to != rhs.to) return lhs.to < rhs.to;
    }

    return std::tie(lhs.from_label, lhs.edge_label, lhs.to_label) <
           std::tie(rhs.from_label, rhs.edge_label, rhs.to_label);
}

bool operator==(const DFSEdge& lhs, const DFSEdge& rhs) {
    return lhs.from == rhs.from &&
           lhs.to == rhs.to &&
           lhs.from_label == rhs.from_label &&
           lhs.edge_label == rhs.edge_label &&
           lhs.to_label == rhs.to_label;
}

bool operator<(const DFSCode& lhs, const DFSCode& rhs) {
    return std::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

bool operator==(const DFSCode& lhs, const DFSCode& rhs) {
    return lhs.size() == rhs.size() &&
           std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

namespace {

struct DataEdge {
    int id = 0;
    int u = 0;
    int v = 0;
    std::string label;
};

struct GraphData {
    std::vector<std::string> vertex_labels;
    std::vector<DataEdge> edges;
    std::vector<std::vector<int>> adjacency;
};

struct PDFS {
    int graph_id = 0;
    int edge_id = -1;
    int prev = -1;
    int from_vid = -1;
    int to_vid = -1;
    int from_dfs = -1;
    int to_dfs = -1;
};

using ProjectedDB = std::vector<int>;

struct PDFSArena {
    std::vector<PDFS> entries;

    int add(const PDFS& pdfs) {
        entries.push_back(pdfs);
        return static_cast<int>(entries.size() - 1);
    }
};

struct HistoryWorkspace {
    std::vector<int> vertex_map;
    std::vector<int> edge_mark;
    std::vector<int> vertex_mark;
    int stamp = 1;

    void reset(size_t dfs_vertices, size_t graph_edges, size_t graph_vertices) {
        vertex_map.assign(dfs_vertices, -1);
        if (edge_mark.size() < graph_edges) edge_mark.resize(graph_edges, 0);
        if (vertex_mark.size() < graph_vertices) vertex_mark.resize(graph_vertices, 0);

        if (stamp == std::numeric_limits<int>::max()) {
            std::fill(edge_mark.begin(), edge_mark.end(), 0);
            std::fill(vertex_mark.begin(), vertex_mark.end(), 0);
            stamp = 1;
        } else {
            ++stamp;
        }
    }

    bool hasEdge(int edge_id) const {
        return edge_id >= 0 &&
               static_cast<size_t>(edge_id) < edge_mark.size() &&
               edge_mark[static_cast<size_t>(edge_id)] == stamp;
    }

    bool hasVertex(int vertex_id) const {
        return vertex_id >= 0 &&
               static_cast<size_t>(vertex_id) < vertex_mark.size() &&
               vertex_mark[static_cast<size_t>(vertex_id)] == stamp;
    }

    void markEdge(int edge_id) {
        if (edge_id >= 0 && static_cast<size_t>(edge_id) < edge_mark.size()) {
            edge_mark[static_cast<size_t>(edge_id)] = stamp;
        }
    }

    void markVertex(int vertex_id) {
        if (vertex_id >= 0 && static_cast<size_t>(vertex_id) < vertex_mark.size()) {
            vertex_mark[static_cast<size_t>(vertex_id)] = stamp;
        }
    }
};

GraphData buildGraphData(const Graph& g) {
    GraphData data;
    data.vertex_labels.resize(boost::num_vertices(g));
    data.adjacency.resize(boost::num_vertices(g));

    for (auto v = boost::vertices(g).first; v != boost::vertices(g).second; ++v) {
        const int idx = static_cast<int>(*v);
        if (idx >= 0 && static_cast<size_t>(idx) < data.vertex_labels.size()) {
            data.vertex_labels[static_cast<size_t>(idx)] = g[*v].label;
        }
    }

    int edge_id = 0;
    for (auto it = boost::edges(g).first; it != boost::edges(g).second; ++it) {
        const int u = static_cast<int>(boost::source(*it, g));
        const int v = static_cast<int>(boost::target(*it, g));
        DataEdge edge;
        edge.id = edge_id++;
        edge.u = u;
        edge.v = v;
        edge.label = g[*it].label;
        data.edges.push_back(edge);
        if (u >= 0 && v >= 0 &&
            static_cast<size_t>(u) < data.adjacency.size() &&
            static_cast<size_t>(v) < data.adjacency.size()) {
            data.adjacency[static_cast<size_t>(u)].push_back(edge.id);
            data.adjacency[static_cast<size_t>(v)].push_back(edge.id);
        }
    }
    return data;
}

int otherEndpoint(const DataEdge& edge, int vertex) {
    return edge.u == vertex ? edge.v : edge.u;
}

int vertexCount(const DFSCode& code) {
    int max_vertex = -1;
    for (const auto& edge : code) {
        max_vertex = std::max(max_vertex, edge.from);
        max_vertex = std::max(max_vertex, edge.to);
    }
    return max_vertex + 1;
}

std::vector<std::string> patternVertexLabels(const DFSCode& code) {
    std::vector<std::string> labels(static_cast<size_t>(vertexCount(code)));
    for (const auto& edge : code) {
        if (edge.from >= 0) labels[static_cast<size_t>(edge.from)] = edge.from_label;
        if (edge.to >= 0) labels[static_cast<size_t>(edge.to)] = edge.to_label;
    }
    return labels;
}

bool patternHasEdge(const DFSCode& code, int lhs, int rhs) {
    for (const auto& edge : code) {
        if ((edge.from == lhs && edge.to == rhs) ||
            (edge.from == rhs && edge.to == lhs)) {
            return true;
        }
    }
    return false;
}

void buildHistory(
    const DFSCode& code,
    const GraphData& graph,
    const PDFSArena& arena,
    int pdfs_index,
    HistoryWorkspace& history) {
    history.reset(
        static_cast<size_t>(vertexCount(code)),
        graph.edges.size(),
        graph.vertex_labels.size());
    std::vector<int> chain;
    for (int idx = pdfs_index; idx >= 0; idx = arena.entries[static_cast<size_t>(idx)].prev) {
        chain.push_back(idx);
    }
    std::reverse(chain.begin(), chain.end());

    for (int idx : chain) {
        const PDFS& pdfs = arena.entries[static_cast<size_t>(idx)];
        history.markEdge(pdfs.edge_id);
        history.markVertex(pdfs.from_vid);
        history.markVertex(pdfs.to_vid);
        if (pdfs.from_dfs >= 0 &&
            static_cast<size_t>(pdfs.from_dfs) < history.vertex_map.size()) {
            history.vertex_map[static_cast<size_t>(pdfs.from_dfs)] = pdfs.from_vid;
        }
        if (pdfs.to_dfs >= 0 &&
            static_cast<size_t>(pdfs.to_dfs) < history.vertex_map.size()) {
            history.vertex_map[static_cast<size_t>(pdfs.to_dfs)] = pdfs.to_vid;
        }
    }
}

std::vector<int> rightmostPath(const DFSCode& code) {
    const int n = vertexCount(code);
    if (n <= 0) return {};

    std::vector<int> parent(static_cast<size_t>(n), -1);
    int rightmost = 0;
    for (const auto& edge : code) {
        if (edge.from < edge.to) {
            parent[static_cast<size_t>(edge.to)] = edge.from;
            rightmost = std::max(rightmost, edge.to);
        } else {
            rightmost = std::max(rightmost, std::max(edge.from, edge.to));
        }
    }

    std::vector<int> path;
    for (int v = rightmost; v >= 0; v = parent[static_cast<size_t>(v)]) {
        path.push_back(v);
        if (parent[static_cast<size_t>(v)] < 0) break;
    }
    std::reverse(path.begin(), path.end());
    return path;
}

std::vector<int> uniqueGraphIdsOrdered(const ProjectedDB& projected, const PDFSArena& arena) {
    std::vector<int> graph_ids;
    int previous_graph = -1;
    for (int pdfs_index : projected) {
        const int graph_id = arena.entries[static_cast<size_t>(pdfs_index)].graph_id;
        if (graph_id != previous_graph) {
            graph_ids.push_back(graph_id);
            previous_graph = graph_id;
        }
    }
    return graph_ids;
}

DFSCode canonicalSingleEdgeCode(
    const std::string& lhs_label,
    const std::string& edge_label,
    const std::string& rhs_label) {
    DFSEdge forward{0, 1, lhs_label, edge_label, rhs_label};
    DFSEdge reverse{0, 1, rhs_label, edge_label, lhs_label};
    DFSCode a{forward};
    DFSCode b{reverse};
    return (b < a) ? b : a;
}

std::map<DFSCode, ProjectedDB> buildInitialProjectedDB(
    const std::vector<GraphData>& graphs,
    PDFSArena& arena) {
    std::map<DFSCode, ProjectedDB> initial;
    for (size_t graph_id = 0; graph_id < graphs.size(); ++graph_id) {
        const GraphData& graph = graphs[graph_id];
        for (const auto& edge : graph.edges) {
            const std::string& u_label = graph.vertex_labels[static_cast<size_t>(edge.u)];
            const std::string& v_label = graph.vertex_labels[static_cast<size_t>(edge.v)];
            const DFSCode code = canonicalSingleEdgeCode(u_label, edge.label, v_label);
            const DFSEdge& dfs_edge = code.front();

            if (dfs_edge.from_label == u_label && dfs_edge.to_label == v_label) {
                const int pdfs_index = arena.add({
                    static_cast<int>(graph_id),
                    edge.id,
                    -1,
                    edge.u,
                    edge.v,
                    0,
                    1
                });
                initial[code].push_back(pdfs_index);
            }
            if (dfs_edge.from_label == v_label && dfs_edge.to_label == u_label) {
                const int pdfs_index = arena.add({
                    static_cast<int>(graph_id),
                    edge.id,
                    -1,
                    edge.v,
                    edge.u,
                    0,
                    1
                });
                initial[code].push_back(pdfs_index);
            }
        }
    }
    return initial;
}

struct ExtensionRecord {
    int graph_id = 0;
    int edge_id = -1;
    int prev = -1;
    int from_vid = -1;
    int to_vid = -1;
    int from_dfs = -1;
    int to_dfs = -1;
};

struct ExtensionEmission {
    DFSEdge dfs_edge;
    ExtensionRecord record;
};

struct ChildAccumulator {
    int support = 0;
    int last_graph_id = -1;
    bool support_reached = false;
    ProjectedDB projected;
    std::vector<ExtensionRecord> deferred;
};

DFSCode makeChildCode(const DFSCode& parent, const DFSEdge& edge) {
    DFSCode child = parent;
    child.push_back(edge);
    return child;
}

int materializeRecord(
    PDFSArena& arena,
    const ExtensionRecord& record) {
    const int next_index = arena.add({
        record.graph_id,
        record.edge_id,
        record.prev,
        record.from_vid,
        record.to_vid,
        record.from_dfs,
        record.to_dfs
    });
    return next_index;
}

void sortUniqueProjected(ProjectedDB& db, const PDFSArena& arena) {
    auto pdfs_less = [&](int lhs_index, int rhs_index) {
        const PDFS& lhs = arena.entries[static_cast<size_t>(lhs_index)];
        const PDFS& rhs = arena.entries[static_cast<size_t>(rhs_index)];
        return std::tie(lhs.graph_id, lhs.edge_id, lhs.prev, lhs.from_vid, lhs.to_vid,
                        lhs.from_dfs, lhs.to_dfs) <
               std::tie(rhs.graph_id, rhs.edge_id, rhs.prev, rhs.from_vid, rhs.to_vid,
                        rhs.from_dfs, rhs.to_dfs);
    };
    auto pdfs_equal = [&](int lhs_index, int rhs_index) {
        const PDFS& lhs = arena.entries[static_cast<size_t>(lhs_index)];
        const PDFS& rhs = arena.entries[static_cast<size_t>(rhs_index)];
        return lhs.graph_id == rhs.graph_id &&
               lhs.edge_id == rhs.edge_id &&
               lhs.prev == rhs.prev &&
               lhs.from_vid == rhs.from_vid &&
               lhs.to_vid == rhs.to_vid &&
               lhs.from_dfs == rhs.from_dfs &&
               lhs.to_dfs == rhs.to_dfs;
    };
    std::sort(db.begin(), db.end(), pdfs_less);
    db.erase(std::unique(db.begin(), db.end(), pdfs_equal), db.end());
}


template <typename Emit>
void getBackward(
    const DFSCode& code,
    const std::vector<int>& rmp,
    const std::vector<std::string>& labels,
    const GraphData& graph,
    const HistoryWorkspace& history,
    int graph_id,
    int pdfs_index,
    Emit&& emit) {
    const int rightmost = rmp.back();
    const int rightmost_data = history.vertex_map[static_cast<size_t>(rightmost)];
    if (rightmost_data < 0) return;

    for (size_t i = 0; i + 1 < rmp.size(); ++i) {
        const int ancestor = rmp[i];
        if (patternHasEdge(code, rightmost, ancestor)) continue;
        const int ancestor_data = history.vertex_map[static_cast<size_t>(ancestor)];
        if (ancestor_data < 0) continue;

        for (int edge_id : graph.adjacency[static_cast<size_t>(rightmost_data)]) {
            if (history.hasEdge(edge_id)) continue;
            const DataEdge& edge = graph.edges[static_cast<size_t>(edge_id)];
            if (otherEndpoint(edge, rightmost_data) != ancestor_data) continue;

            emit(ExtensionEmission{
                {
                    rightmost,
                    ancestor,
                    labels[static_cast<size_t>(rightmost)],
                    edge.label,
                    labels[static_cast<size_t>(ancestor)]
                },
                {
                    graph_id,
                    edge_id,
                    pdfs_index,
                    rightmost_data,
                    ancestor_data,
                    rightmost,
                    ancestor
                }
            });
        }
    }
}

template <typename Emit>
void getForwardPure(
    const DFSCode& code,
    const std::vector<int>& rmp,
    const std::vector<std::string>& labels,
    const GraphData& graph,
    const HistoryWorkspace& history,
    int graph_id,
    int pdfs_index,
    int new_pattern_vertex,
    Emit&& emit) {
    (void)code;
    const int from = rmp.back();
    const int from_data = history.vertex_map[static_cast<size_t>(from)];
    if (from_data < 0) return;

    for (int edge_id : graph.adjacency[static_cast<size_t>(from_data)]) {
        if (history.hasEdge(edge_id)) continue;
        const DataEdge& edge = graph.edges[static_cast<size_t>(edge_id)];
        const int to_data = otherEndpoint(edge, from_data);
        if (history.hasVertex(to_data)) continue;

        emit(ExtensionEmission{
            {
                from,
                new_pattern_vertex,
                labels[static_cast<size_t>(from)],
                edge.label,
                graph.vertex_labels[static_cast<size_t>(to_data)]
            },
            {
                graph_id,
                edge_id,
                pdfs_index,
                from_data,
                to_data,
                from,
                new_pattern_vertex
            }
        });
    }
}

template <typename Emit>
void getForwardRmpath(
    const DFSCode& code,
    const std::vector<int>& rmp,
    const std::vector<std::string>& labels,
    const GraphData& graph,
    const HistoryWorkspace& history,
    int graph_id,
    int pdfs_index,
    int new_pattern_vertex,
    Emit&& emit) {
    (void)code;
    if (rmp.size() <= 1) return;

    for (auto it = std::next(rmp.rbegin()); it != rmp.rend(); ++it) {
        const int from = *it;
        const int from_data = history.vertex_map[static_cast<size_t>(from)];
        if (from_data < 0) continue;

        for (int edge_id : graph.adjacency[static_cast<size_t>(from_data)]) {
            if (history.hasEdge(edge_id)) continue;
            const DataEdge& edge = graph.edges[static_cast<size_t>(edge_id)];
            const int to_data = otherEndpoint(edge, from_data);
            if (history.hasVertex(to_data)) continue;

            emit(ExtensionEmission{
                {
                    from,
                    new_pattern_vertex,
                    labels[static_cast<size_t>(from)],
                    edge.label,
                    graph.vertex_labels[static_cast<size_t>(to_data)]
                },
                {
                    graph_id,
                    edge_id,
                    pdfs_index,
                    from_data,
                    to_data,
                    from,
                    new_pattern_vertex
                }
            });
        }
    }
}

std::map<DFSCode, ProjectedDB> enumerateRightmostExtensions(
    const DFSCode& code,
    const ProjectedDB& projected,
    const std::vector<GraphData>& graphs,
    PDFSArena& arena,
    int support_threshold) {
    const std::vector<int> rmp = rightmostPath(code);
    if (rmp.empty()) return {};

    const std::vector<std::string> labels = patternVertexLabels(code);
    const int new_pattern_vertex = vertexCount(code);
    HistoryWorkspace history;

    auto visit_extensions = [&](auto&& emit) {
        for (int pdfs_index : projected) {
            const PDFS& pdfs = arena.entries[static_cast<size_t>(pdfs_index)];
            const int embedding_graph_id = pdfs.graph_id;
            const GraphData& graph = graphs[static_cast<size_t>(embedding_graph_id)];
            buildHistory(code, graph, arena, pdfs_index, history);

            getBackward(
                code, rmp, labels, graph, history, embedding_graph_id, pdfs_index, emit);
            getForwardPure(
                code, rmp, labels, graph, history, embedding_graph_id, pdfs_index,
                new_pattern_vertex, emit);
            getForwardRmpath(
                code, rmp, labels, graph, history, embedding_graph_id, pdfs_index,
                new_pattern_vertex, emit);
        }
    };

    std::map<DFSEdge, ChildAccumulator> child_supports;
    visit_extensions([&](ExtensionEmission&& emission) {
        ChildAccumulator& acc = child_supports[emission.dfs_edge];
        if (acc.last_graph_id != emission.record.graph_id) {
            acc.last_graph_id = emission.record.graph_id;
            ++acc.support;
        }
        if (acc.support_reached) {
            acc.projected.push_back(materializeRecord(arena, emission.record));
        } else {
            acc.deferred.push_back(std::move(emission.record));
            if (acc.support >= support_threshold) {
                acc.support_reached = true;
                for (const ExtensionRecord& record : acc.deferred) {
                    acc.projected.push_back(materializeRecord(arena, record));
                }
                acc.deferred.clear();
            }
        }
    });

    std::map<DFSCode, ProjectedDB> children;
    for (auto& kv : child_supports) {
        ChildAccumulator& acc = kv.second;
        if (!acc.support_reached) continue;
        sortUniqueProjected(acc.projected, arena);
        children.emplace(makeChildCode(code, kv.first), std::move(acc.projected));
    }
    return children;
}

bool findMinimalNextExtension(
    const DFSCode& code,
    const ProjectedDB& projected,
    const std::vector<GraphData>& graphs,
    PDFSArena& arena,
    DFSCode& min_child,
    ProjectedDB& min_projected) {
    const std::vector<int> rmp = rightmostPath(code);
    if (rmp.empty()) return false;

    const std::vector<std::string> labels = patternVertexLabels(code);
    const int new_pattern_vertex = vertexCount(code);
    HistoryWorkspace history;

    auto visit_projected = [&](bool backward_only, auto&& emit) {
        for (int pdfs_index : projected) {
            const PDFS& pdfs = arena.entries[static_cast<size_t>(pdfs_index)];
            const int embedding_graph_id = pdfs.graph_id;
            const GraphData& graph = graphs[static_cast<size_t>(embedding_graph_id)];
            buildHistory(code, graph, arena, pdfs_index, history);

            if (backward_only) {
                getBackward(
                    code, rmp, labels, graph, history, embedding_graph_id, pdfs_index, emit);
            } else {
                getForwardPure(
                    code, rmp, labels, graph, history, embedding_graph_id, pdfs_index,
                    new_pattern_vertex, emit);
                getForwardRmpath(
                    code, rmp, labels, graph, history, embedding_graph_id, pdfs_index,
                    new_pattern_vertex, emit);
            }
        }
    };

    bool found = false;
    bool found_backward = false;
    DFSEdge min_edge;
    std::vector<ExtensionRecord> min_records;
    auto choose_min = [&](ExtensionEmission&& emission) {
        if (!found || emission.dfs_edge < min_edge) {
            min_edge = emission.dfs_edge;
            min_records.clear();
            found = true;
        }
        if (emission.dfs_edge == min_edge) {
            min_records.push_back(std::move(emission.record));
        }
    };

    visit_projected(true, choose_min);
    found_backward = found;
    if (!found_backward) {
        visit_projected(false, choose_min);
    }
    if (!found) return false;

    min_projected.clear();
    min_child = makeChildCode(code, min_edge);
    for (const ExtensionRecord& record : min_records) {
        min_projected.push_back(materializeRecord(arena, record));
    }

    sortUniqueProjected(min_projected, arena);
    return true;
}

struct MineContext {
    const std::vector<GraphData>& graphs;
    PDFSArena& arena;
    int support_threshold = 1;
    int max_edges = -1;
    size_t dataset_size = 0;
    std::map<std::string, FrequentGraph> frequent_by_code;
    std::unordered_set<std::string> explored_min_codes;
};

void projectPattern(const DFSCode& code, const ProjectedDB& projected, MineContext& ctx) {
    const std::vector<int> graph_ids = uniqueGraphIdsOrdered(projected, ctx.arena);
    if (static_cast<int>(graph_ids.size()) < ctx.support_threshold) {
        return;
    }

    const Graph pattern = GSpanMiner::graphFromDFSCode(code);
    if (!GSpanMiner::isMinDFSCode(code, pattern)) {
        return;
    }

    const std::string code_string = GSpanMiner::dfsCodeToString(code);
    if (!ctx.explored_min_codes.insert(code_string).second) {
        return;
    }

    FrequentGraph fg;
    fg.g = pattern;
    fg.frequency = static_cast<int>(graph_ids.size());
    fg.canonical_label = code_string;
    fg.bit_vector.assign((ctx.dataset_size + 7) / 8, 0);
    for (int graph_id : graph_ids) {
        if (graph_id >= 0 && static_cast<size_t>(graph_id) < ctx.dataset_size) {
            fg.bit_vector[static_cast<size_t>(graph_id) / 8] |=
                static_cast<uint8_t>(1u << (static_cast<size_t>(graph_id) % 8));
        }
    }
    ctx.frequent_by_code.emplace(code_string, std::move(fg));

    if (ctx.max_edges > 0 && static_cast<int>(code.size()) >= ctx.max_edges) return;
    const size_t arena_snapshot = ctx.arena.entries.size();
    const auto children =
        enumerateRightmostExtensions(
            code, projected, ctx.graphs, ctx.arena, ctx.support_threshold);
    for (const auto& kv : children) {
        projectPattern(kv.first, kv.second, ctx);
    }
    ctx.arena.entries.resize(arena_snapshot);
    if (ctx.arena.entries.capacity() > arena_snapshot + 1000000 &&
        ctx.arena.entries.capacity() > arena_snapshot * 2 + 1) {
        ctx.arena.entries.shrink_to_fit();
    }
}

bool graphIsConnectedWithEdges(const Graph& g) {
    if (boost::num_edges(g) == 0 || boost::num_vertices(g) == 0) return false;
    std::vector<bool> visited(boost::num_vertices(g), false);
    std::queue<int> pending;
    visited[0] = true;
    pending.push(0);
    while (!pending.empty()) {
        const int u = pending.front();
        pending.pop();
        for (auto it = boost::adjacent_vertices(u, g).first;
             it != boost::adjacent_vertices(u, g).second; ++it) {
            const int v = static_cast<int>(*it);
            if (!visited[static_cast<size_t>(v)]) {
                visited[static_cast<size_t>(v)] = true;
                pending.push(v);
            }
        }
    }
    return std::all_of(visited.begin(), visited.end(), [](bool value) { return value; });
}


DFSCode buildMinDFSCodeStandard(const Graph& pattern) {
    if (!graphIsConnectedWithEdges(pattern)) return {};

    std::vector<GraphData> graphs;
    graphs.push_back(buildGraphData(pattern));
    PDFSArena arena;
    const auto initial = buildInitialProjectedDB(graphs, arena);
    if (initial.empty()) return {};

    DFSCode min_code = initial.begin()->first;
    ProjectedDB projected = initial.begin()->second;
    const size_t target_edge_count = boost::num_edges(pattern);

    while (min_code.size() < target_edge_count) {
        DFSCode next_min;
        ProjectedDB next_projected;
        if (!findMinimalNextExtension(
                min_code, projected, graphs, arena, next_min, next_projected)) {
            break;
        }
        min_code = std::move(next_min);
        projected = std::move(next_projected);
    }
    return min_code;
}

bool isMinDFSCodeStandard(const DFSCode& code) {
    if (code.empty()) return true;

    const Graph pattern = GSpanMiner::graphFromDFSCode(code);
    std::vector<GraphData> graphs;
    graphs.push_back(buildGraphData(pattern));
    PDFSArena arena;
    const auto initial = buildInitialProjectedDB(graphs, arena);
    if (initial.empty()) return false;

    DFSCode min_prefix = initial.begin()->first;
    ProjectedDB projected = initial.begin()->second;
    if (!(code.front() == min_prefix.front())) {
        return false;
    }

    while (min_prefix.size() < code.size()) {
        DFSCode next_min;
        ProjectedDB next_projected;
        if (!findMinimalNextExtension(
                min_prefix, projected, graphs, arena, next_min, next_projected)) {
            return false;
        }
        const size_t next_pos = min_prefix.size();
        if (!(code[next_pos] == next_min[next_pos])) {
            return false;
        }
        min_prefix = std::move(next_min);
        projected = std::move(next_projected);
    }
    return true;
}

std::vector<FrequentGraph> mineImpl(
    const std::vector<Graph>& dataset,
    int support_threshold,
    int max_edges) {

    std::vector<GraphData> graphs;
    graphs.reserve(dataset.size());
    for (const Graph& graph : dataset) {
        graphs.push_back(buildGraphData(graph));
    }

    PDFSArena arena;
    const auto initial = buildInitialProjectedDB(graphs, arena);

    MineContext ctx{
        graphs,
        arena,
        support_threshold,
        max_edges,
        dataset.size(),
        {},
        {}
    };

    for (const auto& kv : initial) {
        projectPattern(kv.first, kv.second, ctx);
    }

    std::vector<FrequentGraph> result;
    result.reserve(ctx.frequent_by_code.size());
    for (auto& kv : ctx.frequent_by_code) {
        result.push_back(std::move(kv.second));
    }

    std::sort(result.begin(), result.end(), graph_set_order_less);
    for (size_t i = 0; i < result.size(); ++i) {
        result[i].order_id = static_cast<int>(i + 1);
    }

    return result;
}

}  // namespace

DFSCode GSpanMiner::buildMinDFSCode(const Graph& pattern) {
    return buildMinDFSCodeStandard(pattern);
}

bool GSpanMiner::isMinDFSCode(const DFSCode& code, const Graph& pattern) {
    (void)pattern;
    return isMinDFSCodeStandard(code);
}

std::string GSpanMiner::dfsCodeToString(const DFSCode& code) {
    std::ostringstream oss;
    for (size_t i = 0; i < code.size(); ++i) {
        const DFSEdge& edge = code[i];
        if (i != 0) oss << ";";
        oss << "(" << edge.from << "," << edge.to << ","
            << edge.from_label << "," << edge.edge_label << ","
            << edge.to_label << ")";
    }
    return oss.str();
}

Graph GSpanMiner::graphFromDFSCode(const DFSCode& code) {
    Graph graph;
    const int n = vertexCount(code);
    std::vector<bool> initialized(static_cast<size_t>(n), false);
    for (int i = 0; i < n; ++i) {
        boost::add_vertex(graph);
    }
    for (const auto& edge : code) {
        if (!initialized[static_cast<size_t>(edge.from)]) {
            graph[static_cast<size_t>(edge.from)].label = edge.from_label;
            initialized[static_cast<size_t>(edge.from)] = true;
        }
        if (!initialized[static_cast<size_t>(edge.to)]) {
            graph[static_cast<size_t>(edge.to)].label = edge.to_label;
            initialized[static_cast<size_t>(edge.to)] = true;
        }
        const auto added = boost::add_edge(
            static_cast<size_t>(edge.from),
            static_cast<size_t>(edge.to),
            graph).first;
        graph[added].label = edge.edge_label;
    }
    return graph;
}

std::vector<FrequentGraph> GSpanMiner::mine(
    const std::vector<Graph>& dataset,
    int support_threshold,
    int max_edges) {
    return mineImpl(dataset, support_threshold, max_edges);
}
