#include "DataLoader.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <set>
#include <algorithm>

static std::string parse_edge_label(std::istringstream& iss) {
    std::string label;
    std::getline(iss, label);

    const auto first = label.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "unknown";
    const auto last = label.find_last_not_of(" \t\r\n");
    label = label.substr(first, last - first + 1);

    if (label.find(',') != std::string::npos) return label;

    std::istringstream label_stream(label);
    std::string token;
    std::string normalized;
    while (label_stream >> token) {
        if (!normalized.empty()) normalized += ",";
        normalized += token;
    }
    return normalized.empty() ? "unknown" : normalized;
}

std::vector<Graph> DataLoader::loadGraphs(const std::string& filepath) {
    std::vector<Graph> graphs;
    std::ifstream in(filepath);
    if (!in) {
        throw std::runtime_error("Failed to open graph file: " + filepath);
    }

    std::string line;
    Graph current;
    std::unordered_map<int, boost::graph_traits<Graph>::vertex_descriptor> idmap;
    std::set<std::pair<int, int>> added_edges;
    bool in_graph = false;

    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string tag;
        iss >> tag;
        if (!iss) continue;

        if (tag == "t") {
            std::string marker;
            int graph_id = 0;
            if ((iss >> marker >> graph_id) && marker == "#" && graph_id == -1) {
                if (in_graph && boost::num_vertices(current) > 0) {
                    graphs.push_back(std::move(current));
                }
                in_graph = false;
                break;
            }
            // new graph
            if (in_graph) {
                graphs.push_back(std::move(current));
                current = Graph();
                idmap.clear();
                added_edges.clear();
            }
            in_graph = true;
        } else if (tag == "v") {
            int vid; std::string label;
            iss >> vid >> label;
            auto vd = boost::add_vertex(current);
            current[vd].label = label;
            idmap[vid] = vd;
        } else if (tag == "e") {
            int u, v;
            iss >> u >> v;
            if (!iss) continue;
            std::string label = parse_edge_label(iss);
            auto it_u = idmap.find(u);
            auto it_v = idmap.find(v);
            if (it_u == idmap.end() || it_v == idmap.end()) continue;
            std::pair<int, int> edge_key{std::min(u, v), std::max(u, v)};
            if (added_edges.find(edge_key) != added_edges.end()) continue;
            auto ed = boost::add_edge(it_u->second, it_v->second, current).first;
            current[ed].label = label;
            added_edges.insert(edge_key);
        }
    }

    if (in_graph && boost::num_vertices(current) > 0) graphs.push_back(std::move(current));
    return graphs;
}
