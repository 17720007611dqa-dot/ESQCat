#ifndef GSPANMINER_H
#define GSPANMINER_H

#include "IndexBuilder.h"

#include <cstdint>
#include <string>
#include <vector>

struct DFSEdge {
    int from = 0;
    int to = 0;
    std::string from_label;
    std::string edge_label;
    std::string to_label;
};

using DFSCode = std::vector<DFSEdge>;

bool operator<(const DFSEdge& lhs, const DFSEdge& rhs);
bool operator==(const DFSEdge& lhs, const DFSEdge& rhs);
bool operator<(const DFSCode& lhs, const DFSCode& rhs);
bool operator==(const DFSCode& lhs, const DFSCode& rhs);

class GSpanMiner {
public:
    static std::vector<FrequentGraph> mine(
        const std::vector<Graph>& dataset,
        int support_threshold,
        int max_edges);  // -1 means unbounded gSpan mining.

    static DFSCode buildMinDFSCode(const Graph& pattern);
    static bool isMinDFSCode(const DFSCode& code, const Graph& pattern);
    static std::string dfsCodeToString(const DFSCode& code);
    static Graph graphFromDFSCode(const DFSCode& code);
};

#endif
