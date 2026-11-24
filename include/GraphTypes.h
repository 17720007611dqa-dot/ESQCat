#pragma once

#include <string>
#include <boost/graph/adjacency_list.hpp>

struct VertexProp { std::string label; };
struct EdgeProp { std::string label; };
using Graph = boost::adjacency_list<boost::vecS, boost::vecS, boost::undirectedS, VertexProp, EdgeProp>;
