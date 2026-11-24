#pragma once

#include "GraphTypes.h"

#include <string>
#include <vector>

struct DataLoader {
    // Load graphs from a text file in the standard t/v/e format
    static std::vector<Graph> loadGraphs(const std::string& filepath);
};
