#pragma once

#include "CryptoUtils.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

// One masked suffix vector in a per-topology Graphlet B+ tree. The key is an
// ORE ciphertext of an obfuscated threshold count. masked_bitmap is not an
// exact-count bucket and is not plaintext: it stores the masked suffix
// identifier vector for graphs with count >= threshold. The cloud can recover
// only the suffix vector authorized by the query trapdoor mask stream. This
// still leaks that queried suffix vector, but no longer exposes all bucket
// memberships at rest and must not restore per-graph AES decryption.
struct GraphletBPlusEntry {
    std::vector<uint8_t> key;
    std::vector<uint8_t> masked_bitmap;
};

struct GraphletBPlusNode {
    bool is_leaf = true;
    std::vector<std::vector<uint8_t>> keys;
    std::vector<size_t> children;
    std::vector<GraphletBPlusEntry> entries;
    size_t next_leaf = std::numeric_limits<size_t>::max();
};

// Static B+ tree used independently for each PRF-tagged Graphlet topology.
// It is bulk-loaded once from masked suffix vectors. Plaintext counts are not
// stored in nodes; ordering and equality lookup use ORE_Compare.
class GraphletBPlusTree {
public:
    static constexpr size_t npos = std::numeric_limits<size_t>::max();

    std::vector<GraphletBPlusNode> nodes;
    size_t root = npos;
    size_t first_leaf = npos;
    size_t leaf_capacity = 64;
    size_t internal_fanout = 64;

    explicit GraphletBPlusTree(size_t requested_leaf_capacity = 64,
                               size_t requested_internal_fanout = 64)
        : leaf_capacity(std::max<size_t>(1, requested_leaf_capacity)),
          internal_fanout(std::max<size_t>(2, requested_internal_fanout)) {}

    bool empty() const {
        return root == npos;
    }

    void bulk_load(std::vector<GraphletBPlusEntry> entries) {
        nodes.clear();
        root = npos;
        first_leaf = npos;

        std::stable_sort(entries.begin(), entries.end(),
            [](const GraphletBPlusEntry& lhs, const GraphletBPlusEntry& rhs) {
                return CryptoEngine::ORE_Compare(lhs.key, rhs.key) < 0;
            });

        if (entries.empty()) return;

        std::vector<size_t> current_level;
        current_level.reserve((entries.size() + leaf_capacity - 1) / leaf_capacity);

        size_t previous_leaf = npos;
        for (size_t begin = 0; begin < entries.size(); begin += leaf_capacity) {
            const size_t end = std::min(begin + leaf_capacity, entries.size());
            GraphletBPlusNode leaf;
            leaf.entries.reserve(end - begin);
            for (size_t i = begin; i < end; ++i) {
                leaf.entries.push_back(std::move(entries[i]));
            }

            const size_t leaf_index = nodes.size();
            nodes.push_back(std::move(leaf));
            current_level.push_back(leaf_index);

            if (first_leaf == npos) first_leaf = leaf_index;
            if (previous_leaf != npos) nodes[previous_leaf].next_leaf = leaf_index;
            previous_leaf = leaf_index;
        }

        while (current_level.size() > 1) {
            std::vector<size_t> parent_level;
            parent_level.reserve((current_level.size() + internal_fanout - 1) / internal_fanout);

            for (size_t begin = 0; begin < current_level.size(); begin += internal_fanout) {
                const size_t end = std::min(begin + internal_fanout, current_level.size());
                GraphletBPlusNode parent;
                parent.is_leaf = false;
                parent.children.insert(parent.children.end(),
                                       current_level.begin() + static_cast<std::ptrdiff_t>(begin),
                                       current_level.begin() + static_cast<std::ptrdiff_t>(end));
                parent.keys.reserve(parent.children.size() - 1);
                for (size_t i = 1; i < parent.children.size(); ++i) {
                    // keys[i - 1] is the minimum encrypted key in children[i].
                    parent.keys.push_back(minimum_key(parent.children[i]));
                }

                parent_level.push_back(nodes.size());
                nodes.push_back(std::move(parent));
            }
            current_level = std::move(parent_level);
        }

        root = current_level.front();
    }

    bool lookup_equal_masked_bitmap(
        const std::vector<uint8_t>& ore_key,
        std::vector<uint8_t>& masked_bitmap_out) const {
        masked_bitmap_out.clear();
        if (empty()) return false;

        size_t leaf_index = find_first_possible_leaf(ore_key);
        const GraphletBPlusNode* leaf = &nodes[leaf_index];

        while (leaf != nullptr) {
            auto first = std::lower_bound(leaf->entries.begin(), leaf->entries.end(), ore_key,
                [](const GraphletBPlusEntry& entry, const std::vector<uint8_t>& key) {
                    return CryptoEngine::ORE_Compare(entry.key, key) < 0;
                });

            for (auto it = first; it != leaf->entries.end(); ++it) {
                const int cmp = CryptoEngine::ORE_Compare(it->key, ore_key);
                if (cmp == 0) {
                    masked_bitmap_out = it->masked_bitmap;
                    return true;
                }
                if (cmp > 0) return false;
            }

            if (leaf->next_leaf == npos) break;
            leaf = &nodes[leaf->next_leaf];
        }
        return false;
    }

private:
    const std::vector<uint8_t>& minimum_key(size_t node_index) const {
        const GraphletBPlusNode* node = &nodes[node_index];
        while (!node->is_leaf) {
            node = &nodes[node->children.front()];
        }
        return node->entries.front().key;
    }

    size_t find_first_possible_leaf(const std::vector<uint8_t>& lower_bound_key) const {
        size_t node_index = root;
        while (!nodes[node_index].is_leaf) {
            const GraphletBPlusNode& node = nodes[node_index];
            size_t child_pos = 0;
            // Descend left on equality because duplicate ORE keys may span leaves.
            while (child_pos < node.keys.size() &&
                   CryptoEngine::ORE_Compare(node.keys[child_pos], lower_bound_key) < 0) {
                ++child_pos;
            }
            node_index = node.children[child_pos];
        }
        return node_index;
    }

};
