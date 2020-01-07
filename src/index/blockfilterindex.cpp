// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>

#include <clientversion.h>
#include <index/blockfilterindex.h>
#include <streams.h>
#include <sqlite.h>
#include <util/system.h>
#include <validation.h>

/* The index database stores three items for each block: the disk location of the encoded filter,
 * its dSHA256 hash, and the header. Those belonging to blocks on the active chain are indexed by
 * height, and those belonging to blocks that have been reorganized out of the active chain are
 * indexed by block hash. This ensures that filter data for any block that becomes part of the
 * active chain can always be retrieved, alleviating timing concerns.
 */

static std::map<BlockFilterType, BlockFilterIndex> g_filter_indexes;

static const sqlite::sqlite_config sharedConfig {
        sqlite::OpenFlags::READWRITE | sqlite::OpenFlags::CREATE,
        nullptr, sqlite::Encoding::UTF8
};

BlockFilterIndex::BlockFilterIndex(BlockFilterType filter_type,
                                   size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_filter_type(filter_type), db(f_memory ? ":memory:" : (GetDataDir() / "block_filter.sqlite").string(), sharedConfig)
{
    m_filter_name = BlockFilterTypeName(filter_type);
    if (m_filter_name.empty()) throw std::invalid_argument("unknown filter_type");

    db << "PRAGMA cache_size=-" + std::to_string(n_cache_size >> 10U); // in -KB
    db << "PRAGMA synchronous=OFF"; // don't disk sync after transaction commit
    db << "PRAGMA journal_mode=WAL";
    db << "PRAGMA temp_store=MEMORY";
    db << "PRAGMA case_sensitive_like=true";

    db << "CREATE TABLE IF NOT EXISTS " + m_filter_name +
          " (height INTEGER, blockHash BLOB NOT NULL, filterHash BLOB NOT NULL,"
          " filter BLOB NOT NULL, PRIMARY KEY(height, blockHash));";

    if (f_wipe) {
        db << "DELETE FROM " + m_filter_name;
    }
    db << "BEGIN";
}

//bool BlockFilterIndex::Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip)
//{
//    assert(current_tip->GetAncestor(new_tip->nHeight) == new_tip);
//
//    // During a reorg, we need to copy all filters for blocks that are getting disconnected from the
//    // height index to the hash index so we can still find them when the height index entries are
//    // overwritten.
//
//    db << "UPDATE block SET height = NULL WHERE height BETWEEN ? AND ?"
//          << new_tip->nHeight + 1 << current_tip->nHeight;
//    return db.rows_modified() > 0;
//}

bool BlockFilterIndex::LookupFilter(const CBlockIndex* block_index, BlockFilter& filter_out) const
{
    std::vector<BlockFilter> filters;
    if (!LookupFilterRange(block_index->nHeight, block_index, filters))
        return false;
    filter_out = std::move(filters[0]);
    return true;
}

bool BlockFilterIndex::LookupFilterHeader(const CBlockIndex* block_index, uint256& header_out) const
{
    std::vector<uint256> filters;
    if (!LookupFilterHashRange(block_index->nHeight, block_index, filters))
        return false;
    header_out = std::move(filters[0]);
    return true;
}

bool BlockFilterIndex::LookupFilterRange(int start_height, const CBlockIndex* stop_index,
                                         std::vector<BlockFilter>& filters_out) const
{
    if (start_height < 0) {
        return error("%s: start height (%d) is negative", __func__, start_height);
    }
    if (start_height > stop_index->nHeight) {
        return error("%s: start height (%d) is greater than stop height (%d)",
                     __func__, start_height, stop_index->nHeight);
    }

    auto query = db << "SELECT height, blockHash, filter FROM " + m_filter_name +
                       " WHERE height BETWEEN ? AND ? ORDER BY height DESC"
                    << start_height << stop_index->nHeight;
    filters_out.reserve(stop_index->nHeight - start_height + 1);
    std::unordered_map<int, BlockFilter> temp;
    for (auto&& row: query) {
        int height = 0;
        uint256 hash;
        std::vector<uint8_t> filter;
        row >> height >> hash >> filter;
        temp.emplace(height, BlockFilter(m_filter_type, hash, filter));
    }

    while (start_height <= stop_index->nHeight) {
        auto hit = temp.find(stop_index->nHeight);
        if (hit != temp.end() && hit->second.GetBlockHash() == stop_index->GetBlockHash()) {
            filters_out.push_back(std::move(hit->second));
            continue;
        }
        // look it up by hash:
        auto innerQuery = db << "SELECT filter FROM " + m_filter_name +
                                " WHERE height IS NULL AND blockHash = ? LIMIT 1" << stop_index->GetBlockHash();
        for (auto&& innerRow: innerQuery) {
            std::vector<uint8_t> filter;
            innerRow >> filter;
            filters_out.emplace_back(m_filter_type, stop_index->GetBlockHash(), filter);
        }
        stop_index = stop_index->pprev;
    }

    return filters_out.size() == stop_index->nHeight - start_height + 1;
}

bool BlockFilterIndex::LookupFilterHashRange(int start_height, const CBlockIndex* stop_index,
                                             std::vector<uint256>& hashes_out) const

{
    if (start_height < 0) {
        return error("%s: start height (%d) is negative", __func__, start_height);
    }
    if (start_height > stop_index->nHeight) {
        return error("%s: start height (%d) is greater than stop height (%d)",
                     __func__, start_height, stop_index->nHeight);
    }

    hashes_out.reserve(stop_index->nHeight - start_height + 1);

    while (start_height <= stop_index->nHeight) {
        auto innerQuery = db << "SELECT filterHash FROM " + m_filter_name +
                                " WHERE (height = ? OR height IS NULL) AND blockHash = ? LIMIT 1"
                                << stop_index->nHeight << stop_index->GetBlockHash();
        for (auto&& innerRow: innerQuery) {
            uint256 hash;
            innerRow >> hash;
            hashes_out.push_back(hash);
        }
        stop_index = stop_index->pprev;
    }

    return hashes_out.size() == stop_index->nHeight - start_height + 1;
}

BlockFilterIndex* GetBlockFilterIndex(BlockFilterType filter_type)
{
    auto it = g_filter_indexes.find(filter_type);
    return it != g_filter_indexes.end() ? &it->second : nullptr;
}

void ForEachBlockFilterIndex(std::function<void (BlockFilterIndex&)> fn)
{
    for (auto& entry : g_filter_indexes) fn(entry.second);
}

bool InitBlockFilterIndex(BlockFilterType filter_type,
                          size_t n_cache_size, bool f_memory, bool f_wipe)
{
    auto result = g_filter_indexes.emplace(std::piecewise_construct,
                                           std::forward_as_tuple(filter_type),
                                           std::forward_as_tuple(filter_type,
                                                                 n_cache_size, f_memory, f_wipe));
    return result.second;
}

bool DestroyBlockFilterIndex(BlockFilterType filter_type)
{
    return g_filter_indexes.erase(filter_type);
}

void DestroyAllBlockFilterIndexes()
{
    g_filter_indexes.clear();
}
