// Optional stable source/CFG feedback for target-directed dynamic validation.
// This is deliberately separate from SymCC's symbolic solver and is disabled
// unless SYMCC_FEEDBACK_MAP_DIR is set during compilation.
#ifndef SYMCC_FEEDBACK_H
#define SYMCC_FEEDBACK_H

#include <cstdint>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <unistd.h>

#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

namespace symcc_feedback {

inline bool enabled() {
  const char *directory = std::getenv("SYMCC_FEEDBACK_MAP_DIR");
  return directory != nullptr && *directory != '\0';
}

inline uint64_t hash(const std::string &value) {
  uint64_t result = 14695981039346656037ULL;
  for (unsigned char byte : value) {
    result ^= byte;
    result *= 1099511628211ULL;
  }
  return result;
}

inline std::string normalizedModuleId(const llvm::Module &module) {
  std::string value = module.getModuleIdentifier();
  const char *root = std::getenv("SYMCC_SOURCE_ROOT");
  if (root != nullptr && *root != '\0') {
    std::string prefix(root);
    while (!prefix.empty() && prefix.back() == '/')
      prefix.pop_back();
    if (value.compare(0, prefix.size(), prefix) == 0 &&
        value.size() > prefix.size() && value[prefix.size()] == '/')
      value.erase(0, prefix.size() + 1);
  }
  return value;
}

// The map is emitted from the module-level view of the CFG, but notifications
// are inserted later, after instrumentation has split and added blocks.  Block
// ordinals (and therefore block and location IDs) would differ between the two
// views.  Caching the IDs computed for the map keeps both sides consistent.
inline std::unordered_map<const void *, uint64_t> &blockIdCache() {
  static std::unordered_map<const void *, uint64_t> cache;
  return cache;
}

inline uint64_t blockId(const llvm::BasicBlock &block) {
  const auto *cacheKey = static_cast<const void *>(&block);
  auto &cache = blockIdCache();
  const auto cached = cache.find(cacheKey);
  if (cached != cache.end())
    return cached->second;

  const auto *function = block.getParent();
  uint64_t ordinal = 0;
  for (const auto &candidate : *function) {
    if (&candidate == &block)
      break;
    ++ordinal;
  }
  const std::string key = normalizedModuleId(*function->getParent()) + "|" +
                          function->getName().str() + "|bb|" +
                          std::to_string(ordinal);
  const uint64_t identifier =
      (uint64_t{1} << 62) | (hash(key) & ((uint64_t{1} << 62) - 1));
  cache[cacheKey] = identifier;
  return identifier;
}

inline std::string sourcePath(const llvm::DILocation &location) {
  const auto *file = location.getScope()->getFile();
  if (file == nullptr)
    return {};
  std::string path;
  if (!file->getDirectory().empty())
    path = file->getDirectory().str() + "/";
  path += file->getFilename().str();
  for (char &character : path) {
    if (character == '\\')
      character = '/';
  }
  const char *root = std::getenv("SYMCC_SOURCE_ROOT");
  if (root != nullptr && *root != '\0') {
    std::string prefix(root);
    while (!prefix.empty() && prefix.back() == '/')
      prefix.pop_back();
    if (path.compare(0, prefix.size(), prefix) == 0 &&
        path.size() > prefix.size() && path[prefix.size()] == '/')
      path.erase(0, prefix.size() + 1);
  }
  return path;
}

inline std::string sourceFunction(const llvm::DILocation &location,
                                  const llvm::Function &fallback) {
  const auto *scope = location.getScope();
  const auto *subprogram = scope == nullptr ? nullptr : scope->getSubprogram();
  return subprogram == nullptr ? fallback.getName().str()
                               : subprogram->getName().str();
}

inline uint64_t locationId(const llvm::DILocation &location,
                           const llvm::Function &function,
                           const llvm::BasicBlock &block) {
  const std::string path = sourcePath(location);
  const std::string key = normalizedModuleId(*function.getParent()) + "|" +
                          sourceFunction(location, function) + "|line|" + path +
                          "|" + std::to_string(location.getLine()) + "|" +
                          std::to_string(location.getColumn()) + "|bb|" +
                          std::to_string(blockId(block));
  return (uint64_t{1} << 61) | (hash(key) & ((uint64_t{1} << 61) - 1));
}

inline std::string escapeJson(const std::string &value) {
  std::string escaped;
  escaped.reserve(value.size() + 8);
  for (unsigned char character : value) {
    switch (character) {
    case '"': escaped += "\\\""; break;
    case '\\': escaped += "\\\\"; break;
    case '\b': escaped += "\\b"; break;
    case '\f': escaped += "\\f"; break;
    case '\n': escaped += "\\n"; break;
    case '\r': escaped += "\\r"; break;
    case '\t': escaped += "\\t"; break;
    default:
      if (character < 0x20) {
        static const char hex[] = "0123456789abcdef";
        escaped += "\\u00";
        escaped += hex[character >> 4];
        escaped += hex[character & 0xf];
      } else {
        escaped += static_cast<char>(character);
      }
    }
  }
  return escaped;
}

struct SourceLocation {
  uint64_t id;
  std::string file;
  std::string function;
  unsigned line;
  unsigned column;
};

inline std::vector<SourceLocation> sourceLocations(const llvm::BasicBlock &block) {
  std::vector<SourceLocation> result;
  std::vector<uint64_t> seen;
  for (const auto &instruction : block) {
    const auto debug = instruction.getDebugLoc();
    if (!debug || debug->getLine() == 0)
      continue;
    const uint64_t id = locationId(*debug, *block.getParent(), block);
    if (std::find(seen.begin(), seen.end(), id) != seen.end())
      continue;
    seen.push_back(id);
    result.push_back({id, sourcePath(*debug), sourceFunction(*debug, *block.getParent()),
                      debug->getLine(), debug->getColumn()});
  }
  return result;
}

inline void emitMap(const llvm::Module &module) {
  if (!enabled())
    return;
  const char *directory = std::getenv("SYMCC_FEEDBACK_MAP_DIR");
  try {
    std::filesystem::create_directories(directory);
    const std::string moduleId = normalizedModuleId(module);
    const std::string base = std::to_string(hash(moduleId));
    const std::string path = std::string(directory) + "/" + base + ".jsonl";
    const std::string temporary = path + "." + std::to_string(
        static_cast<unsigned long long>(::getpid())) + ".tmp";
    std::ofstream output(temporary, std::ios::out | std::ios::trunc);
    if (!output)
      return;
    const char *commit = std::getenv("SYMCC_SOURCE_COMMIT");
    for (const auto &function : module) {
      if (function.isDeclaration() || function.empty())
        continue;
      output << "{\"schema_version\":1,\"module_id\":\""
             << escapeJson(moduleId) << "\",\"source_commit\":";
      if (commit == nullptr || *commit == '\0')
        output << "null";
      else
        output << "\"" << escapeJson(commit) << "\"";
      output << ",\"function\":\"" << escapeJson(function.getName().str())
             << "\",\"blocks\":[";
      bool firstBlock = true;
      for (const auto &block : function) {
        if (!firstBlock)
          output << ',';
        firstBlock = false;
        const uint64_t id = blockId(block);
        const auto locations = sourceLocations(block);
        const auto *terminator = block.getTerminator();
        const bool exit = llvm::isa<llvm::ReturnInst>(terminator) ||
                          llvm::isa<llvm::ResumeInst>(terminator);
        output << "{\"id\":" << id << ",\"entry\":"
               << (&block == &function.getEntryBlock() ? "true" : "false")
               << ",\"exit\":" << (exit ? "true" : "false")
               << ",\"source_file\":\""
               << (locations.empty() ? "" : escapeJson(locations.front().file))
               << "\",\"line\":";
        if (locations.empty())
          output << "null";
        else
          output << locations.front().line;
        output << ",\"successors\":[";
        for (unsigned index = 0; index < terminator->getNumSuccessors(); ++index) {
          if (index)
            output << ',';
          output << blockId(*terminator->getSuccessor(index));
        }
        output << "],\"source_locations\":[";
        for (size_t index = 0; index < locations.size(); ++index) {
          if (index)
            output << ',';
          const auto &location = locations[index];
          output << "{\"id\":" << location.id << ",\"source_file\":\""
                 << escapeJson(location.file) << "\",\"source_function\":\""
                 << escapeJson(location.function) << "\",\"line\":"
                 << location.line << ",\"column\":" << location.column << '}';
        }
        output << "],\"calls\":[";
        bool firstCall = true;
        for (const auto &instruction : block) {
          const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
          const auto *callee = call == nullptr ? nullptr : call->getCalledFunction();
          if (callee == nullptr || callee->isIntrinsic())
            continue;
          if (!firstCall)
            output << ',';
          firstCall = false;
          output << "{\"callee\":\"" << escapeJson(callee->getName().str())
                 << "\",\"callee_key\":";
          if (callee->isDeclaration())
            output << "null";
          else
            output << "\"" << escapeJson(moduleId + "::" + callee->getName().str()) << "\"";
          output << ",\"return_to\":[";
          for (unsigned index = 0; index < terminator->getNumSuccessors(); ++index) {
            if (index)
              output << ',';
            output << blockId(*terminator->getSuccessor(index));
          }
          output << "]}";
        }
        output << "]}";
      }
      output << "]}\n";
    }
    output.close();
    std::error_code error;
    std::filesystem::rename(temporary, path, error);
    if (error) {
      std::filesystem::remove(path, error);
      error.clear();
      std::filesystem::rename(temporary, path, error);
      if (error)
        std::filesystem::remove(temporary);
    }
  } catch (...) {
    // Feedback-map output is optional and must not make target compilation fail.
  }
}

} // namespace symcc_feedback

#endif // SYMCC_FEEDBACK_H
