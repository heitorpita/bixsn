#include "scope.h"

#include <fstream>
#include <stdexcept>

#include "../net/cidr.h"

namespace bixsn::safety {

void Scope::add_rule(const std::string& spec) {
  // Reusa a expansão/validação do módulo cidr, mas guardamos apenas os
  // extremos para não materializar redes grandes. Reinterpretamos a spec:
  auto slash = spec.find('/');
  auto dash = spec.find('-');
  uint32_t start = 0, end = 0;
  if (slash != std::string::npos) {
    uint32_t base;
    if (!net::parse_ipv4(spec.substr(0, slash), base))
      throw std::invalid_argument("IP inválido em regra de escopo: " + spec);
    int bits = std::stoi(spec.substr(slash + 1));
    if (bits < 0 || bits > 32)
      throw std::invalid_argument("prefixo inválido em escopo: " + spec);
    uint32_t mask = (bits == 0) ? 0u : (0xffffffffu << (32 - bits));
    start = base & mask;
    end = start | ~mask;
  } else if (dash != std::string::npos) {
    std::string lo = spec.substr(0, dash), hi = spec.substr(dash + 1);
    if (!net::parse_ipv4(lo, start))
      throw std::invalid_argument("IP inicial inválido em escopo: " + spec);
    if (hi.find('.') == std::string::npos) {
      int last = std::stoi(hi);
      if (last < 0 || last > 255)
        throw std::invalid_argument("octeto final inválido em escopo: " + spec);
      end = (start & 0xffffff00u) | static_cast<uint32_t>(last);
    } else if (!net::parse_ipv4(hi, end)) {
      throw std::invalid_argument("IP final inválido em escopo: " + spec);
    }
  } else {
    if (!net::parse_ipv4(spec, start))
      throw std::invalid_argument("IP inválido em escopo: " + spec);
    end = start;
  }
  if (start > end) throw std::invalid_argument("range invertido em escopo: " + spec);
  ranges_.push_back({start, end});
}

void Scope::load_file(const std::string& path) {
  std::ifstream in(path);
  if (!in) throw std::runtime_error("não foi possível abrir escopo: " + path);
  std::string line;
  size_t lineno = 0;
  while (std::getline(in, line)) {
    ++lineno;
    auto hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    auto a = line.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) continue;
    auto b = line.find_last_not_of(" \t\r\n");
    std::string spec = line.substr(a, b - a + 1);
    try {
      add_rule(spec);
    } catch (const std::exception& e) {
      throw std::invalid_argument("escopo " + path + ":" + std::to_string(lineno) +
                                  ": " + e.what());
    }
  }
}

bool Scope::in_scope(const std::string& ip) const {
  uint32_t v;
  if (!net::parse_ipv4(ip, v)) return false;
  for (const auto& r : ranges_)
    if (v >= r.start && v <= r.end) return true;
  return false;
}

}  // namespace bixsn::safety
