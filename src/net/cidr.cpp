#include "cidr.h"

#include <array>
#include <cstdio>
#include <set>
#include <stdexcept>

namespace bixsn::net {

bool parse_ipv4(const std::string& s, uint32_t& out) {
  std::array<int, 4> o{};
  int consumed = 0;
  // %n grava quantos chars foram consumidos; exige casar os 4 octetos e a string inteira.
  int n = std::sscanf(s.c_str(), "%d.%d.%d.%d%n", &o[0], &o[1], &o[2], &o[3],
                      &consumed);
  if (n != 4 || consumed != static_cast<int>(s.size())) return false;
  for (int v : o)
    if (v < 0 || v > 255) return false;
  out = (static_cast<uint32_t>(o[0]) << 24) | (static_cast<uint32_t>(o[1]) << 16) |
        (static_cast<uint32_t>(o[2]) << 8) | static_cast<uint32_t>(o[3]);
  return true;
}

std::string ipv4_to_string(uint32_t ip) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (ip >> 24) & 0xff,
                (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
  return std::string(buf);
}

namespace {

void push_range(uint32_t start, uint32_t end, size_t max_hosts,
                std::vector<std::string>& out) {
  if (start > end) throw std::invalid_argument("range invertido (início > fim)");
  uint64_t count = static_cast<uint64_t>(end) - start + 1;
  if (max_hosts && count > max_hosts)
    throw std::invalid_argument("range excede max_hosts (" +
                                std::to_string(count) + " > " +
                                std::to_string(max_hosts) + ")");
  for (uint32_t ip = start;; ++ip) {
    out.push_back(ipv4_to_string(ip));
    if (ip == end) break;  // evita overflow quando end == 0xffffffff
  }
}

std::vector<std::string> expand_cidr(const std::string& ip_part,
                                     const std::string& bits_part,
                                     size_t max_hosts) {
  uint32_t base;
  if (!parse_ipv4(ip_part, base))
    throw std::invalid_argument("IP inválido em CIDR: " + ip_part);
  int bits = 0;
  try {
    size_t pos = 0;
    bits = std::stoi(bits_part, &pos);
    if (pos != bits_part.size()) throw std::invalid_argument("lixo após prefixo");
  } catch (...) {
    throw std::invalid_argument("prefixo CIDR inválido: /" + bits_part);
  }
  if (bits < 0 || bits > 32)
    throw std::invalid_argument("prefixo CIDR fora de 0..32: /" + bits_part);

  uint32_t mask = (bits == 0) ? 0u : (0xffffffffu << (32 - bits));
  uint32_t network = base & mask;
  uint32_t broadcast = network | ~mask;

  std::vector<std::string> out;
  // /31 e /32: todos os endereços são usáveis (RFC 3021 / host único).
  if (bits >= 31) {
    push_range(network, broadcast, max_hosts, out);
  } else {
    push_range(network + 1, broadcast - 1, max_hosts, out);  // sem rede/broadcast
  }
  return out;
}

}  // namespace

std::vector<std::string> expand_target(const std::string& spec,
                                       size_t max_hosts) {
  auto slash = spec.find('/');
  if (slash != std::string::npos)
    return expand_cidr(spec.substr(0, slash), spec.substr(slash + 1), max_hosts);

  auto dash = spec.find('-');
  if (dash != std::string::npos) {
    std::string lo = spec.substr(0, dash);
    std::string hi = spec.substr(dash + 1);
    uint32_t start, end;
    if (!parse_ipv4(lo, start))
      throw std::invalid_argument("IP inicial inválido em range: " + lo);
    if (hi.find('.') == std::string::npos) {
      // range curto: só o último octeto (ex. 10.0.0.1-50)
      int last = 0;
      try {
        size_t pos = 0;
        last = std::stoi(hi, &pos);
        if (pos != hi.size()) throw std::invalid_argument("lixo");
      } catch (...) {
        throw std::invalid_argument("octeto final inválido em range: " + hi);
      }
      if (last < 0 || last > 255)
        throw std::invalid_argument("octeto final fora de 0..255: " + hi);
      end = (start & 0xffffff00u) | static_cast<uint32_t>(last);
    } else if (!parse_ipv4(hi, end)) {
      throw std::invalid_argument("IP final inválido em range: " + hi);
    }
    std::vector<std::string> out;
    push_range(start, end, max_hosts, out);
    return out;
  }

  uint32_t ip;
  if (!parse_ipv4(spec, ip))
    throw std::invalid_argument("alvo inválido: " + spec);
  return {ipv4_to_string(ip)};
}

std::vector<std::string> expand_targets(const std::string& specs,
                                        size_t max_hosts) {
  std::vector<std::string> out;
  std::set<std::string> seen;
  size_t pos = 0;
  while (pos <= specs.size()) {
    auto comma = specs.find(',', pos);
    std::string tok = specs.substr(
        pos, comma == std::string::npos ? std::string::npos : comma - pos);
    // trim
    auto a = tok.find_first_not_of(" \t");
    auto b = tok.find_last_not_of(" \t");
    if (a != std::string::npos) {
      tok = tok.substr(a, b - a + 1);
      for (auto& ip : expand_target(tok, max_hosts))
        if (seen.insert(ip).second) out.push_back(ip);
    }
    if (comma == std::string::npos) break;
    pos = comma + 1;
  }
  return out;
}

}  // namespace bixsn::net
