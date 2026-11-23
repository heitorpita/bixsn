#pragma once
// Escopo de autorização: a ferramenta só age sobre IPs explicitamente
// permitidos. Carregado de um arquivo (CIDRs/ranges, um por linha, '#'
// para comentários). Sem escopo carregado, in_scope() é sempre false — o
// orquestrador deve recusar operar.
#include <cstdint>
#include <string>
#include <vector>

namespace bixsn::safety {

class Scope {
 public:
  // Carrega regras de um arquivo. Lança std::runtime_error se não abrir, ou
  // std::invalid_argument numa linha malformada (com o número da linha).
  void load_file(const std::string& path);

  // Adiciona uma regra única (CIDR, range ou IP). Usado por --i-own-this-range.
  void add_rule(const std::string& spec);

  bool empty() const { return ranges_.empty(); }
  size_t rule_count() const { return ranges_.size(); }

  // true se o IP (string "a.b.c.d") cai em alguma regra permitida.
  bool in_scope(const std::string& ip) const;

 private:
  struct Range {
    uint32_t start;
    uint32_t end;
  };
  std::vector<Range> ranges_;
};

}  // namespace bixsn::safety
