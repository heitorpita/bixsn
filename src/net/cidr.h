#pragma once
// Expansão de alvos IPv4: CIDR (10.0.0.0/24), range (10.0.0.1-10.0.0.50),
// range curto (10.0.0.1-50) e IP único. Módulo puro, sem dependências de rede.
#include <cstdint>
#include <string>
#include <vector>

namespace bixsn::net {

// Converte "a.b.c.d" -> inteiro host-order. Retorna false se inválido.
bool parse_ipv4(const std::string& s, uint32_t& out);

// Converte inteiro host-order -> "a.b.c.d".
std::string ipv4_to_string(uint32_t ip);

// Expande uma especificação de alvo em IPs individuais (strings "a.b.c.d").
// Formatos aceitos:
//   "10.0.0.5"                IP único
//   "10.0.0.0/24"             CIDR  (exclui rede e broadcast p/ prefixos < 31)
//   "10.0.0.1-10.0.0.50"      range completo
//   "10.0.0.1-50"             range curto (último octeto)
// Em erro, lança std::invalid_argument com mensagem descritiva.
// max_hosts limita a expansão (proteção contra /8 acidental); 0 = sem limite.
std::vector<std::string> expand_target(const std::string& spec,
                                       size_t max_hosts = 65536);

// Expande várias specs separadas por vírgula, deduplicando e preservando ordem.
std::vector<std::string> expand_targets(const std::string& specs,
                                        size_t max_hosts = 65536);

}  // namespace bixsn::net
