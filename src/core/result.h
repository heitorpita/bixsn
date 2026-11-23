#pragma once
// Achados normalizados da auditoria + níveis de risco.
#include <cstdint>
#include <string>
#include <vector>

#include "target.h"

namespace bixsn::core {

enum class Risk { Info, Low, Medium, High, Critical };

const char* to_string(Risk r);

// Um achado individual sobre um host.
struct Finding {
  std::string host;
  uint16_t port = 161;
  Risk risk = Risk::Info;
  std::string title;           // ex. "community RW aceita"
  std::string detail;          // ex. "community 'private' permite escrita"
  std::string recommendation;  // orientação de hardening
};

// Resultado agregado por host.
struct HostResult {
  std::string host;
  uint16_t port = 161;
  bool snmp_open = false;
  std::string engine_id;            // v3 engineID (hex) quando descoberto
  std::string sys_descr;            // sysDescr.0 quando obtido
  std::vector<std::string> communities_ro;
  std::vector<std::string> communities_rw;
  std::vector<std::string> v3_users_valid;
  std::vector<Finding> findings;
};

}  // namespace bixsn::core
