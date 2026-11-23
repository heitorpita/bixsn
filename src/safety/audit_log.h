#pragma once
// Log append-only de auditoria: registra o que a ferramenta executou
// (timestamp UTC, operação, alvos, flags), para rastreabilidade do teste.
#include <mutex>
#include <string>

namespace bixsn::safety {

class AuditLog {
 public:
  // Abre (cria) o arquivo em modo append. Lança std::runtime_error se falhar.
  explicit AuditLog(const std::string& path);

  // Escreve uma linha "<ISO-8601 UTC> | <event>". Thread-safe.
  void write(const std::string& event);

 private:
  std::string path_;
  std::mutex mtx_;
};

}  // namespace bixsn::safety
