#include "audit_log.h"

#include <ctime>
#include <fstream>
#include <stdexcept>

namespace bixsn::safety {

AuditLog::AuditLog(const std::string& path) : path_(path) {
  std::ofstream test(path_, std::ios::app);
  if (!test) throw std::runtime_error("não foi possível abrir audit log: " + path);
}

void AuditLog::write(const std::string& event) {
  std::time_t t = std::time(nullptr);
  std::tm tm_utc{};
#if defined(_WIN32)
  gmtime_s(&tm_utc, &t);
#else
  gmtime_r(&t, &tm_utc);
#endif
  char ts[32];
  std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

  std::lock_guard<std::mutex> lk(mtx_);
  std::ofstream out(path_, std::ios::app);
  if (!out) return;  // melhor esforço; não derruba a execução
  out << ts << " | " << event << "\n";
}

}  // namespace bixsn::safety
