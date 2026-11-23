#include "result.h"

namespace bixsn::core {

const char* to_string(Risk r) {
  switch (r) {
    case Risk::Info: return "INFO";
    case Risk::Low: return "LOW";
    case Risk::Medium: return "MEDIUM";
    case Risk::High: return "HIGH";
    case Risk::Critical: return "CRITICAL";
  }
  return "?";
}

}  // namespace bixsn::core
