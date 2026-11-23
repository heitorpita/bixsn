#include "reporter.h"

#include <algorithm>

namespace bixsn::report {

using namespace bixsn::core;

namespace {
void join(std::ostream& os, const std::vector<std::string>& v) {
  for (size_t i = 0; i < v.size(); ++i) os << (i ? ", " : "") << v[i];
}
}  // namespace

void write_text(std::ostream& os, const std::vector<HostResult>& results) {
  size_t open_hosts = 0, total_findings = 0, critical = 0;

  for (const auto& hr : results) {
    if (!hr.snmp_open) continue;
    ++open_hosts;

    os << "== " << hr.host << ":" << hr.port << " ==\n";
    if (!hr.sys_descr.empty()) os << "  sysDescr: " << hr.sys_descr << "\n";
    if (!hr.engine_id.empty()) os << "  engineID: " << hr.engine_id << "\n";
    if (!hr.communities_ro.empty()) {
      os << "  community RO: ";
      join(os, hr.communities_ro);
      os << "\n";
    }
    if (!hr.communities_rw.empty()) {
      os << "  community RW: ";
      join(os, hr.communities_rw);
      os << "\n";
    }
    if (!hr.v3_users_valid.empty()) {
      os << "  usuários v3: ";
      join(os, hr.v3_users_valid);
      os << "\n";
    }

    for (const auto& f : hr.findings) {
      ++total_findings;
      if (f.risk == Risk::Critical) ++critical;
      os << "  [" << to_string(f.risk) << "] " << f.title;
      if (!f.detail.empty()) os << " — " << f.detail;
      os << "\n";
      if (!f.recommendation.empty()) os << "      -> " << f.recommendation << "\n";
    }
    os << "\n";
  }

  os << "resumo: " << open_hosts << " host(s) com SNMP aberto, "
     << total_findings << " achado(s), " << critical << " crítico(s).\n";
}

}  // namespace bixsn::report
