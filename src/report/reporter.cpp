#include "reporter.h"

#include <algorithm>
#include <cstdio>

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

namespace {
// Escapa uma string para um literal JSON (sem as aspas externas).
std::string jesc(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += static_cast<char>(c);
        }
    }
  }
  return o;
}

void jarray(std::ostream& os, const std::vector<std::string>& v) {
  os << "[";
  for (size_t i = 0; i < v.size(); ++i)
    os << (i ? "," : "") << "\"" << jesc(v[i]) << "\"";
  os << "]";
}
}  // namespace

void write_json(std::ostream& os, const std::vector<HostResult>& results) {
  size_t open_hosts = 0, total_findings = 0, critical = 0;
  os << "{\"hosts\":[";
  bool first_host = true;
  for (const auto& hr : results) {
    if (!hr.snmp_open) continue;
    ++open_hosts;
    os << (first_host ? "" : ",");
    first_host = false;
    os << "{\"host\":\"" << jesc(hr.host) << "\",\"port\":" << hr.port
       << ",\"sys_descr\":\"" << jesc(hr.sys_descr) << "\""
       << ",\"engine_id\":\"" << jesc(hr.engine_id) << "\""
       << ",\"communities_ro\":";
    jarray(os, hr.communities_ro);
    os << ",\"communities_rw\":";
    jarray(os, hr.communities_rw);
    os << ",\"v3_users\":";
    jarray(os, hr.v3_users_valid);
    os << ",\"findings\":[";
    for (size_t i = 0; i < hr.findings.size(); ++i) {
      const auto& f = hr.findings[i];
      ++total_findings;
      if (f.risk == Risk::Critical) ++critical;
      os << (i ? "," : "") << "{\"risk\":\"" << to_string(f.risk)
         << "\",\"title\":\"" << jesc(f.title) << "\",\"detail\":\""
         << jesc(f.detail) << "\",\"recommendation\":\""
         << jesc(f.recommendation) << "\"}";
    }
    os << "]}";
  }
  os << "],\"summary\":{\"open_hosts\":" << open_hosts
     << ",\"findings\":" << total_findings << ",\"critical\":" << critical
     << "}}\n";
}

}  // namespace bixsn::report
