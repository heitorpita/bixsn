#include "walk.h"

#include <utility>

#include "../core/oids.h"
#include "../core/snmp_session.h"

namespace bixsn::collect {

using namespace bixsn::core;

void collect_system(HostResult& hr, const std::string& community,
                    SnmpVersion version, std::chrono::microseconds timeout,
                    int retries) {
  Credential cred;
  cred.version = version;
  cred.community = community;

  Session s({hr.host, hr.port}, cred, timeout, retries);

  const std::pair<const char*, const char*> items[] = {
      {"sysDescr", oids::kSysDescr},     {"sysObjectID", oids::kSysObjectID},
      {"sysUpTime", oids::kSysUpTime},   {"sysContact", oids::kSysContact},
      {"sysName", oids::kSysName},       {"sysLocation", oids::kSysLocation},
  };

  for (const auto& [label, oid] : items) {
    GetResult g = s.get(oid);
    if (g.status != GetStatus::Ok) continue;
    if (oid == oids::kSysDescr && hr.sys_descr.empty()) hr.sys_descr = g.value;
    hr.findings.push_back({hr.host, hr.port, Risk::Info,
                           std::string("system.") + label, g.value, ""});
  }
}

}  // namespace bixsn::collect
