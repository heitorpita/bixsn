#include "discovery.h"

#include "../core/oids.h"
#include "../core/snmp_session.h"

namespace bixsn::discovery {

void probe(core::HostResult& hr, std::chrono::microseconds timeout,
           int retries) {
  using namespace bixsn::core;
  // Usuário inexistente, noAuthNoPriv: o GET falha, mas o engineID é
  // descoberto no caminho (report usmStatsUnknownEngineIDs -> retry).
  Credential cred;
  cred.version = SnmpVersion::V3;
  cred.username = "bixsn-probe";
  cred.sec_level = SecLevel::noAuthNoPriv;

  Session s({hr.host, hr.port}, cred, timeout, retries);
  GetResult g = s.get(oids::kSysDescr);
  (void)g;  // o status não importa; só queremos o engineID descoberto

  std::string eng = s.engine_id();
  if (!eng.empty()) {
    hr.snmp_open = true;
    hr.engine_id = eng;
    hr.findings.push_back(
        {hr.host, hr.port, Risk::Info, "Agente SNMPv3 vivo",
         "engineID descoberto: " + eng,
         "Confirme que SNMP deve estar exposto nesta interface."});
  }
}

}  // namespace bixsn::discovery
