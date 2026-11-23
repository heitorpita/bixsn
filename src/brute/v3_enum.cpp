#include "brute.h"

#include "../core/oids.h"
#include "../core/snmp_session.h"

namespace bixsn::brute {

using namespace bixsn::core;

void enum_v3_users(HostResult& hr, const std::vector<std::string>& users,
                   std::chrono::microseconds timeout, int retries) {
  for (const auto& user : users) {
    Credential cred;
    cred.version = SnmpVersion::V3;
    cred.username = user;
    cred.sec_level = SecLevel::noAuthNoPriv;

    Session s({hr.host, hr.port}, cred, timeout, retries);
    GetResult g = s.get(oids::kSysDescr);

    if (hr.engine_id.empty()) {
      std::string eng = s.engine_id();
      if (!eng.empty()) {
        hr.engine_id = eng;
        hr.snmp_open = true;
      }
    }

    // UnknownUser => o nome NÃO existe. Qualquer outra resposta do agente
    // (AuthError, NotInTimeWindow, DecryptError, Ok, noSuchName) => existe.
    if (g.status == GetStatus::UnknownUser) continue;
    if (g.status == GetStatus::Timeout || g.status == GetStatus::OtherError)
      continue;  // host mudo ou erro: não conclui existência

    hr.snmp_open = true;
    hr.v3_users_valid.push_back(user);
    hr.findings.push_back(
        {hr.host, hr.port, Risk::Medium, "Usuário SNMPv3 (USM) existente",
         "usuário '" + user + "' reconhecido pelo agente (status: " +
             to_string(g.status) + ")",
         "Nomes de usuário previsíveis facilitam ataque de senha. Use nomes "
         "não triviais e authPriv com senhas fortes."});
  }
}

}  // namespace bixsn::brute
