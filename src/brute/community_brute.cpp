#include "brute.h"

#include "../core/oids.h"
#include "../core/snmp_session.h"

namespace bixsn::brute {

using namespace bixsn::core;

namespace {

// Um GET cuja resposta (Ok ou noSuchName) prova que o agente aceitou a
// credencial. Timeout/erro de credencial => inválida.
bool credential_valid(const GetResult& g) {
  return g.status == GetStatus::Ok || g.status == GetStatus::NoSuchName;
}

}  // namespace

void community(HostResult& hr, const std::vector<std::string>& communities,
               const Options& opt) {
  for (const auto& comm : communities) {
    Credential cred;
    cred.version = opt.version;  // V1 ou V2c
    cred.community = comm;

    Session s({hr.host, hr.port}, cred, opt.timeout, opt.retries);
    GetResult g = s.get(oids::kSysDescr);
    if (!credential_valid(g)) continue;

    hr.snmp_open = true;
    hr.communities_ro.push_back(comm);
    if (g.status == GetStatus::Ok && hr.sys_descr.empty())
      hr.sys_descr = g.value;

    hr.findings.push_back(
        {hr.host, hr.port, Risk::High, "Community SNMP válida (RO)",
         "community '" + comm + "' responde em " + to_string(opt.version),
         "Troque communities default, restrinja por ACL/firewall e migre p/ "
         "SNMPv3 authPriv."});

    if (!opt.test_write) continue;

    // Prova de RW sem alterar estado: lê sysLocation e reescreve o MESMO valor.
    GetResult cur = s.get(oids::kSysLocation);
    if (cur.status != GetStatus::Ok) continue;  // sem valor legível p/ reescrever
    // snprint_value pode devolver "STRING: valor"; extrai o conteúdo após ": ".
    std::string val = cur.value;
    auto sep = val.find(": ");
    if (sep != std::string::npos) val = val.substr(sep + 2);

    GetResult w = s.set(oids::kSysLocation, 's', val);
    if (w.status == GetStatus::Ok) {
      hr.communities_rw.push_back(comm);
      hr.findings.push_back(
          {hr.host, hr.port, Risk::Critical, "Community SNMP com ESCRITA (RW)",
           "community '" + comm +
               "' aceitou SET em sysLocation (write-back idempotente)",
           "RW permite reconfigurar o dispositivo. Remova a community RW "
           "imediatamente e audite alterações."});
    }
  }
}

}  // namespace bixsn::brute
