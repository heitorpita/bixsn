#include "brute.h"

#include "../core/oids.h"
#include "../core/snmp_session.h"
#include "../safety/audit_log.h"

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

    // engineID normalmente já veio do discovery::probe (fonte primária). Só
    // sondamos aqui como fallback, se o probe não o obteve — evita descoberta
    // duplicada quando o discovery rodou antes (caso comum no run_scan).
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

void brute_v3_auth(HostResult& hr, const std::string& user,
                   const std::vector<std::string>& passwords,
                   std::chrono::microseconds timeout, int retries,
                   safety::AuditLog* audit) {
  // Protocolos de auth mais comuns em campo. generate_Ku exige passphrase de
  // ao menos 8 bytes; senhas curtas simplesmente falham ao abrir a sessão e
  // são puladas (não é um achado).
  struct Proto { AuthProto proto; const char* name; };
  static const Proto protos[] = {{AuthProto::SHA, "SHA"}, {AuthProto::MD5, "MD5"}};

  for (const auto& pass : passwords) {
    bool found = false;
    for (const auto& pr : protos) {
      Credential cred;
      cred.version = SnmpVersion::V3;
      cred.username = user;
      cred.sec_level = SecLevel::authNoPriv;
      cred.auth_proto = pr.proto;
      cred.auth_pass = pass;

      Session s({hr.host, hr.port}, cred, timeout, retries);
      GetResult g = s.get(oids::kSysDescr);
      if (audit)
        audit->write("V3-AUTH host=" + hr.host + " user='" + user +
                     "' proto=" + pr.name + " status=" + to_string(g.status));

      // Agente aceitou o digest (respondeu com dado ou noSuchName) => senha ok.
      if (g.status == GetStatus::Ok || g.status == GetStatus::NoSuchName) {
        hr.snmp_open = true;
        hr.findings.push_back(
            {hr.host, hr.port, Risk::Critical,
             "Senha SNMPv3 (USM) fraca descoberta",
             "usuário '" + user + "' autentica com " + pr.name +
                 " e senha '" + pass + "' (authNoPriv)",
             "Troque a senha imediatamente, exija authPriv com senhas longas "
             "e rotacione credenciais expostas."});
        found = true;
        break;  // uma senha válida por usuário basta
      }
    }
    if (found) break;
  }
}

}  // namespace bixsn::brute
