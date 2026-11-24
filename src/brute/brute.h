#pragma once
// Ataques de credencial: adivinhação de community (v1/v2c) e enumeração de
// usuários USM (v3). Operam sobre um HostResult já criado (host/port).
#include <chrono>
#include <string>
#include <vector>

#include "../core/result.h"
#include "../core/target.h"

namespace bixsn::safety { class AuditLog; }

namespace bixsn::brute {

struct Options {
  core::SnmpVersion version = core::SnmpVersion::V2c;  // v1 ou v2c p/ community
  std::chrono::microseconds timeout{std::chrono::seconds{1}};
  int retries = 1;
  bool test_write = false;  // provar RW via write-back idempotente (ESCREVE)
  safety::AuditLog* audit = nullptr;  // registra cada SET (best-effort); pode ser null
};

// Testa cada community. GET de sysDescr que RESPONDE (Ok ou noSuchName) => a
// community é válida (RO). Com test_write, confirma RW relendo e reescrevendo
// o MESMO valor de sysLocation (sem alterar estado). Preenche
// communities_ro/rw, sys_descr, snmp_open e findings.
void community(core::HostResult& hr, const std::vector<std::string>& communities,
               const Options& opt);

// Enumera usuários USM: para cada nome, um GET v3 noAuthNoPriv distingue
// UnknownUser (não existe) dos demais (existe). Preenche v3_users_valid e
// findings; também marca snmp_open/engine_id se descobertos.
void enum_v3_users(core::HostResult& hr,
                   const std::vector<std::string>& users,
                   std::chrono::microseconds timeout, int retries);

// Após achar um usuário USM existente, testa senhas de auth (authNoPriv) da
// wordlist contra os protocolos MD5 e SHA-1. Um GET que o agente ACEITA
// (Ok/noSuchName) prova a senha; WrongDigest/AuthError => senha errada.
// ESCREVE nada, mas gera tráfego autenticado — registre no audit. Acrescenta
// um Finding Critical por senha descoberta. `audit` pode ser null.
void brute_v3_auth(core::HostResult& hr, const std::string& user,
                   const std::vector<std::string>& passwords,
                   std::chrono::microseconds timeout, int retries,
                   safety::AuditLog* audit);

}  // namespace bixsn::brute
