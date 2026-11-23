#pragma once
// Ataques de credencial: adivinhação de community (v1/v2c) e enumeração de
// usuários USM (v3). Operam sobre um HostResult já criado (host/port).
#include <chrono>
#include <string>
#include <vector>

#include "../core/result.h"
#include "../core/target.h"

namespace bixsn::brute {

struct Options {
  core::SnmpVersion version = core::SnmpVersion::V2c;  // v1 ou v2c p/ community
  std::chrono::microseconds timeout{std::chrono::seconds{1}};
  int retries = 1;
  bool test_write = false;  // provar RW via write-back idempotente (ESCREVE)
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

}  // namespace bixsn::brute
