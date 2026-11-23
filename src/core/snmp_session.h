#pragma once
// Wrapper RAII sobre a "single-session" API do Net-SNMP (snmp_sess_open/
// snmp_sess_synch_response/snmp_sess_close). Cada objeto Session encapsula um
// handle opaco e NÃO deve ser compartilhado entre threads — abra uma Session
// por worker. A tradução de erros USM alimenta a enumeração de usuários v3.
#include <chrono>
#include <string>

#include "target.h"

namespace bixsn::core {

// Inicializa a biblioteca Net-SNMP uma única vez (thread-safe). Idempotente.
void init_netsnmp_once();

enum class GetStatus {
  Ok,            // resposta válida recebida
  NoSuchName,    // OID inexistente (mas o agente respondeu => credencial válida)
  Timeout,       // sem resposta
  AuthError,     // v3: falha de autenticação (usuário EXISTE, digest errado)
  UnknownUser,   // v3: usmStatsUnknownUserNames (usuário NÃO existe)
  NotInTimeWindow,  // v3: relógio/engine boots fora de janela
  DecryptError,  // v3: falha de decriptação (priv)
  OtherError,    // demais erros
};

const char* to_string(GetStatus s);

struct GetResult {
  GetStatus status = GetStatus::OtherError;
  std::string value;       // valor formatado (quando Ok)
  std::string type;        // tipo SNMP textual (quando Ok)
  long errstat = 0;        // error-status do PDU de resposta (quando aplicável)
  std::string message;     // detalhe/erro textual do Net-SNMP
};

class Session {
 public:
  Session(Target target, Credential cred,
          std::chrono::microseconds timeout = std::chrono::seconds{1},
          int retries = 1);
  ~Session();

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
  Session(Session&&) noexcept;
  Session& operator=(Session&&) noexcept;

  // Abre a sessão. Em v3, dispara a descoberta de engineID no primeiro request.
  // Retorna false se snmp_sess_open falhar (ex. nome de host inválido).
  bool open();

  // GET de um OID (dot-decimal). Não requer open() prévio explícito: open()
  // é chamado sob demanda.
  GetResult get(const char* oid);

  // SET de um OID. `type` é o caractere de tipo do Net-SNMP (ex. 's' string,
  // 'i' int). Usado apenas para o teste de escrita idempotente (write-back do
  // próprio valor lido) — ESCREVE no agente; use com autorização explícita.
  GetResult set(const char* oid, char type, const std::string& value);

  // engineID descoberto (hex), vazio se indisponível. Útil como fingerprint v3.
  std::string engine_id() const;

 private:
  void close();

  Target target_;
  Credential cred_;
  std::chrono::microseconds timeout_;
  int retries_;
  void* sessp_ = nullptr;  // handle opaco do Net-SNMP (snmp_session*)
  bool opened_ = false;
};

}  // namespace bixsn::core
