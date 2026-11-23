#pragma once
// Sondagem de liveness SNMP. Um probe SNMPv3 sem credencial válida ainda
// dispara a descoberta de engineID (report), revelando se há agente vivo e
// seu engineID (fingerprint), sem precisar adivinhar community nem usuário.
#include <chrono>

#include "../core/result.h"

namespace bixsn::discovery {

// Preenche hr.snmp_open e hr.engine_id via probe v3. Best-effort: um host que
// só fala v1/v2c pode não responder ao probe v3 e ainda assim ter SNMP aberto
// (o brute de community decide isso). Não escreve nada no alvo.
void probe(core::HostResult& hr, std::chrono::microseconds timeout, int retries);

}  // namespace bixsn::discovery
