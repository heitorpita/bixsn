#pragma once
// Coleta de dados com uma credencial RO já validada. Lê o grupo system da
// MIB-2 (sysDescr/Name/Location/Contact/ObjectID/UpTime) para fingerprint.
#include <chrono>
#include <string>

#include "../core/result.h"
#include "../core/target.h"

namespace bixsn::collect {

// Usa `community` (v1/v2c) para GET dos OIDs de sistema; grava sys_descr e
// adiciona um Finding Info por item legível. Só-leitura.
void collect_system(core::HostResult& hr, const std::string& community,
                    core::SnmpVersion version,
                    std::chrono::microseconds timeout, int retries);

}  // namespace bixsn::collect
