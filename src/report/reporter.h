#pragma once
// Relatório em texto dos achados da auditoria.
#include <ostream>
#include <vector>

#include "../core/result.h"

namespace bixsn::report {

// Imprime um bloco por host (apenas hosts com SNMP aberto) e um resumo final.
void write_text(std::ostream& os, const std::vector<core::HostResult>& results);

// Emite um documento JSON (array de hosts com SNMP aberto + resumo) para
// consumo por pipeline/NOC. Sem dependências externas.
void write_json(std::ostream& os, const std::vector<core::HostResult>& results);

}  // namespace bixsn::report
