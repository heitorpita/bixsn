#pragma once
// OIDs numéricos conhecidos usados pela ferramenta. Strings dot-decimal para
// passar direto ao read_objid()/snmp_parse_oid() da libnetsnmp.
namespace bixsn::core::oids {

// --- MIB-2 system (1.3.6.1.2.1.1) ---
inline constexpr const char* kSysDescr   = "1.3.6.1.2.1.1.1.0";  // string do dispositivo
inline constexpr const char* kSysObjectID= "1.3.6.1.2.1.1.2.0";  // fabricante/modelo
inline constexpr const char* kSysUpTime  = "1.3.6.1.2.1.1.3.0";
inline constexpr const char* kSysContact = "1.3.6.1.2.1.1.4.0";  // RW comum
inline constexpr const char* kSysName    = "1.3.6.1.2.1.1.5.0";  // RW comum (teste idempotente)
inline constexpr const char* kSysLocation= "1.3.6.1.2.1.1.6.0";  // RW comum

// --- SNMPv3 USM stats (1.3.6.1.6.3.15.1.1) ---
// Distinguem o resultado de um request USM malformado/ inválido:
inline constexpr const char* kUsmStatsUnsupportedSecLevels = "1.3.6.1.6.3.15.1.1.1.0";
inline constexpr const char* kUsmStatsNotInTimeWindows     = "1.3.6.1.6.3.15.1.1.2.0";
inline constexpr const char* kUsmStatsUnknownUserNames     = "1.3.6.1.6.3.15.1.1.3.0"; // usuário NÃO existe
inline constexpr const char* kUsmStatsUnknownEngineIDs     = "1.3.6.1.6.3.15.1.1.4.0";
inline constexpr const char* kUsmStatsWrongDigests         = "1.3.6.1.6.3.15.1.1.5.0"; // usuário EXISTE, auth errada
inline constexpr const char* kUsmStatsDecryptionErrors     = "1.3.6.1.6.3.15.1.1.6.0";

}  // namespace bixsn::core::oids
