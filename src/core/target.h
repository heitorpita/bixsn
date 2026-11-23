#pragma once
// Modelos de alvo e credencial SNMP.
#include <cstdint>
#include <string>

namespace bixsn::core {

enum class SnmpVersion { V1, V2c, V3 };

enum class SecLevel { noAuthNoPriv, authNoPriv, authPriv };

enum class AuthProto { None, MD5, SHA, SHA224, SHA256, SHA384, SHA512 };

enum class PrivProto { None, DES, AES };

const char* to_string(SnmpVersion v);
const char* to_string(SecLevel l);
const char* to_string(AuthProto p);
const char* to_string(PrivProto p);

// Credencial unificada: para v1/v2c usa-se `community`; para v3, os campos USM.
struct Credential {
  SnmpVersion version = SnmpVersion::V2c;

  // v1/v2c
  std::string community;

  // v3 / USM
  std::string username;
  SecLevel sec_level = SecLevel::noAuthNoPriv;
  AuthProto auth_proto = AuthProto::None;
  std::string auth_pass;
  PrivProto priv_proto = PrivProto::None;
  std::string priv_pass;
};

// Um alvo = endereço + porta (UDP 161 por padrão).
struct Target {
  std::string host;
  uint16_t port = 161;
};

}  // namespace bixsn::core
