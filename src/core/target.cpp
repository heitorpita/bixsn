#include "target.h"

namespace bixsn::core {

const char* to_string(SnmpVersion v) {
  switch (v) {
    case SnmpVersion::V1: return "v1";
    case SnmpVersion::V2c: return "v2c";
    case SnmpVersion::V3: return "v3";
  }
  return "?";
}

const char* to_string(SecLevel l) {
  switch (l) {
    case SecLevel::noAuthNoPriv: return "noAuthNoPriv";
    case SecLevel::authNoPriv: return "authNoPriv";
    case SecLevel::authPriv: return "authPriv";
  }
  return "?";
}

const char* to_string(AuthProto p) {
  switch (p) {
    case AuthProto::None: return "none";
    case AuthProto::MD5: return "MD5";
    case AuthProto::SHA: return "SHA";
    case AuthProto::SHA224: return "SHA-224";
    case AuthProto::SHA256: return "SHA-256";
    case AuthProto::SHA384: return "SHA-384";
    case AuthProto::SHA512: return "SHA-512";
  }
  return "?";
}

const char* to_string(PrivProto p) {
  switch (p) {
    case PrivProto::None: return "none";
    case PrivProto::DES: return "DES";
    case PrivProto::AES: return "AES";
  }
  return "?";
}

}  // namespace bixsn::core
