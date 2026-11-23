#include "snmp_session.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/transform_oids.h>  // kTransformOidLen + OIDs

#include <cstdlib>
#include <cstring>
#include <mutex>

#include "oids.h"

namespace bixsn::core {

void init_netsnmp_once() {
  static std::once_flag flag;
  std::call_once(flag, [] {
    // Não dependemos de MIBs: usamos OIDs numéricos (oids.h). Evita ruído de
    // parsing e torna o init rápido/determinístico.
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    setenv("MIBS", "", 1);
    init_snmp("bixsn");
  });
}

const char* to_string(GetStatus s) {
  switch (s) {
    case GetStatus::Ok: return "ok";
    case GetStatus::NoSuchName: return "noSuchName";
    case GetStatus::Timeout: return "timeout";
    case GetStatus::AuthError: return "authError";
    case GetStatus::UnknownUser: return "unknownUser";
    case GetStatus::NotInTimeWindow: return "notInTimeWindow";
    case GetStatus::DecryptError: return "decryptError";
    case GetStatus::OtherError: return "otherError";
  }
  return "?";
}

namespace {

// Mapeia AuthProto -> OID de transform do Net-SNMP. Retorna nullptr p/ None.
// Todos os OIDs de transform USM têm 10 elementos (transform_oids.h). Versões
// recentes do Net-SNMP não exportam mais USM_LENGTH_OID_TRANSFORM.
constexpr size_t kTransformOidLen = 10;

// Os símbolos de transform são arrays `extern oid[]` (não macros), declarados
// pela libsnmp. SHA-2 exige libsnmp >= 5.8 (Ubuntu 24.04 traz 5.9).
const oid* auth_oid(AuthProto p) {
  switch (p) {
    case AuthProto::MD5: return usmHMACMD5AuthProtocol;
    case AuthProto::SHA: return usmHMACSHA1AuthProtocol;
    case AuthProto::SHA224: return usmHMAC128SHA224AuthProtocol;
    case AuthProto::SHA256: return usmHMAC192SHA256AuthProtocol;
    case AuthProto::SHA384: return usmHMAC256SHA384AuthProtocol;
    case AuthProto::SHA512: return usmHMAC384SHA512AuthProtocol;
    case AuthProto::None: return nullptr;
  }
  return nullptr;
}

const oid* priv_oid(PrivProto p) {
  switch (p) {
    case PrivProto::DES: return usmDESPrivProtocol;
    case PrivProto::AES: return usmAESPrivProtocol;
    case PrivProto::None: return nullptr;
  }
  return nullptr;
}

int sec_level_netsnmp(SecLevel l) {
  switch (l) {
    case SecLevel::noAuthNoPriv: return SNMP_SEC_LEVEL_NOAUTH;
    case SecLevel::authNoPriv: return SNMP_SEC_LEVEL_AUTHNOPRIV;
    case SecLevel::authPriv: return SNMP_SEC_LEVEL_AUTHPRIV;
  }
  return SNMP_SEC_LEVEL_NOAUTH;
}

// Converte o libsnmp errno (de um report USM) no nosso GetStatus.
GetStatus map_lib_errno(int liberr) {
  switch (liberr) {
    case SNMPERR_UNKNOWN_USER_NAME: return GetStatus::UnknownUser;
    case SNMPERR_AUTHENTICATION_FAILURE: return GetStatus::AuthError;
    case SNMPERR_NOT_IN_TIME_WINDOW: return GetStatus::NotInTimeWindow;
    case SNMPERR_DECRYPTION_ERR: return GetStatus::DecryptError;
    case SNMPERR_USM_UNKNOWNSECURITYNAME: return GetStatus::UnknownUser;
    case SNMPERR_USM_AUTHENTICATIONFAILURE: return GetStatus::AuthError;
    case SNMPERR_TIMEOUT: return GetStatus::Timeout;
    default: return GetStatus::OtherError;
  }
}

// Interpreta o resultado de snmp_sess_synch_response (compartilhado get/set).
GetResult interpret(void* sessp, int status, netsnmp_pdu* resp) {
  GetResult r;
  if (status == STAT_SUCCESS && resp) {
    if (resp->errstat == SNMP_ERR_NOERROR && resp->variables) {
      netsnmp_variable_list* v = resp->variables;
      if (v->type == SNMP_NOSUCHOBJECT || v->type == SNMP_NOSUCHINSTANCE ||
          v->type == SNMP_ENDOFMIBVIEW) {
        r.status = GetStatus::NoSuchName;  // agente respondeu => credencial OK
      } else {
        char buf[2048];
        snprint_value(buf, sizeof(buf), v->name, v->name_length, v);
        r.status = GetStatus::Ok;
        r.value = buf;
      }
    } else if (resp->errstat == SNMP_ERR_NOSUCHNAME) {
      r.status = GetStatus::NoSuchName;  // v1: OID inexistente, credencial OK
    } else {
      r.status = GetStatus::OtherError;
      r.errstat = resp->errstat;
      r.message = snmp_errstring(resp->errstat);
    }
  } else if (status == STAT_TIMEOUT) {
    r.status = GetStatus::Timeout;
  } else {
    // STAT_ERROR: inclui reports USM (v3). Extrai o errno do libsnmp.
    int syserr = 0, liberr = 0;
    char* errstr = nullptr;
    snmp_sess_error(sessp, &syserr, &liberr, &errstr);
    r.status = map_lib_errno(liberr);
    if (errstr) {
      r.message = errstr;
      free(errstr);
    }
  }
  return r;
}

std::string engine_hex(const u_char* id, size_t len) {
  static const char* hx = "0123456789abcdef";
  std::string s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    s.push_back(hx[(id[i] >> 4) & 0xf]);
    s.push_back(hx[id[i] & 0xf]);
  }
  return s;
}

}  // namespace

Session::Session(Target target, Credential cred,
                 std::chrono::microseconds timeout, int retries)
    : target_(std::move(target)),
      cred_(std::move(cred)),
      timeout_(timeout),
      retries_(retries) {}

Session::~Session() { close(); }

Session::Session(Session&& o) noexcept
    : target_(std::move(o.target_)),
      cred_(std::move(o.cred_)),
      timeout_(o.timeout_),
      retries_(o.retries_),
      sessp_(o.sessp_),
      opened_(o.opened_) {
  o.sessp_ = nullptr;
  o.opened_ = false;
}

Session& Session::operator=(Session&& o) noexcept {
  if (this != &o) {
    close();
    target_ = std::move(o.target_);
    cred_ = std::move(o.cred_);
    timeout_ = o.timeout_;
    retries_ = o.retries_;
    sessp_ = o.sessp_;
    opened_ = o.opened_;
    o.sessp_ = nullptr;
    o.opened_ = false;
  }
  return *this;
}

bool Session::open() {
  if (opened_) return true;
  init_netsnmp_once();

  netsnmp_session ss;
  snmp_sess_init(&ss);

  std::string peer = "udp:" + target_.host + ":" + std::to_string(target_.port);
  ss.peername = const_cast<char*>(peer.c_str());
  ss.timeout = timeout_.count();  // microssegundos
  ss.retries = retries_;

  switch (cred_.version) {
    case SnmpVersion::V1: ss.version = SNMP_VERSION_1; break;
    case SnmpVersion::V2c: ss.version = SNMP_VERSION_2c; break;
    case SnmpVersion::V3: ss.version = SNMP_VERSION_3; break;
  }

  if (cred_.version == SnmpVersion::V3) {
    ss.securityName = const_cast<char*>(cred_.username.c_str());
    ss.securityNameLen = cred_.username.size();
    ss.securityLevel = sec_level_netsnmp(cred_.sec_level);

    if (cred_.sec_level != SecLevel::noAuthNoPriv) {
      const oid* ao = auth_oid(cred_.auth_proto);
      if (!ao) return false;  // protocolo indisponível nesta build
      ss.securityAuthProto = const_cast<oid*>(ao);
      ss.securityAuthProtoLen = kTransformOidLen;
      ss.securityAuthKeyLen = USM_AUTH_KU_LEN;
      if (generate_Ku(ss.securityAuthProto, ss.securityAuthProtoLen,
                      reinterpret_cast<const u_char*>(cred_.auth_pass.data()),
                      cred_.auth_pass.size(), ss.securityAuthKey,
                      &ss.securityAuthKeyLen) != SNMPERR_SUCCESS)
        return false;
    }
    if (cred_.sec_level == SecLevel::authPriv) {
      const oid* po = priv_oid(cred_.priv_proto);
      if (!po) return false;
      ss.securityPrivProto = const_cast<oid*>(po);
      ss.securityPrivProtoLen = kTransformOidLen;
      ss.securityPrivKeyLen = USM_PRIV_KU_LEN;
      // A chave priv deriva da auth_pass via mesmo protocolo de auth.
      if (generate_Ku(ss.securityAuthProto, ss.securityAuthProtoLen,
                      reinterpret_cast<const u_char*>(cred_.priv_pass.data()),
                      cred_.priv_pass.size(), ss.securityPrivKey,
                      &ss.securityPrivKeyLen) != SNMPERR_SUCCESS)
        return false;
    }
  } else {
    ss.community = reinterpret_cast<u_char*>(
        const_cast<char*>(cred_.community.c_str()));
    ss.community_len = cred_.community.size();
  }

  // snmp_sess_open copia a struct (incl. peername e chaves): seguro liberar o
  // escopo local depois.
  sessp_ = snmp_sess_open(&ss);
  if (!sessp_) return false;
  opened_ = true;
  return true;
}

GetResult Session::get(const char* oid_str) {
  GetResult r;
  if (!opened_ && !open()) {
    r.status = GetStatus::OtherError;
    r.message = "falha ao abrir sessão";
    return r;
  }

  oid name[MAX_OID_LEN];
  size_t name_len = MAX_OID_LEN;
  if (!read_objid(oid_str, name, &name_len)) {
    r.status = GetStatus::OtherError;
    r.message = std::string("OID inválido: ") + oid_str;
    return r;
  }

  netsnmp_pdu* pdu = snmp_pdu_create(SNMP_MSG_GET);
  snmp_add_null_var(pdu, name, name_len);

  netsnmp_pdu* resp = nullptr;
  int status = snmp_sess_synch_response(sessp_, pdu, &resp);
  // pdu é consumido (liberado ou vira resp) por synch_response.
  r = interpret(sessp_, status, resp);
  if (resp) snmp_free_pdu(resp);
  return r;
}

GetResult Session::set(const char* oid_str, char type, const std::string& value) {
  GetResult r;
  if (!opened_ && !open()) {
    r.status = GetStatus::OtherError;
    r.message = "falha ao abrir sessão";
    return r;
  }

  oid name[MAX_OID_LEN];
  size_t name_len = MAX_OID_LEN;
  if (!read_objid(oid_str, name, &name_len)) {
    r.status = GetStatus::OtherError;
    r.message = std::string("OID inválido: ") + oid_str;
    return r;
  }

  netsnmp_pdu* pdu = snmp_pdu_create(SNMP_MSG_SET);
  if (snmp_add_var(pdu, name, name_len, type, value.c_str()) != 0) {
    snmp_free_pdu(pdu);
    r.status = GetStatus::OtherError;
    r.message = "valor SET inválido";
    return r;
  }

  netsnmp_pdu* resp = nullptr;
  int status = snmp_sess_synch_response(sessp_, pdu, &resp);
  r = interpret(sessp_, status, resp);
  if (resp) snmp_free_pdu(resp);
  return r;
}

std::string Session::engine_id() const {
  if (!sessp_) return {};
  netsnmp_session* live = snmp_sess_session(sessp_);
  if (!live || !live->securityEngineID || live->securityEngineIDLen == 0)
    return {};
  return engine_hex(live->securityEngineID, live->securityEngineIDLen);
}

void Session::close() {
  if (sessp_) {
    snmp_sess_close(sessp_);
    sessp_ = nullptr;
  }
  opened_ = false;
}

}  // namespace bixsn::core
