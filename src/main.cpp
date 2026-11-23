// bixsn — auditoria de SNMP (v1/v2c community brute, v3 USM enum) com escopo
// de autorização obrigatório e log de auditoria. Ferramenta para testes
// AUTORIZADOS: sem escopo carregado, nada roda.
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include "brute/brute.h"
#include "collect/walk.h"
#include "core/result.h"
#include "core/target.h"
#include "discovery/discovery.h"
#include "net/cidr.h"
#include "net/thread_pool.h"
#include "report/reporter.h"
#include "safety/audit_log.h"
#include "safety/scope.h"

using namespace bixsn;

namespace {

void usage(const char* argv0) {
  std::cerr <<
      "uso: " << argv0 << " [opções] <alvos>\n"
      "  <alvos>                CIDR/range/IP, separados por vírgula\n"
      "                         (ex. 10.0.0.0/24,10.0.1.1-50)\n"
      "escopo (um é OBRIGATÓRIO):\n"
      "  --scope FILE           arquivo de escopo (CIDRs/ranges, um por linha)\n"
      "  --i-own-this-range SPEC  adiciona uma regra de escopo inline\n"
      "opções:\n"
      "  --version v1|v2c|v3    protocolo (padrão v2c)\n"
      "  --community-file FILE  wordlist de communities (padrão data/community-strings.txt)\n"
      "  --v3-user-file FILE    wordlist de usuários v3 (padrão data/v3-users.txt)\n"
      "  --port N               porta UDP (padrão 161)\n"
      "  --threads N            concorrência (padrão 16)\n"
      "  --timeout MS           timeout por request (padrão 1000)\n"
      "  --retries N            retries por request (padrão 1)\n"
      "  --delay MS             intervalo mínimo global entre requests (rate limit)\n"
      "  --test-write           prova RW via write-back idempotente (ESCREVE no alvo)\n"
      "  --audit-log FILE       log de auditoria (padrão bixsn-audit.log)\n";
}

// Lê uma wordlist: uma entrada por linha, '#' comenta, ignora linhas em branco.
std::vector<std::string> read_wordlist(const std::string& path) {
  std::ifstream in(path);
  if (!in) throw std::runtime_error("não foi possível abrir wordlist: " + path);
  std::vector<std::string> out;
  std::string line;
  while (std::getline(in, line)) {
    auto hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    auto a = line.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) continue;
    auto b = line.find_last_not_of(" \t\r\n");
    out.push_back(line.substr(a, b - a + 1));
  }
  return out;
}

bool parse_version(const std::string& s, core::SnmpVersion& v) {
  if (s == "v1") v = core::SnmpVersion::V1;
  else if (s == "v2c") v = core::SnmpVersion::V2c;
  else if (s == "v3") v = core::SnmpVersion::V3;
  else return false;
  return true;
}

void banner(const char* mode, size_t hosts, size_t wordlist) {
  static const char* arts[] = {
      R"(
      _     _
     | |__ (_)_  _____ _ __
     | '_ \| \ \/ / __| '_ \
     | |_) | |>  <\__ \ | | |
     |_.__/|_/_/\_\___/_| |_|
)",
      R"(
    ####  #  #   #  ####  #   #
    #   # #   # #   #     ##  #
    ####  #    #     ###  # # #
    #   # #   # #       # #  ##
    ####  #  #   #  ####  #   #
          . : snmp auditor : .
)",
      R"(
   ┌────────────────────────────┐
   │  b i x s n                  │
   │  >> snmp recon & audit <<   │
   └────────────────────────────┘
)",
  };
  static const char* taglines[] = {
      "trap set -- waiting for the walk...",
      "they left the community string as 'public'. again.",
      "GET in, SET nothing, leave no trace.",
      "OID you not -- every switch talks eventually.",
      "walk softly and carry a big MIB.",
      "spanning trees, not covering tracks.",
      "your uptime is my attack window.",
      "public / private -- pick your poison.",
      "161 reasons this switch shouldn't face the internet.",
      "community? I barely know 'ity.",
      "no creds? no problem. snmpwalk says hi.",
      "the switch remembers everything. so do we.",
  };
  const size_t n = sizeof(arts) / sizeof(arts[0]);
  const size_t tn = sizeof(taglines) / sizeof(taglines[0]);
  std::srand(static_cast<unsigned>(std::time(nullptr)));
  const char* art = arts[std::rand() % n];
  const char* tag = taglines[std::rand() % tn];

  const bool tty = isatty(fileno(stderr));
  const char* R = tty ? "\033[1;31m" : "";
  const char* B = tty ? "\033[1;37m" : "";
  const char* Z = tty ? "\033[0m" : "";
  const char* D = tty ? "\033[2;37m" : "";

  std::cerr << R << art << Z << "\n";
  std::cerr << D << "       \"" << tag << "\"" << Z << "\n\n";
  std::cerr
      << B << "       =[ " << Z << "bixsn v0.1.0 — authorized SNMP auditor\n"
      << B << "+ -- --=[ " << Z << "mode    : " << mode << "\n"
      << B << "+ -- --=[ " << Z << "scope   : " << hosts << " host(s)\n"
      << B << "+ -- --=[ " << Z << "wordlist: " << wordlist << " entries\n\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string scope_file, scope_rule, target_spec;
  std::string community_file = "data/community-strings.txt";
  std::string v3_user_file = "data/v3-users.txt";
  std::string audit_path = "bixsn-audit.log";
  core::SnmpVersion version = core::SnmpVersion::V2c;
  uint16_t port = 161;
  size_t threads = 16;
  int timeout_ms = 1000, retries = 1, delay_ms = 0;
  bool test_write = false;

  // Parser simples: --flag VALOR, flags booleanas sem valor, resto = alvos.
  auto need = [&](int& i) -> std::string {
    if (i + 1 >= argc) { std::cerr << "faltou valor para " << argv[i] << "\n"; exit(2); }
    return argv[++i];
  };
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    else if (a == "--scope") scope_file = need(i);
    else if (a == "--i-own-this-range") scope_rule = need(i);
    else if (a == "--community-file") community_file = need(i);
    else if (a == "--v3-user-file") v3_user_file = need(i);
    else if (a == "--audit-log") audit_path = need(i);
    else if (a == "--port") port = static_cast<uint16_t>(std::stoi(need(i)));
    else if (a == "--threads") threads = static_cast<size_t>(std::stoul(need(i)));
    else if (a == "--timeout") timeout_ms = std::stoi(need(i));
    else if (a == "--retries") retries = std::stoi(need(i));
    else if (a == "--delay") delay_ms = std::stoi(need(i));
    else if (a == "--test-write") test_write = true;
    else if (a == "--version") {
      if (!parse_version(need(i), version)) { std::cerr << "versão inválida\n"; return 2; }
    } else if (!a.empty() && a[0] == '-') {
      std::cerr << "opção desconhecida: " << a << "\n"; return 2;
    } else {
      target_spec += (target_spec.empty() ? "" : ",") + a;
    }
  }

  if (target_spec.empty()) { usage(argv[0]); return 2; }

  // --- Escopo obrigatório (fail-closed) ---
  safety::Scope scope;
  try {
    if (!scope_file.empty()) scope.load_file(scope_file);
    if (!scope_rule.empty()) scope.add_rule(scope_rule);
  } catch (const std::exception& e) {
    std::cerr << "erro de escopo: " << e.what() << "\n";
    return 2;
  }
  if (scope.empty()) {
    std::cerr << "RECUSADO: nenhum escopo de autorização carregado. "
                 "Use --scope FILE ou --i-own-this-range SPEC.\n";
    return 2;
  }

  // --- Expande alvos e filtra pelo escopo ---
  std::vector<std::string> hosts;
  try {
    hosts = net::expand_targets(target_spec);
  } catch (const std::exception& e) {
    std::cerr << "erro nos alvos: " << e.what() << "\n";
    return 2;
  }
  std::vector<std::string> in_scope;
  size_t skipped = 0;
  for (auto& h : hosts) {
    if (scope.in_scope(h)) in_scope.push_back(h);
    else ++skipped;
  }
  if (skipped)
    std::cerr << "aviso: " << skipped << " alvo(s) fora do escopo, ignorados.\n";
  if (in_scope.empty()) { std::cerr << "nenhum alvo dentro do escopo.\n"; return 2; }

  // --- Wordlists ---
  std::vector<std::string> communities, users;
  try {
    if (version == core::SnmpVersion::V3) users = read_wordlist(v3_user_file);
    else communities = read_wordlist(community_file);
  } catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    return 2;
  }

  std::string mode = (version == core::SnmpVersion::V3)
                         ? "SNMPv3 USM user enumeration"
                         : std::string(core::to_string(version)) +
                               " community brute";
  if (test_write) mode += " + RW write-test";
  size_t wordlist_n =
      (version == core::SnmpVersion::V3) ? users.size() : communities.size();
  banner(mode.c_str(), in_scope.size(), wordlist_n);

  // --- Auditoria ---
  safety::AuditLog audit(audit_path);
  audit.write("START version=" + std::string(core::to_string(version)) +
              " targets=" + target_spec + " hosts_in_scope=" +
              std::to_string(in_scope.size()) +
              (test_write ? " test_write=ON" : ""));

  auto timeout = std::chrono::milliseconds(timeout_ms);
  brute::Options opt;
  opt.version = version;
  opt.timeout = timeout;
  opt.retries = retries;
  opt.test_write = test_write;

  std::vector<core::HostResult> results(in_scope.size());
  net::ThreadPool pool(threads, std::chrono::milliseconds(delay_ms));

  for (size_t i = 0; i < in_scope.size(); ++i) {
    core::HostResult& hr = results[i];
    hr.host = in_scope[i];
    hr.port = port;
    pool.submit([&hr, &communities, &users, &opt, version, timeout, retries] {
      discovery::probe(hr, timeout, retries);
      if (version == core::SnmpVersion::V3) {
        brute::enum_v3_users(hr, users, timeout, retries);
      } else {
        brute::community(hr, communities, opt);
        if (!hr.communities_ro.empty())
          collect::collect_system(hr, hr.communities_ro.front(), version,
                                  timeout, retries);
      }
    });
  }
  pool.wait_idle();

  report::write_text(std::cout, results);
  audit.write("END");
  return 0;
}
