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
#include <sstream>
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

struct Config {
  std::string scope_file;
  std::string scope_rule;
  std::string target_spec;
  std::string community_file = "data/community-strings.txt";
  std::string v3_user_file = "data/v3-users.txt";
  std::string audit_path = "bixsn-audit.log";
  core::SnmpVersion version = core::SnmpVersion::V2c;
  uint16_t port = 161;
  size_t threads = 16;
  int timeout_ms = 1000;
  int retries = 1;
  int delay_ms = 0;
  bool test_write = false;
};

const char* version_str(core::SnmpVersion v) {
  switch (v) {
    case core::SnmpVersion::V1: return "v1";
    case core::SnmpVersion::V2c: return "v2c";
    case core::SnmpVersion::V3: return "v3";
  }
  return "v2c";
}

std::string mode_str(const Config& c) {
  std::string m = (c.version == core::SnmpVersion::V3)
                      ? "SNMPv3 USM user enumeration"
                      : std::string(version_str(c.version)) + " community brute";
  if (c.test_write) m += " + RW write-test";
  return m;
}

void usage(const char* argv0) {
  std::cerr <<
      "uso: " << argv0 << " [opções] <alvos>\n"
      "  (sem argumentos abre o console interativo)\n"
      "  <alvos>                CIDR/range/IP, separados por vírgula\n"
      "                         (ex. 10.0.0.0/24,10.0.1.1-50)\n"
      "escopo (um é OBRIGATÓRIO):\n"
      "  --scope FILE           arquivo de escopo (CIDRs/ranges, um por linha)\n"
      "  --range, -r SPEC       adiciona uma regra de escopo inline (você confirma que o range é seu)\n"
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

bool file_exists(const std::string& p) {
  std::ifstream f(p);
  return static_cast<bool>(f);
}

std::string exe_dir() {
  char buf[4096];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return {};
  buf[n] = '\0';
  std::string p(buf);
  auto slash = p.find_last_of('/');
  return slash == std::string::npos ? std::string() : p.substr(0, slash);
}

// Procura o diretório das wordlists perto do cwd e do executável, para que
// `bixsn` funcione de qualquer diretório (não só de dentro do projeto).
std::string resolve_data_dir() {
  std::vector<std::string> cands = {"data"};
  std::string ed = exe_dir();
  if (!ed.empty()) {
    cands.push_back(ed + "/data");
    cands.push_back(ed + "/../data");
    cands.push_back(ed + "/../share/bixsn");
  }
  for (const auto& c : cands)
    if (file_exists(c + "/community-strings.txt")) return c;
  return "data";
}

void splash() {
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
  const char* D = tty ? "\033[2;37m" : "";
  const char* Z = tty ? "\033[0m" : "";

  std::cerr << R << art << Z << "\n";
  std::cerr << D << "       \"" << tag << "\"" << Z << "\n\n";
  std::cerr << "       =[ bixsn v0.1.0 — authorized SNMP auditor ]=\n\n";
}

// Executa um scan a partir da configuração. Retorna o código de saída.
int run_scan(const Config& cfg) {
  safety::Scope scope;
  try {
    if (!cfg.scope_file.empty()) scope.load_file(cfg.scope_file);
    if (!cfg.scope_rule.empty()) scope.add_rule(cfg.scope_rule);
  } catch (const std::exception& e) {
    std::cerr << "erro de escopo: " << e.what() << "\n";
    return 2;
  }
  if (scope.empty()) {
    std::cerr << "RECUSADO: nenhum escopo de autorização carregado. "
                 "Defina scope (--scope FILE) ou range (--range SPEC).\n";
    return 2;
  }
  if (cfg.target_spec.empty()) {
    std::cerr << "nenhum alvo definido.\n";
    return 2;
  }

  std::vector<std::string> hosts;
  try {
    hosts = net::expand_targets(cfg.target_spec);
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

  std::vector<std::string> communities, users;
  try {
    if (cfg.version == core::SnmpVersion::V3) users = read_wordlist(cfg.v3_user_file);
    else communities = read_wordlist(cfg.community_file);
  } catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    return 2;
  }

  size_t wordlist_n =
      (cfg.version == core::SnmpVersion::V3) ? users.size() : communities.size();
  std::cerr << "[*] mode    : " << mode_str(cfg) << "\n"
            << "[*] scope   : " << in_scope.size() << " host(s)\n"
            << "[*] wordlist: " << wordlist_n << " entries\n\n";

  safety::AuditLog audit(cfg.audit_path);
  audit.write("START version=" + std::string(version_str(cfg.version)) +
              " targets=" + cfg.target_spec + " hosts_in_scope=" +
              std::to_string(in_scope.size()) +
              (cfg.test_write ? " test_write=ON" : ""));

  auto timeout = std::chrono::milliseconds(cfg.timeout_ms);
  brute::Options opt;
  opt.version = cfg.version;
  opt.timeout = timeout;
  opt.retries = cfg.retries;
  opt.test_write = cfg.test_write;
  core::SnmpVersion version = cfg.version;
  int retries = cfg.retries;

  std::vector<core::HostResult> results(in_scope.size());
  net::ThreadPool pool(cfg.threads, std::chrono::milliseconds(cfg.delay_ms));

  for (size_t i = 0; i < in_scope.size(); ++i) {
    core::HostResult& hr = results[i];
    hr.host = in_scope[i];
    hr.port = cfg.port;
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

// ---- Console interativo ----

void console_help() {
  std::cerr <<
      "comandos:\n"
      "  show [options]      mostra a configuração atual\n"
      "  use v1|v2c|v3       seleciona o protocolo (modo)\n"
      "  set <opção> <valor> define uma opção (ex.: set targets 10.0.0.0/24)\n"
      "  unset <opção>       limpa uma opção\n"
      "  run | go            executa o scan com a configuração atual\n"
      "  banner              mostra o banner novamente\n"
      "  help | ?            esta ajuda\n"
      "  exit | quit         sai\n"
      "\nopções (set <nome> <valor>):\n"
      "  mode        v1 | v2c | v3\n"
      "  targets     lista CIDR/range/IP dos alvos\n"
      "  range       range autorizado inline (você confirma que é seu)\n"
      "  scope-file  arquivo de escopo\n"
      "  port        porta UDP (padrão 161)\n"
      "  threads     concorrência (padrão 16)\n"
      "  timeout     timeout por request em ms (padrão 1000)\n"
      "  retries     retries por request (padrão 1)\n"
      "  delay       intervalo mínimo entre requests em ms\n"
      "  test-write  on | off  (ESCREVE no alvo)\n"
      "  communities arquivo de wordlist de communities\n"
      "  users       arquivo de wordlist de usuários v3\n"
      "  audit-log   caminho do log de auditoria\n";
}

void show_options(const Config& c) {
  auto val = [](const std::string& s) { return s.empty() ? "(vazio)" : s; };
  std::cerr << "\nConfiguração (mode: " << mode_str(c) << ")\n\n";
  std::cerr << "   Nome         Valor atual                  Obrig.  Descrição\n";
  std::cerr << "   ----         -----------                  ------  ---------\n";
  auto row = [](const char* name, const std::string& v, const char* req,
                const char* desc) {
    std::string n = name, vv = v;
    n.resize(12, ' ');
    vv.resize(28, ' ');
    std::cerr << "   " << n << " " << vv << " " << req << "    " << desc << "\n";
  };
  row("mode", version_str(c.version), "sim", "v1 | v2c | v3");
  row("targets", val(c.target_spec), "sim", "CIDR/range/IP dos alvos");
  row("range", val(c.scope_rule), "sim*", "range autorizado inline");
  row("scope-file", val(c.scope_file), "sim*", "arquivo de escopo");
  row("port", std::to_string(c.port), "não", "porta UDP");
  row("threads", std::to_string(c.threads), "não", "concorrência");
  row("timeout", std::to_string(c.timeout_ms), "não", "ms por request");
  row("retries", std::to_string(c.retries), "não", "retries por request");
  row("delay", std::to_string(c.delay_ms), "não", "ms entre requests");
  row("test-write", c.test_write ? "on" : "off", "não", "ESCREVE no alvo");
  row("communities", val(c.community_file), "não", "wordlist communities");
  row("users", val(c.v3_user_file), "não", "wordlist usuários v3");
  row("audit-log", val(c.audit_path), "não", "log de auditoria");
  std::cerr << "\n   * defina range OU scope-file (pelo menos um).\n\n";
}

bool set_option(Config& c, const std::string& key, const std::string& value) {
  auto as_int = [&](int& dst) { try { dst = std::stoi(value); return true; } catch (...) { return false; } };
  if (key == "mode" || key == "version") {
    if (!parse_version(value, c.version)) { std::cerr << "versão inválida\n"; return false; }
  } else if (key == "targets" || key == "target" || key == "rhosts") {
    c.target_spec = value;
  } else if (key == "range") {
    c.scope_rule = value;
  } else if (key == "scope-file" || key == "scope") {
    c.scope_file = value;
  } else if (key == "port") {
    int p; if (!as_int(p)) return false; c.port = static_cast<uint16_t>(p);
  } else if (key == "threads") {
    int t; if (!as_int(t)) return false; c.threads = static_cast<size_t>(t);
  } else if (key == "timeout") {
    if (!as_int(c.timeout_ms)) return false;
  } else if (key == "retries") {
    if (!as_int(c.retries)) return false;
  } else if (key == "delay") {
    if (!as_int(c.delay_ms)) return false;
  } else if (key == "test-write" || key == "testwrite") {
    c.test_write = (value == "on" || value == "true" || value == "1" || value == "yes");
  } else if (key == "communities" || key == "community-file") {
    c.community_file = value;
  } else if (key == "users" || key == "v3-user-file") {
    c.v3_user_file = value;
  } else if (key == "audit-log" || key == "auditlog") {
    c.audit_path = value;
  } else {
    std::cerr << "opção desconhecida: " << key << " (use 'show' ou 'help')\n";
    return false;
  }
  std::cerr << key << " => " << (value.empty() ? "(vazio)" : value) << "\n";
  return true;
}

void unset_option(Config& c, const std::string& key) {
  if (key == "targets" || key == "target") c.target_spec.clear();
  else if (key == "range") c.scope_rule.clear();
  else if (key == "scope-file" || key == "scope") c.scope_file.clear();
  else if (key == "test-write") c.test_write = false;
  else { std::cerr << "não dá pra limpar: " << key << "\n"; return; }
  std::cerr << key << " => (vazio)\n";
}

int console(Config cfg) {
  splash();
  show_options(cfg);
  std::cerr << "digite 'help' para os comandos, 'run' para executar.\n\n";

  const bool tty = isatty(fileno(stderr));
  const std::string prompt = tty ? "\033[1;31mbixsn\033[0m > " : "bixsn > ";

  std::string line;
  while (true) {
    std::cerr << prompt;
    if (!std::getline(std::cin, line)) { std::cerr << "\n"; break; }

    std::istringstream ss(line);
    std::string cmd;
    ss >> cmd;
    if (cmd.empty()) continue;

    if (cmd == "exit" || cmd == "quit") break;
    else if (cmd == "help" || cmd == "?") console_help();
    else if (cmd == "banner") splash();
    else if (cmd == "show") show_options(cfg);
    else if (cmd == "use") {
      std::string v; ss >> v;
      if (!parse_version(v, cfg.version)) std::cerr << "uso: use v1|v2c|v3\n";
      else std::cerr << "mode => " << version_str(cfg.version) << "\n";
    } else if (cmd == "set") {
      std::string k, v;
      ss >> k;
      std::getline(ss, v);
      size_t a = v.find_first_not_of(" \t");
      v = (a == std::string::npos) ? "" : v.substr(a);
      if (k.empty()) std::cerr << "uso: set <opção> <valor>\n";
      else set_option(cfg, k, v);
    } else if (cmd == "unset") {
      std::string k; ss >> k;
      if (k.empty()) std::cerr << "uso: unset <opção>\n";
      else unset_option(cfg, k);
    } else if (cmd == "run" || cmd == "go" || cmd == "scan") {
      run_scan(cfg);
    } else {
      std::cerr << "comando desconhecido: " << cmd << " (help)\n";
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Config cfg;
  std::string data_dir = resolve_data_dir();
  cfg.community_file = data_dir + "/community-strings.txt";
  cfg.v3_user_file = data_dir + "/v3-users.txt";

  if (argc == 1) return console(cfg);

  auto need = [&](int& i) -> std::string {
    if (i + 1 >= argc) { std::cerr << "faltou valor para " << argv[i] << "\n"; exit(2); }
    return argv[++i];
  };
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    else if (a == "--scope") cfg.scope_file = need(i);
    else if (a == "--range" || a == "-r" || a == "--i-own-this-range")
      cfg.scope_rule = need(i);
    else if (a == "--community-file") cfg.community_file = need(i);
    else if (a == "--v3-user-file") cfg.v3_user_file = need(i);
    else if (a == "--audit-log") cfg.audit_path = need(i);
    else if (a == "--port") cfg.port = static_cast<uint16_t>(std::stoi(need(i)));
    else if (a == "--threads") cfg.threads = static_cast<size_t>(std::stoul(need(i)));
    else if (a == "--timeout") cfg.timeout_ms = std::stoi(need(i));
    else if (a == "--retries") cfg.retries = std::stoi(need(i));
    else if (a == "--delay") cfg.delay_ms = std::stoi(need(i));
    else if (a == "--test-write") cfg.test_write = true;
    else if (a == "--version") {
      if (!parse_version(need(i), cfg.version)) { std::cerr << "versão inválida\n"; return 2; }
    } else if (!a.empty() && a[0] == '-') {
      std::cerr << "opção desconhecida: " << a << "\n"; return 2;
    } else {
      cfg.target_spec += (cfg.target_spec.empty() ? "" : ",") + a;
    }
  }

  if (cfg.target_spec.empty()) { usage(argv[0]); return 2; }
  splash();
  return run_scan(cfg);
}
