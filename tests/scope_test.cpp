// Teste do módulo scope sem framework externo: asserts simples + contador.
// Escopo é a barreira de autorização; erra aqui = agir fora do permitido.
#include "../src/safety/scope.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond)                                                       \
  do {                                                                    \
    if (cond) {                                                           \
      ++g_pass;                                                           \
    } else {                                                              \
      ++g_fail;                                                           \
      std::cerr << "FAIL: " << #cond << " (" << __FILE__ << ":" << __LINE__ \
                << ")\n";                                                 \
    }                                                                     \
  } while (0)

using bixsn::safety::Scope;

template <typename F>
static bool throws(F f) {
  try {
    f();
  } catch (const std::exception&) {
    return true;
  }
  return false;
}

int main() {
  // Sem regras: nada está em escopo (fail-closed).
  Scope empty;
  CHECK(empty.empty());
  CHECK(!empty.in_scope("10.0.0.1"));

  // IP único.
  Scope s;
  s.add_rule("10.0.0.5");
  CHECK(!s.empty() && s.rule_count() == 1);
  CHECK(s.in_scope("10.0.0.5"));
  CHECK(!s.in_scope("10.0.0.6"));

  // CIDR: rede e broadcast também contam como "em escopo" (é autorização, não
  // enumeração de hosts — quem escaneia é o cidr).
  Scope c;
  c.add_rule("192.168.1.0/24");
  CHECK(c.in_scope("192.168.1.0"));
  CHECK(c.in_scope("192.168.1.1"));
  CHECK(c.in_scope("192.168.1.255"));
  CHECK(!c.in_scope("192.168.2.1"));

  // Range completo e range curto.
  Scope r;
  r.add_rule("10.1.1.10-10.1.1.20");
  r.add_rule("10.2.2.1-5");
  CHECK(r.in_scope("10.1.1.10") && r.in_scope("10.1.1.20"));
  CHECK(!r.in_scope("10.1.1.21"));
  CHECK(r.in_scope("10.2.2.5") && !r.in_scope("10.2.2.6"));

  // /32 e /0.
  Scope host32;
  host32.add_rule("172.16.0.1/32");
  CHECK(host32.in_scope("172.16.0.1") && !host32.in_scope("172.16.0.2"));
  Scope all;
  all.add_rule("0.0.0.0/0");
  CHECK(all.in_scope("8.8.8.8") && all.in_scope("255.255.255.255"));

  // IP malformado nunca está em escopo.
  CHECK(!s.in_scope("10.0.0.256"));
  CHECK(!s.in_scope("nope"));

  // Regras malformadas lançam.
  CHECK(throws([] { Scope x; x.add_rule("10.0.0.0/33"); }));
  CHECK(throws([] { Scope x; x.add_rule("10.0.0.50-10.0.0.10"); }));  // invertido
  CHECK(throws([] { Scope x; x.add_rule("not.an.ip"); }));

  // load_file: lê CIDRs/ranges, ignora comentários e linhas em branco.
  {
    char tmpl[] = "/tmp/bixsn_scope_XXXXXX";
    int fd = mkstemp(tmpl);
    CHECK(fd >= 0);
    {
      std::ofstream out(tmpl);
      out << "# escopo de teste\n";
      out << "10.0.0.0/30\n";
      out << "   \n";                 // branco
      out << "192.168.0.1  # inline\n";
    }
    Scope f;
    f.load_file(tmpl);
    CHECK(f.rule_count() == 2);
    CHECK(f.in_scope("10.0.0.2") && f.in_scope("192.168.0.1"));
    CHECK(!f.in_scope("192.168.0.2"));
    std::remove(tmpl);
  }

  // load_file inexistente lança runtime_error; linha ruim reporta o número.
  CHECK(throws([] { Scope x; x.load_file("/nao/existe/escopo.txt"); }));

  std::cout << "scope_test: " << g_pass << " passaram, " << g_fail
            << " falharam\n";
  return g_fail == 0 ? 0 : 1;
}
