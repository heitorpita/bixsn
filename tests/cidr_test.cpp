// Teste do módulo cidr sem framework externo: asserts simples + contador.
#include "../src/net/cidr.h"

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

using bixsn::net::expand_target;
using bixsn::net::expand_targets;
using bixsn::net::ipv4_to_string;
using bixsn::net::parse_ipv4;

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
  uint32_t v = 0;
  CHECK(parse_ipv4("10.0.0.1", v) && v == 0x0A000001u);
  CHECK(parse_ipv4("255.255.255.255", v) && v == 0xFFFFFFFFu);
  CHECK(parse_ipv4("0.0.0.0", v) && v == 0);
  CHECK(!parse_ipv4("10.0.0.256", v));
  CHECK(!parse_ipv4("10.0.0", v));
  CHECK(!parse_ipv4("10.0.0.1 ", v));
  CHECK(!parse_ipv4("a.b.c.d", v));
  CHECK(ipv4_to_string(0x0A000001u) == "10.0.0.1");

  // IP único
  auto one = expand_target("192.168.1.10");
  CHECK(one.size() == 1 && one[0] == "192.168.1.10");

  // /24 exclui rede e broadcast => 254 hosts
  auto c24 = expand_target("10.0.0.0/24");
  CHECK(c24.size() == 254);
  CHECK(c24.front() == "10.0.0.1");
  CHECK(c24.back() == "10.0.0.254");

  // /30 => 2 hosts úteis
  auto c30 = expand_target("10.0.0.0/30");
  CHECK(c30.size() == 2 && c30[0] == "10.0.0.1" && c30[1] == "10.0.0.2");

  // /31 => 2 endereços (RFC 3021)
  auto c31 = expand_target("10.0.0.0/31");
  CHECK(c31.size() == 2 && c31[0] == "10.0.0.0" && c31[1] == "10.0.0.1");

  // /32 => 1 endereço
  auto c32 = expand_target("10.0.0.5/32");
  CHECK(c32.size() == 1 && c32[0] == "10.0.0.5");

  // range completo
  auto r = expand_target("10.0.0.10-10.0.0.12");
  CHECK(r.size() == 3 && r[0] == "10.0.0.10" && r[2] == "10.0.0.12");

  // range curto
  auto rs = expand_target("10.0.0.1-3");
  CHECK(rs.size() == 3 && rs[0] == "10.0.0.1" && rs[2] == "10.0.0.3");

  // múltiplos + dedup
  auto multi = expand_targets("10.0.0.1, 10.0.0.1, 10.0.0.2");
  CHECK(multi.size() == 2);

  // erros
  CHECK(throws([] { expand_target("10.0.0.0/33"); }));
  CHECK(throws([] { expand_target("10.0.0.0/24", 10); }));  // excede max_hosts
  CHECK(throws([] { expand_target("10.0.0.50-10.0.0.10"); }));  // invertido
  CHECK(throws([] { expand_target("not.an.ip"); }));

  std::cout << "cidr_test: " << g_pass << " passaram, " << g_fail
            << " falharam\n";
  return g_fail == 0 ? 0 : 1;
}
