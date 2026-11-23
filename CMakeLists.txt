cmake_minimum_required(VERSION 3.16)
project(bixsn LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

# --- Descobre o Net-SNMP via net-snmp-config (vem com libsnmp-dev) ---
find_program(NETSNMP_CONFIG net-snmp-config)
if(NOT NETSNMP_CONFIG)
  message(FATAL_ERROR
    "net-snmp-config não encontrado. Instale: sudo apt-get install libsnmp-dev")
endif()

execute_process(COMMAND ${NETSNMP_CONFIG} --cflags
  OUTPUT_VARIABLE NETSNMP_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
# --netsnmp-libs traz libnetsnmp (sem a parte de agente, que não usamos)
execute_process(COMMAND ${NETSNMP_CONFIG} --netsnmp-libs
  OUTPUT_VARIABLE NETSNMP_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${NETSNMP_CONFIG} --external-libs
  OUTPUT_VARIABLE NETSNMP_EXT_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE)
separate_arguments(NETSNMP_CFLAGS)
separate_arguments(NETSNMP_LIBS)
separate_arguments(NETSNMP_EXT_LIBS)

find_package(Threads REQUIRED)

# --- Biblioteca com a lógica (compartilhada entre app e testes) ---
add_library(bixsn_core STATIC
  src/net/cidr.cpp
  src/net/thread_pool.cpp
  src/core/target.cpp
  src/core/result.cpp
  src/core/snmp_session.cpp
  src/discovery/discovery.cpp
  src/brute/community_brute.cpp
  src/brute/v3_enum.cpp
  src/collect/walk.cpp
  src/report/reporter.cpp
  src/safety/scope.cpp
  src/safety/audit_log.cpp
)
target_include_directories(bixsn_core PUBLIC src)
target_compile_options(bixsn_core PUBLIC ${NETSNMP_CFLAGS})
target_link_libraries(bixsn_core PUBLIC
  ${NETSNMP_LIBS} ${NETSNMP_EXT_LIBS} Threads::Threads)

# --- Executável CLI ---
add_executable(bixsn src/main.cpp)
target_link_libraries(bixsn PRIVATE bixsn_core)

# --- Testes ---
enable_testing()
add_executable(cidr_test tests/cidr_test.cpp)
target_link_libraries(cidr_test PRIVATE bixsn_core)
add_test(NAME cidr_test COMMAND cidr_test)

add_executable(scope_test tests/scope_test.cpp)
target_link_libraries(scope_test PRIVATE bixsn_core)
add_test(NAME scope_test COMMAND scope_test)
