#pragma once
// Pool de threads com limite de concorrência e rate limiter opcional (delay
// mínimo entre o início de tarefas), para não floodar os agentes SNMP.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace bixsn::net {

class ThreadPool {
 public:
  // num_threads workers; min_gap = intervalo mínimo entre despachos de tarefa
  // (0 = sem rate limit). Equivale ao -d do braa, mas global ao pool.
  explicit ThreadPool(size_t num_threads,
                      std::chrono::microseconds min_gap = std::chrono::microseconds{0});
  ~ThreadPool();

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;

  void submit(std::function<void()> task);

  // Bloqueia até a fila esvaziar e todas as tarefas em voo terminarem.
  void wait_idle();

 private:
  void worker_loop();
  void throttle();

  std::vector<std::thread> workers_;
  std::queue<std::function<void()>> tasks_;
  std::mutex mtx_;
  std::condition_variable cv_;          // acorda workers
  std::condition_variable idle_cv_;     // sinaliza wait_idle
  bool stop_ = false;
  size_t active_ = 0;                   // tarefas em execução

  // rate limiter
  std::chrono::microseconds min_gap_;
  std::mutex gap_mtx_;
  std::chrono::steady_clock::time_point next_slot_{};
};

}  // namespace bixsn::net
