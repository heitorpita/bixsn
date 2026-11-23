#include "thread_pool.h"

namespace bixsn::net {

ThreadPool::ThreadPool(size_t num_threads, std::chrono::microseconds min_gap)
    : min_gap_(min_gap) {
  if (num_threads == 0) num_threads = 1;
  workers_.reserve(num_threads);
  for (size_t i = 0; i < num_threads; ++i)
    workers_.emplace_back([this] { worker_loop(); });
}

ThreadPool::~ThreadPool() {
  {
    std::lock_guard<std::mutex> lk(mtx_);
    stop_ = true;
  }
  cv_.notify_all();
  for (auto& t : workers_)
    if (t.joinable()) t.join();
}

void ThreadPool::submit(std::function<void()> task) {
  {
    std::lock_guard<std::mutex> lk(mtx_);
    tasks_.push(std::move(task));
  }
  cv_.notify_one();
}

void ThreadPool::throttle() {
  if (min_gap_.count() == 0) return;
  std::lock_guard<std::mutex> lk(gap_mtx_);
  auto now = std::chrono::steady_clock::now();
  if (next_slot_ > now) std::this_thread::sleep_until(next_slot_);
  next_slot_ = std::max(now, next_slot_) + min_gap_;
}

void ThreadPool::worker_loop() {
  for (;;) {
    std::function<void()> task;
    {
      std::unique_lock<std::mutex> lk(mtx_);
      cv_.wait(lk, [this] { return stop_ || !tasks_.empty(); });
      if (stop_ && tasks_.empty()) return;
      task = std::move(tasks_.front());
      tasks_.pop();
      ++active_;
    }
    throttle();
    try {
      task();
    } catch (...) {
      // Uma tarefa não pode derrubar o worker; erros são tratados nas tarefas.
    }
    {
      std::lock_guard<std::mutex> lk(mtx_);
      --active_;
      if (tasks_.empty() && active_ == 0) idle_cv_.notify_all();
    }
  }
}

void ThreadPool::wait_idle() {
  std::unique_lock<std::mutex> lk(mtx_);
  idle_cv_.wait(lk, [this] { return tasks_.empty() && active_ == 0; });
}

}  // namespace bixsn::net
