#include <pollster/messagequeue.h>

pollster::message_queue::message_queue() : init(false)
{
}

void
pollster::message_queue::initialize(error *err)
{
   if (mutex_init(&lock))
      ERROR_SET(err, unknown, "mutex init failed");
   init = true;
exit:;
}

pollster::message_queue::~message_queue()
{
   if (init)
      mutex_destroy(&lock);
}

namespace
{
   class locker
   {
      mutex *m;
      bool locked;
   public:
      locker(mutex &m_) : m(&m_), locked(false) {}
      locker(mutex *m_) : m(m_), locked(false) {}
      locker(const locker&) = delete;
      ~locker() { unlock(); }

      void lock() { mutex_acquire(m); locked = true; }
      void unlock() { if (locked) { mutex_release(m); locked = false; } }
   };
}

void
pollster::message_queue::synchronize(std::function<void(void)> op)
{
   locker l(lock);

   l.lock();
   op();
}

void
pollster::message_queue::drain(error *err)
{
   std::vector<std::function<void(error*)>> queueDrain;
   locker l(lock);

   l.lock();
   std::swap(queueDrain, queue);
   l.unlock();

   for (auto &fn : queueDrain)
   {
      fn(err);
      ERROR_CHECK(err);
   }
exit:;
}

bool
pollster::message_queue::enqueue_work(std::function<void(error*)> func, bool &shutdown, error *err)
{
   locker l(lock);
   bool r = false;

   l.lock();
   auto wasEmpty = !queue.size();
   if (shutdown)
      goto exit;
   try
   {
      queue.push_back(func);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
   if (wasEmpty && on_enqueue)
      on_enqueue(err);
   r = true;
exit:
   return r;
}

bool
pollster::message_queue::is_empty()
{
   return !queue.size();
}