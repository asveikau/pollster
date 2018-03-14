#include <pollster/timer.h>

pollster::timer::timer()
   : head(nullptr), last_time(0)
{
}

pollster::timer::~timer()
{
   while (head)
   {
      auto p = head;

      *p->prev = p->next;
      p->Release();
   }
}

int64_t
pollster::timer::next_timer(void)
{
   int64_t r = -1;
   if (head)
      r = head->pendingMillis;
   return r;
}

void
pollster::timer::insert(timer_node *r)
{
   r->pendingMillis = r->totalMillis;

   auto prev = &head;

   while ((*prev) && (*prev)->pendingMillis > r->pendingMillis)
   {
      r->pendingMillis -= (*prev)->pendingMillis;
      prev = &((*prev)->next);
   }

   r->prev = prev;
   r->next = *prev;
   *prev = r;
}

void
pollster::timer::add(
   uint64_t millis,
   bool repeating,
   event **ev,
   error *err
)
{
   common::Pointer<timer_node> r;

   *r.GetAddressOf() = new (std::nothrow) timer_node();
   if (!r.Get())
      ERROR_SET(err, nomem);

   r->repeat = repeating;
   r->totalMillis = millis;
   insert(r.Get());
   r->AddRef();
exit:
   if (!ERROR_FAILED(err))
      *ev = r.Detach();
}

void
pollster::timer::begin_poll(error *err)
{
   // TODO
}

void
pollster::timer::end_poll(error *err)
{
   uint64_t ellapsed = 0; // TODO

   auto prev = &head;

   while ((*prev))
   {
      auto p = *prev;

      if (ellapsed < p->pendingMillis)
      {
         p->pendingMillis -= ellapsed;
         break;
      }

      ellapsed -= p->pendingMillis;
      *prev = p->next;
      if (*prev)
         (*prev)->prev = prev;
      p->prev = nullptr;
      p->next = nullptr;

      p->signal_from_backend(false, err);

      if (ERROR_FAILED(err))
      {
         if (p->on_error)
            p->on_error(err);
         error_clear(err);
         p->repeat = false;
      }

      if (p->repeat)
         insert(p);
      else
         p->Release();
   }
}

pollster::timer_node::timer_node()
   : prev(nullptr),
     next(nullptr),
     repeat(false),
     pendingMillis(0),
     totalMillis(0)
{
}

void
pollster::timer_node::remove(error *err)
{
   if (prev)
   {
      *prev = next;
      if (*prev)
         (*prev)->prev = prev;
      prev = nullptr;
      next = nullptr;
      Release();
   }
}