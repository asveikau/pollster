#include <pollster/backends.h>

struct backend_factory
{
   void (*fn)(pollster::waiter **, error *err);
};

void
pollster::create(waiter **w, error *err)
{
   static const backend_factory backends[] =
   {
#if defined(USE_KQUEUE)
      {create_kqueue},
#endif
      {nullptr}
   };
   *w = nullptr;
   for (auto f = backends; f->fn; ++f)
   {
      f->fn(w, err);
      if (ERROR_FAILED(err))
         error_clear(err);
      else
         break;
   }
   if (!*w)
      ERROR_SET(err, unknown, "could not create backend object");
exit:;
}
