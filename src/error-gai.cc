#include <pollster/socket.h>

#define ERROR_SRC_GAI \
   (error_source)(('g' | (((unsigned)'a') << 8) | (((unsigned)'i') << 16)))

void
pollster::error_set_gai(error *err, int r)
{
   error_clear(err);
   err->source = ERROR_SRC_GAI;
   err->code = r;
   err->get_string = [] (error *err) -> const char *
   {
      return gai_strerror(err->code);
   };
}