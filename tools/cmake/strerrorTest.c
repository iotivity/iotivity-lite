#ifdef HAVE_GLIBC_STRERROR_R
#include <string.h>
#include <errno.h>

static void
check(char c)
{
  // no-op
}

int
main()
{
  char buffer[256];
  // This will not compile if strerror_r does not return a char*
  check(strerror_r(EINVAL, buffer, sizeof(buffer))[0]);
  return 0;
}
#endif // HAVE_GLIBC_STRERROR_R

#ifdef HAVE_POSIX_STRERROR_R
#include <string.h>
#include <errno.h>

// because a pointer can't be implicitly cast to float
static void
check(float f)
{
  // no-op
}

int
main()
{
  char buffer[256];
  // This will not compile if strerror_r does not return an int
  check(strerror_r(EINVAL, buffer, sizeof(buffer)));
  return 0;
}
#endif // HAVE_POSIX_STRERROR_R
