
#ifndef AMEGER_OFFSETS_H
#define AMEGER_OFFSETS_H

#define AMEGER_CHANNEL_USER_VA_CANONICAL      0x00007FF000000000ULL
#define AMEGER_SELFTEST_ACK_OFFSET_CANONICAL  0x78ULL

#ifdef AMEGER_CHANNEL_USER_VA
#  if AMEGER_CHANNEL_USER_VA != AMEGER_CHANNEL_USER_VA_CANONICAL
#    error "AMEGER_CHANNEL_USER_VA was overridden by the build system; \
this is a silent-failure risk. Remove the -D and consume the header value."
#  endif
#else
#  define AMEGER_CHANNEL_USER_VA  AMEGER_CHANNEL_USER_VA_CANONICAL
#endif

#ifdef AMEGER_SELFTEST_ACK_OFFSET
#  if AMEGER_SELFTEST_ACK_OFFSET != AMEGER_SELFTEST_ACK_OFFSET_CANONICAL
#    error "AMEGER_SELFTEST_ACK_OFFSET was overridden; this is a silent-failure risk."
#  endif
#else
#  define AMEGER_SELFTEST_ACK_OFFSET  AMEGER_SELFTEST_ACK_OFFSET_CANONICAL
#endif

#endif
