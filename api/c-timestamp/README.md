[![Build Status](https://travis-ci.org/chansen/c-timestamp.png?branch=master)](https://travis-ci.org/chansen/c-timestamp) [![Coverage Status](https://coveralls.io/repos/chansen/c-timestamp/badge.png)](https://coveralls.io/r/chansen/c-timestamp)

timestamp
=========


```c

typedef struct {
    int64_t sec;    /* Number of seconds since the epoch of 1970-01-01T00:00:00Z */
    int32_t nsec;   /* Nanoseconds [0, 999999999] */
    int16_t offset; /* Offset from UTC in minutes [-1439, 1439] */
} timestamp_t;

int         timestamp_parse            (const char *str, size_t len, timestamp_t *tsp);
size_t      timestamp_format           (char *dst, size_t len, const timestamp_t *tsp);
size_t      timestamp_format_precision (char *dst, size_t len, const timestamp_t *tsp, int precision);
int         timestamp_compare          (const timestamp_t *tsp1, const timestamp_t *tsp2);
bool        timestamp_valid            (const timestamp_t *tsp);
struct tm * timestamp_to_tm_utc        (const timestamp_t *tsp, struct tm *tmp);
struct tm * timestamp_to_tm_local      (const timestamp_t *tsp, struct tm *tmp);


```

