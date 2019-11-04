#include <stdint.h>
#include <stdlib.h>
#include "oc_audit.h"

void oc_audit_log(char* aeid, char *message, uint8_t category, uint8_t priority, char **aux, size_t aux_len) {
  OC_ERR("audit_log: %s %s %u %u", aeid, message, category, priority);
  if (aux) {
    size_t i;
    for (i = 0; i < aux_len; ++i) {
      OC_ERR("audit_log: %s", aux[i]);
      free(aux[i]);
    }
    free(aux);
  }
}
