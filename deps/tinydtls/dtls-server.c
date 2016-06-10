#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>

#include "tinydtls.h"
#include "dtls.h"
#include "debug.h"


#define DEFAULT_PORT 20220



#define DTLS_SERVER_CMD_CLOSE "server:close"
#define DTLS_SERVER_CMD_RENEGOTIATE "server:renegotiate"

static int
read_from_peer(struct dtls_context_t *ctx,
	       session_t *session, uint8 *data, size_t len) {
  printf("Read data\n");
  size_t i;
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  return 0;//dtls_write(ctx, session, data, len);
}

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {
  printf("Sending encrypted data\n");
  int fd = *(int *)dtls_get_app_data(ctx);
  return sendto(fd, data, len, MSG_DONTWAIT,
		&session->addr.sa, session->size);
}

static int
dtls_handle_read(struct dtls_context_t *ctx) {
  int *fd;
  session_t session;
  static uint8 buf[DTLS_MAX_BUF];
  int len;

  fd = dtls_get_app_data(ctx);

  assert(fd);

  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);
  len = recvfrom(*fd, buf, sizeof(buf), MSG_TRUNC,
		 &session.addr.sa, &session.size);

  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dtls_debug("got %d bytes from port %d\n", len, 
	     ntohs(session.addr.sin6.sin6_port));
    if ((int)(sizeof(buf)) < len) {
      dtls_warn("packet was truncated (%d bytes lost)\n", len - sizeof(buf));
    }
  }

  int err = dtls_handle_message(ctx, &session, buf, len);
  printf("handle_message return code: %d\n", err);
  return err;
}

static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
};

int
main(int argc, char **argv) {
  dtls_context_t *the_context = NULL;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, result;
  int on = 1;
  struct sockaddr_in6 listen_addr;

  memset(&listen_addr, 0, sizeof(struct sockaddr_in6));


  listen_addr.sin6_family = AF_INET6;
  listen_addr.sin6_port = htons(56789);
  listen_addr.sin6_addr = in6addr_any;
 
  /* init socket and set it to non-blocking */
  fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

  if (fd < 0) {
    dtls_alert("socket: %s\n", strerror(errno));
    return 0;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dtls_alert("setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }

  if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
    dtls_alert("bind: %s\n", strerror(errno));
    goto error;
  }

  dtls_init();

  the_context = dtls_new_context(&fd);

  /* enable/disable tls_ecdh_anon_with_aes_128_cbc_sha_256 */
  dtls_enables_anon_ecdh(the_context, DTLS_CIPHER_ENABLE);

  dtls_set_handler(the_context, &cb);

  while (1) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fd, &rfds);
    /* FD_SET(fd, &wfds); */
    
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    result = select( fd+1, &rfds, &wfds, 0, &timeout);
    
    if (result < 0) {		/* error */
      if (errno != EINTR)
	perror("select");
    } else if (result == 0) {	/* timeout */
    } else {			/* ok */
      if (FD_ISSET(fd, &wfds))
	;
      else if (FD_ISSET(fd, &rfds)) {
	dtls_handle_read(the_context);
      }
    }
  }
  
 error:
  dtls_free_context(the_context);
  exit(0);
}
