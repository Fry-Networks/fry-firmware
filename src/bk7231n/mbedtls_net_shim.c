// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
/* LibreTiny's MbedTLSClient calls mbedtls_net_set_nonblock(), which the Beken SDK's mbedtls port does not define (its
 * tls_net.c has the function commented out and keeps only net_set_nonblock(int fd), line 492). Without this, every HTTPS
 * build of the BK7231N fails to link with "undefined reference to mbedtls_net_set_nonblock". The shim is that commented-out
 * function over the SDK's fd helper; the context type is the SDK's own (mbedtls_net_context is { int fd; }, tls_net.h). */
typedef struct {
  int fd;
} fry_mbedtls_net_context;

extern int net_set_nonblock(int fd);

int mbedtls_net_set_nonblock(fry_mbedtls_net_context *ctx) {
  return net_set_nonblock(ctx->fd);
}
#endif  // FRY_BOARDS_PORT
