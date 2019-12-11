#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define STDIN_FILENO 0

#define MAX_LINE_LEN 256

typedef struct cb_arg {
  char query[MAX_LINE_LEN];
  char verbose;
  char pending;
  char gotdata;
} cb_arg_t;

short max_queued = 1024;

int us_delay = 10000;
struct timeval maxtv;

int queued  = 0;
int version = 0;

unsigned int responses = 0;

int set_nb(int fd) {
  int flags;

  /* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
  /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
  if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
    flags = 0;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
  /* Otherwise, use the old way of doing it */
  flags = 1;
  return ioctl(fd, FIOBIO, &flags);
#endif
}

unsigned int line_buffer_fill = 0;
unsigned int line_buffer_chkd = 0;
char line_buffer[MAX_LINE_LEN*2];

#define NBRL_WAIT     0
#define NBRL_GOTLINE  1
#define NBRL_EOF     -1
#define NBRL_ERR     -2

int nb_readline(char *line) {
  int l;
  fd_set fds;
  struct timeval tv;

  if (line_buffer_fill > line_buffer_chkd) {
    for (;line_buffer_chkd<line_buffer_fill;line_buffer_chkd++) {
      /* check for existing eol */
      if (line_buffer[line_buffer_chkd] == '\n') {
        goto gotline;
      }
    }
  }
  
  tv.tv_sec  = 0;
  tv.tv_usec = us_delay;
  FD_ZERO(&fds);
  FD_SET(STDIN_FILENO, &fds);
  if (select(1, &fds, NULL, NULL, &tv)) {
    /* assume this means stdin is ready */
    if ((l = read(STDIN_FILENO, line_buffer + line_buffer_chkd, MAX_LINE_LEN - line_buffer_fill)) > 0) {
      line_buffer_fill += l; /* bytes read */
      for (;line_buffer_chkd<line_buffer_fill;line_buffer_chkd++) {
        /* check for eol */
        if (line_buffer[line_buffer_chkd] == '\n') {
          gotline:
          line_buffer[line_buffer_chkd] = '\0';
          line_buffer_chkd++;
          memcpy(line, line_buffer, line_buffer_chkd);
          line_buffer_fill -= line_buffer_chkd;
          memcpy(line_buffer, line_buffer + line_buffer_chkd, line_buffer_fill);
          line_buffer[line_buffer_fill] = '\0';
          line_buffer_chkd = 0;
          return NBRL_GOTLINE;
        }
      }
      if (line_buffer_chkd >= MAX_LINE_LEN) {
        fprintf(stderr, "nb_readline - line too long\n");
      }
      return NBRL_WAIT;
    } else if (l == 0) {
      fprintf(stderr, "read failed, errno=%d '%s'\n", errno, strerror(errno));
      return NBRL_EOF;
    } else {
      return NBRL_ERR;
    }
  } else {
    return NBRL_WAIT;
  }
  fprintf(stderr, "nb_readline - line too long or bug\n");
  abort();
}

void dns_callback_gethostbyname(void *cb_arg, int status, int timeouts, struct hostent *host) {
  char ip[INET6_ADDRSTRLEN];
  cb_arg_t *arg = cb_arg;

  queued--;
  responses++;
  arg->pending -= 1;

  if (arg->verbose) {
    printf("CALLBACK[%04d]: %s\n", queued, arg->query);
  }

  if (status != ARES_SUCCESS) {
    if (timeouts > 3) {
      printf("FAIL\t%s\tTimeout\n", arg->query);
    } else {
      if (status != ARES_ENODATA || (arg->pending == 0 && arg->gotdata == 0)) {
        printf("FAIL\t%s\t%s (%d)\n", arg->query, ares_strerror(status), status);
      }
    }
    goto dns_cb_ghbn_cleanup;
  }

  int i = 0;
  while (host->h_addr_list[i] != NULL) {
    arg->gotdata = 1;
    inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
    printf("OKAY\t%s\t%s\n", arg->query, ip);
    ++i;
  }
dns_cb_ghbn_cleanup:
  if (arg->pending == 0) {
    free(arg);
  } else if (arg->pending != 1) {
    fprintf(stderr, "WARN %s pending=%d\n", arg->query, arg->pending);
  }
}


void dns_callback_gethostbyaddr(void *cb_arg, int status, int timeouts, struct hostent *host) {
  cb_arg_t *arg = cb_arg;

  queued--;
  responses++;

  if (arg->verbose) {
    printf("CALLBACK[%04d]: %s\n", queued, arg->query);
  }
  
  if (status != ARES_SUCCESS) {
    if (timeouts > 3) {
      printf("FAIL\t%s\tTimeout\n", arg->query);
    } else {
      printf("FAIL\t%s\t%s (%d)\n", arg->query, ares_strerror(status), status);
    }
    free(arg);
    return;
  }

  if (version < 0x010600) {
    printf("OKAY\t%s\t%s\n", arg->query, host->h_name);
  } else { // Old versions of c-ares don't populate host->h_aliases
    int i = 0;
    while (host->h_aliases[i] != NULL) {
      printf("OKAY\t%s\t%s\n", arg->query, host->h_aliases[i]);
      ++i;
    }
  }
  free(arg);
}

void usage(char *name) {
  fprintf(stderr, "Usage: %s (-r|-f) [OPTIONS...]\n\n\
 -r                          Do reverse (PTR) lookups.\n\
 -f                          Do forward (A/AAAA) lookups.\n\
 -4                          Do IPv4 lookups in forward mode. (default)\n\
 -6                          Do IPv6 lookups in forward mode. This disables\n\
                             IPv4 unless -4 is also specified.\n\
 -T                          Always use TCP instead of UDP for queries.\n\
 -n MAX_QUEUE                Specify maximum size of query queue.\n\
 -S SERVERS                  Use specific DNS servers (comma seperated)\n\
                             instead system defaults.\n\
 -v                          Verbose mode. Repeat for more verbosity\n\
 -h                          Show this screen.\n",
  name);
}

int main (int argc, char **argv) {
  char line[MAX_LINE_LEN] = "";
  int nfds, ready, res, i;
  int nbrl = 0;

  char *endptr;
  int optnr;

  struct timeval tv, *tvp;

  int ip_fam, ip_len;
  struct in6_addr ip;

  struct ares_options options;
  int optmask = 0;

  char *servers = NULL;

  char forward = 0, reverse = 0, verbose = 0, qrv4 = 1, qrv6 = 0;

  ares_channel channel;
  fd_set readers, writers;

  maxtv.tv_sec  = 0;
  maxtv.tv_usec = us_delay;


  set_nb(STDIN_FILENO);

#ifdef CARES_HAVE_ARES_LIBRARY_INIT
  if ((res = ares_library_init(ARES_LIB_INIT_ALL)) != ARES_SUCCESS) {
    fprintf(stderr, "ares_library_init failed: %s\n", ares_strerror(res));
    return 1;
  }
#endif
  ares_version(&version);
  if (version < 0x010600) {
    fprintf(stderr,
            "WARNING: c-ares v%d.%d.%d < v1.6.0; No support for IPs with multiple hostnames\n",
            version>>16&255, version>>8&255, version&255);
  }

  while( (optnr = getopt(argc, argv, "n:S:rfvT46h")) != -1 ) {
    switch(optnr) {
      case '4':
        qrv4 = 3;
        if (qrv6 == 1) { qrv6 = 0; }
        break;
      case '6':
        qrv6 = 3;
        if (qrv4 == 1) { qrv4 = 0; }
        break;
      case 'T':
        options.flags |= ARES_FLAG_USEVC;
        break;
      case 'v':
        if (verbose < 7) { ++verbose; }
        break;
      case 'r':
        reverse = 1;
        break;
      case 'f':
        forward = 1;
        break;
      case 'n':
        max_queued = strtoul(optarg, &endptr, 10);
        break;
      case 'S':
        servers = optarg;
        break;
      case 'h':
        usage(argv[0]);
        return 1;
        break;
    }
  }

  if (forward == reverse) {
    fprintf(stderr, "must specific exactly one of `-f` or `-r`\n");
    return 1;
  }

  if (reverse && (qrv4 > 1 || qrv6 > 1)) {
    fprintf(stderr, "WARNING: `-4` and `-6` ignored in reverse mode\n");
  }

  options.timeout = 2500;
  optmask |= ARES_OPT_TIMEOUTMS;

  options.ndots = 0;
  optmask |= ARES_OPT_NDOTS;

  options.flags |= ARES_FLAG_NOSEARCH;
  options.flags |= ARES_FLAG_NOALIASES;
  optmask |= ARES_OPT_FLAGS;
  
  optmask |= ARES_OPT_ROTATE;

  if((res = ares_init_options(&channel, &options, optmask)) != ARES_SUCCESS) {
    fprintf(stderr, "ares_init_options failed: %s\n", ares_strerror(res));
    return 1;
  }

  if (servers != NULL) {
    if ((res = ares_set_servers_csv(channel, servers)) != ARES_SUCCESS) {
      fprintf(stderr, "ares_set_servers_csv failed: %s\n", ares_strerror(res));
      return 1;
    }
  }

  for (;;) {
    // See if we can issue more requests
    if (queued < max_queued && nbrl >= 0) {
      if ((nbrl = nb_readline(line)) > 0) {
        cb_arg_t *arg;
        arg = malloc(sizeof(cb_arg_t));
        if (arg == NULL) {
          fprintf(stderr, "Malloc failed!");
          return 2;
        }
        strncpy(arg->query, line, MAX_LINE_LEN);
        arg->pending = arg->gotdata = 0;
        arg->verbose = verbose;
        if (reverse) {
          // figure out if this is a v6 or v4 address and parse
          for (i = 0; line[i] > 0 && i < 5; ++i) {
            if (line[i++] == ':') {
              ip_len = 16; ip_fam = AF_INET6;
              res = inet_pton(AF_INET6, line, &ip);
              goto ip_parsed;
            }
          }
          ip_len = 4; ip_fam = AF_INET;
          res = inet_aton(line, (struct in_addr *)&ip);

          ip_parsed:
          ares_gethostbyaddr(channel, &ip, ip_len, ip_fam, dns_callback_gethostbyaddr, arg);
          queued++;
          if (verbose) printf("QUEUE R [%04d]: %s\n", queued, line);
        } else if (forward) {
          // need to set the pending value before starting any queries
          if (qrv4) { arg->pending += 1; }
          if (qrv6) { arg->pending += 1; }
          // okay, *now* run queries
          if (qrv4) {
            ares_gethostbyname(channel, (char *)&line, AF_INET,  dns_callback_gethostbyname, arg);
            queued++;
            if (verbose) printf("QUEUE 4 [%04d]: %s\n", queued, line);
          }
          if (qrv6) {
            ares_gethostbyname(channel, (char *)&line, AF_INET6, dns_callback_gethostbyname, arg);
            queued++;
            if (verbose) printf("QUEUE 6 [%04d]: %s\n", queued, line);
          }
        }
      } else if (nbrl == NBRL_ERR) {
        fprintf(stderr, "Error reading stdin\n");
        return 3;
      }
    } else if (queued == 0) {
      return 0;
    }

    FD_ZERO(&readers);
    FD_ZERO(&writers);
    nfds = ares_fds(channel, &readers, &writers);
    if (nfds != 0) {
      if (nbrl >= 0 && queued < max_queued) {
        // limit how long we wait if we could be making another request
        tvp = ares_timeout(channel, &maxtv, &tv);
      } else {
        tvp = ares_timeout(channel, NULL, &tv);
      }
      ready = select(nfds, &readers, &writers, NULL, tvp);
      if (ready < 0) {
        fprintf(stderr, "Error in select()\n");
      }
      // Wait for queries to finish
      ares_process(channel, &readers, &writers);
    }
  }
  return 0;
}

// vim: ts=2 sw=2 et ai si
