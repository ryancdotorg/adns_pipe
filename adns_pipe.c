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

#define MAX_LINE_LEN    64

short max_queued    = 1024;

int us_delay         = 10000;
struct timeval maxtv;


int queued  = 0;
int version = 0;

unsigned int responses = 0;

int readline(char *line, int size) {
  if (queued >= max_queued) {
    return 0;
  }
  if (fgets(line, size, stdin)) {
    char *newline = strchr(line, '\n'); // look for end of line
    if (newline) {
      *newline = '\0'; // change to end of string
      return 1;
    }
  }
  line = NULL;
  return 0;
}

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

  //printf("line_buffer 1: %2d %2d %s\n", line_buffer_chkd, line_buffer_fill, line_buffer);

  if (line_buffer_fill > line_buffer_chkd) {
    for (;line_buffer_chkd<line_buffer_fill;line_buffer_chkd++) {
      /* check for existing eol */
      //printf("line_buffer 2: %2d %2d %s\n", line_buffer_chkd, line_buffer_fill, line_buffer);
      if (line_buffer[line_buffer_chkd] == '\n') {
        goto gotline;
      }
    }
  }
  
  //printf("line_buffer 3: %2d %2d %s\n", line_buffer_chkd, line_buffer_fill, line_buffer);

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
        //printf("line_buffer 4: %2d %2d %s\n", line_buffer_chkd, line_buffer_fill, line_buffer);
        if (line_buffer[line_buffer_chkd] == '\n') {
          gotline:
          line_buffer[line_buffer_chkd] = '\0';
          line_buffer_chkd++;
          memcpy(line, line_buffer, line_buffer_chkd);
          line_buffer_fill -= line_buffer_chkd;
          memcpy(line_buffer, line_buffer + line_buffer_chkd, line_buffer_fill);
          line_buffer[line_buffer_fill] = '\0';
          line_buffer_chkd = 0;
          //printf("line_buffer 5: %2d %2d %s\n", line_buffer_chkd, line_buffer_fill, line_buffer);
          //printf("line_buffer r: %s\n", line);
          return NBRL_GOTLINE;
        }
      }
      return NBRL_WAIT;
    } else if (l == 0) {
      fprintf(stderr, "Got EoF\n");
      return NBRL_EOF;
    } else {
      return NBRL_ERR;
    }
  } else {
    return NBRL_WAIT;
  }
  fprintf(stderr, "nb_readline - line too long or bug\n");
  exit(1);
}

void dns_callback_gethostbyaddr(void *arg, int status, int timeouts, struct hostent *host) {
  queued--;
  responses++;
  
  if (status != ARES_SUCCESS) {
    if (status != ARES_ENOTFOUND) {
      printf("CALLBACK[%04d]: %s ERROR: %d\n", queued, (char *)arg, status);
    }
    if (timeouts > 3) {
      printf("CALLBACK[%04d]: %s ERROR: TIMEOUT\n", queued, (char *)arg);      
    }
    free(arg);
    return;
  }

  if (version < 0x010600) {
    printf("CALLBACK[%04d]: %s %s\n", queued, (char *)arg, host->h_name);
  } else { // Old versions of c-ares don't populate host->h_aliases
    int i = 0;
    while (host->h_aliases[i] != NULL) {
      printf("CALLBACK[%04d]: %s %s\n", queued, (char *)arg, host->h_aliases[i]);
      i++;
    }
  }
  free(arg);
}

/*
void dns_callback_query(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  queued--;
  responses++;

  if (status != ARES_SUCCESS) {
    if (status != ARES_ENOTFOUND) {
      printf("CALLBACK[%04d]: %s ERROR: %d\n", queued, (char *)arg, status);
    }
    free(arg);
    return;
  }
  
  int res;
  res = ares_parse_ptr_reply(abuf, alen, NULL, 0, 0, NULL);
}
*/

int main (int argc, char **argv) {
  char line[MAX_LINE_LEN] = "";
  int nfds, count, res;
  int nbrl = 0;

  struct timeval tv, *tvp;
  struct in_addr ip;

  struct ares_options options;
  int optmask = 0;

  ares_channel channel;
  fd_set readers, writers;

  maxtv.tv_sec  = 0;
  maxtv.tv_usec = us_delay;

  if (argc == 2) {
    max_queued = atoi(argv[1]);
  }

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

  options.timeout = 2500;
  optmask |= ARES_OPT_TIMEOUTMS;

  if((res = ares_init_options(&channel, &options, optmask)) != ARES_SUCCESS) {
    fprintf(stderr, "ares_init_options failed: %s\n", ares_strerror(res));
    return 1;
  }

  for (;;) {
    // See if we can issue more requests
    if (queued < max_queued && nbrl >= 0) {
      if ((nbrl = nb_readline(line)) > 0) {
        inet_aton(line, &ip);
        char *arg;
        arg = malloc(MAX_LINE_LEN*sizeof(char));
        if (arg == NULL) {
          fprintf(stderr, "Malloc failed!");
          return 2;
        }
        strncpy(arg, line, MAX_LINE_LEN);
        ares_gethostbyaddr(channel, &ip, sizeof ip, AF_INET, dns_callback_gethostbyaddr, arg);
        //                       IN PTR
        //ares_query(channel, line, 1, 12, dns_callback_query, arg);
        queued++;
        printf("QUEUED  [%04d]: %s\n", queued, line);
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
      count = select(nfds, &readers, &writers, NULL, tvp);
      // Wait for queries to finish
      ares_process(channel, &readers, &writers);
    }
  }
  return 0;
}

// vim: ts=2 sw=2 et ai si
