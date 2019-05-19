#include "httpd.h"
#include "base64.h"
#include "assert.h"
#include <openssl/md5.h>

typedef char User[100];  // User format: <username>:<password-md5>
User users[100];         // contents of /etc/htpasswd, max 100 entries

void read_users();
void send_file(char*);
int check_auth(User[], char*);


int main(int c, char **v) {
  read_users();
  serve_forever("8000");
  return 0;
}

void route() {
  // HTTP Basic Auth, seems to work.
  // TODO: gcc 7 gives warnings, check
  header_t *h = request_headers();
  while (h->name && strcmp(h->name, "Authorization") != 0)
    h++;

  if(h->name) {
    // Authorization header found, check it
    if(!check_auth(users, h->value))
      return;

  } else {
    // no Authorization header, return 401
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Basic realm=\"");
    printf("Enter username/password");
    printf("\"\r\n\r\n");
    return;
  }

  ROUTE_START()

  ROUTE_GET("/") {
    printf("HTTP/1.1 200 OK\r\n\r\n");
    send_file("/var/www/pico/index.html");
  }

  ROUTE_GET("/test") {
    printf("HTTP/1.1 200 OK\r\n\r\n");
    printf("List of request headers:\r\n\r\n");

    header_t *h = request_headers();

    while (h->name) {
      printf("%s: %s\n", h->name, h->value);
      h++;
    }
  }

  ROUTE_POST("/") {
    printf("HTTP/1.1 200 OK\r\n\r\n");
    printf("Wow, seems that you POSTed %d bytes. \r\n", payload_size);
    printf("Fetch the data using `payload` variable.");
  }

  ROUTE_END()
}

void read_users() {
  // read users from /etc/htpasswd
  // the file's format is: <username>:<password-md5>
  //
  FILE *file = fopen("/etc/htpasswd", "r");
  assert(file);

  int i;
  for(i = 0; i < sizeof(users) && fgets(users[i], sizeof(User), file); i++)
    users[i][strlen(users[i])-1] = '\0'; // strip newline
  users[i][0] = '\0'; // finish with empty string
  fclose(file);
}

// returns str's md5 in hex form in md5
void md5_hex(char *str, char *md5) {
  unsigned char md5_bin[16]; // 128bits=16 bytes
  MD5(str, strlen(str), md5_bin);
  for(int i = 0; i < 16; i++)  // 16 hex chars
    sprintf(md5 + 2*i, "%02x", md5_bin[i]);
}

int check_auth(User users[], char *auth_header) {
  // auth_header contains "Basic <Base64>", extract <Base64> string and decode in auth_username
  char auth_username[100];
  Base64DecodeStr(auth_header+6, auth_username, 100); // +6 to skip "Basic "
  
  // auth_username is of the form "<username>:<password>", separate them
  char *colon = strchr(auth_username, ':');   // find ':'
  if(colon != NULL)
    *colon = '\0';                            // change to \0 to split the string in two
  char *auth_password = colon ? colon+1 : ""; // password starts after the colon

  // find auth_username in users (each line is <user>:<md5>)
  char *password_md5 = NULL;
  int ul = strlen(auth_username);
  for(int i = 0; strcmp(users[i], "") != 0; i++) {
    if(strncmp(users[i], auth_username, ul) == 0 && users[i][ul] == ':') {
      password_md5 = users[i] + ul + 1; // <md5> part, after the ':'
      break;
    }
  }

  // check if user is found
  if(password_md5 == NULL) {
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Basic realm=\"");
    printf("Invalid user: ");
    printf(auth_username);
    printf("\"\r\n\r\n");
    return 0;
  }

  // check password's md5
  char auth_password_md5[33];
  md5_hex(auth_password, auth_password_md5);
  if(strcmp(password_md5, auth_password_md5) != 0) {
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Basic realm=\"");
    printf("Invalid password");
    printf("\"\r\n\r\n");
    return 0;
  }

  return 1; // both ok
}

void send_file(char *filename) {
  FILE *file = fopen(filename, "r");
  char buf[1024];
  int buflen;
  while((buflen = fread(buf, 1, 1024, file)) > 0)
    fwrite(buf, 1, buflen, stdout);
  fclose(file);
}
