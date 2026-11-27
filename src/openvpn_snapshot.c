#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum { MAX_LINE = 4096, MAX_RESPONSE = 4 * 1024 * 1024, TIMEOUT_SECONDS = 3 };

static void on_timeout(int signal_number)
{
    (void)signal_number;
    _exit(EXIT_FAILURE);
}

static bool start_timeout(void)
{
    struct sigaction action = { .sa_handler = on_timeout };
    sigset_t unblocked;
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGALRM, &action, NULL) != 0 ||
        sigemptyset(&unblocked) != 0 || sigaddset(&unblocked, SIGALRM) != 0 ||
        sigprocmask(SIG_UNBLOCK, &unblocked, NULL) != 0)
        return false;
    alarm(TIMEOUT_SECONDS);
    return true;
}

static bool send_status_command(int fd)
{
    static const char command[] = "status 3\n";
    size_t offset = 0;
    while (offset < sizeof(command) - 1) {
        ssize_t sent = send(fd, command + offset, sizeof(command) - 1 - offset, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            return false;
        offset += (size_t)sent;
    }
    return true;
}

static char record_separator(const char *line, const char *record)
{
    size_t length = strlen(record);
    if (strncmp(line, record, length) == 0 && (line[length] == ',' || line[length] == '\t') &&
        line[length + 1])
        return line[length];
    return '\0';
}

static bool is_status_record(const char *line, char *client_separator)
{
    char header_separator = record_separator(line, "HEADER");
    if (header_separator &&
        record_separator(line + sizeof("HEADER"), "CLIENT_LIST") == header_separator) {
        *client_separator = header_separator;
        return true;
    }
    if (*client_separator && record_separator(line, "CLIENT_LIST") == *client_separator)
        return true;
    return record_separator(line, "TITLE") || record_separator(line, "TIME");
}

static bool read_status_response(int fd)
{
    char line[MAX_LINE];
    size_t used = 0;
    bool invalid = false;
    char client_separator = '\0';
    size_t remaining = MAX_RESPONSE;
    while (remaining) {
        unsigned char chunk[4096];
        size_t requested = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
        ssize_t received = recv(fd, chunk, requested, 0);
        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0)
            break;
        remaining -= (size_t)received;

        for (size_t i = 0; i < (size_t)received; ++i) {
            unsigned char byte = chunk[i];
            if (byte != '\n') {
                if (used >= sizeof(line) - 1 || byte == 0x7f ||
                    (byte < 0x20 && byte != '\t' && byte != '\r'))
                    invalid = true;
                if (!invalid)
                    line[used++] = (char)byte;
                continue;
            }

            if (!invalid) {
                if (used && line[used - 1] == '\r')
                    --used;
                line[used] = '\0';
                if (strcmp(line, "END") == 0)
                    return puts(line) != EOF && fflush(stdout) == 0;
                if (!memchr(line, '\r', used) && is_status_record(line, &client_separator) &&
                    puts(line) == EOF)
                    return false;
            }
            used = 0;
            invalid = false;
        }
    }
    return false;
}

int main(int argc, char **argv)
{
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (argc != 2 || !argv[1][0] || strlen(argv[1]) >= sizeof(address.sun_path)) {
        fputs("Usage: adminpanelaz-openvpn-snapshot <unix socket>\n", stderr);
        return EXIT_FAILURE;
    }

    size_t path_size = strlen(argv[1]) + 1;
    memcpy(address.sun_path, argv[1], path_size);
    socklen_t address_size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_size);
    if (!start_timeout()) {
        perror("Set OpenVPN status timeout");
        return EXIT_FAILURE;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("Open management socket");
        return EXIT_FAILURE;
    }

    bool success = false;
    if (connect(fd, (const struct sockaddr *)&address, address_size) != 0)
        perror("Connect to OpenVPN management socket");
    else if (!send_status_command(fd))
        fputs("Unable to request OpenVPN status\n", stderr);
    else {
        success = read_status_response(fd);
        if (!success)
            fputs("Incomplete OpenVPN status response\n", stderr);
    }
    close(fd);
    alarm(0);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
