#define _POSIX_C_SOURCE 200809L

#include "client_operation.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int take_lock(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0)
        return -1;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & 077) || flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool trusted_script(const char *path)
{
    struct stat info;
    return path[0] == '/' && lstat(path, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_uid == geteuid() && !(info.st_mode & (S_IWGRP | S_IWOTH)) && (info.st_mode & S_IXUSR);
}

static void set_signal(int signal_number, void (*handler)(int))
{
    struct sigaction action = {0};
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    sigaction(signal_number, &action, NULL);
}

static volatile sig_atomic_t interrupted;

static void mark_interrupted(int signal_number)
{
    (void)signal_number;
    interrupted = 1;
}

static void execute_script(char *const child_args[])
{
    setpgid(0, 0);
    set_signal(SIGINT, SIG_DFL);
    set_signal(SIGTERM, SIG_DFL);
    set_signal(SIGHUP, SIG_DFL);
    int null = open("/dev/null", O_RDWR);
    if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(null, STDOUT_FILENO) < 0 ||
        dup2(null, STDERR_FILENO) < 0)
        _exit(CLIENT_SCRIPT_FAILED);
    if (null > STDERR_FILENO)
        close(null);
    char *const environment[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
        NULL
    };
    execve(child_args[0], child_args, environment);
    _exit(CLIENT_SCRIPT_FAILED);
}

static int wait_for_script(pid_t child, int limit)
{
    struct timespec start, now;
    bool clock_ok = clock_gettime(CLOCK_MONOTONIC, &start) == 0;
    int status;
    while (clock_ok && !interrupted) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : CLIENT_SCRIPT_FAILED;
        if (result < 0 && errno != EINTR)
            return CLIENT_SCRIPT_FAILED;
        clock_ok = clock_gettime(CLOCK_MONOTONIC, &now) == 0;
        if (!clock_ok || now.tv_sec - start.tv_sec >= limit)
            break;
        struct timespec delay = {.tv_nsec = 100 * 1000 * 1000};
        nanosleep(&delay, NULL);
    }
    /* The script can launch subprocesses. Stop the entire group before releasing the lock. */
    (void)kill(-child, SIGTERM);
    struct timespec grace = {.tv_sec = 1};
    nanosleep(&grace, NULL);
    (void)kill(-child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    return interrupted ? CLIENT_TEMPORARY : CLIENT_DEADLINE;
}

static bool path_for(char out[PATH_MAX], const char *root, const char *relative)
{
    int length = snprintf(out, PATH_MAX, "%s/%s", root, relative);
    return length > 0 && length < PATH_MAX;
}

static bool available_file(const char *root, const char *relative)
{
    char path[PATH_MAX];
    struct stat info;
    return path_for(path, root, relative) && stat(path, &info) == 0 && S_ISREG(info.st_mode) && info.st_size > 0;
}

/* Count exact WireGuard peer names in the two configured tunnels. */
static bool wireguard_peer(const char *root, const char *relative, const char *name, bool *found, bool *clash)
{
    char path[PATH_MAX];
    FILE *config = path_for(path, root, relative) ? fopen(path, "r") : NULL;
    if (!config)
        return false;
    const char marker[] = "# Client = ";
    char line[256];
    *found = false;
    while (fgets(line, sizeof(line), config)) {
        size_t newline = strcspn(line, "\r\n");
        if (!line[newline] && !feof(config)) {
            int ch;
            while ((ch = fgetc(config)) != EOF && ch != '\n') {
            }
            continue;
        }
        line[newline] = '\0';
        if (strncmp(line, marker, sizeof(marker) - 1))
            continue;
        const char *peer = line + sizeof(marker) - 1;
        if (!strcmp(peer, name))
            *found = true;
        else if (!strcasecmp(peer, name))
            *clash = true;
    }
    bool read_ok = !ferror(config);
    return fclose(config) == 0 && read_ok;
}

static int wireguard_state(const char *root, const char *name)
{
    bool antizapret, vpn, clash = false;
    if (!available_file(root, "wireguard/key") || !available_file(root, "wireguard/antizapret.conf") ||
        !available_file(root, "wireguard/vpn.conf") ||
        !wireguard_peer(root, "wireguard/antizapret.conf", name, &antizapret, &clash) ||
        !wireguard_peer(root, "wireguard/vpn.conf", name, &vpn, &clash))
        return -1;
    if (clash)
        return -2;
    return antizapret + vpn;
}

static int openvpn_state(const char *root, const char *name)
{
    char path[PATH_MAX];
    if (!available_file(root, "openvpn/easyrsa3/pki/ca.crt") ||
        !available_file(root, "openvpn/easyrsa3/pki/issued/antizapret-server.crt") ||
        !available_file(root, "openvpn/easyrsa3/pki/private/antizapret-server.key") ||
        !path_for(path, root, "openvpn/easyrsa3/pki/issued"))
        return -1;
    DIR *stream = opendir(path);
    if (!stream)
        return -1;
    char filename[37];
    snprintf(filename, sizeof(filename), "%s.crt", name);
    int found = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(stream))) {
        if (!strcasecmp(entry->d_name, filename)) {
            found = strcmp(entry->d_name, filename) ? -2 : 1;
            if (found == -2)
                break;
        }
    }
    int result = errno ? -1 : found;
    closedir(stream);
    return result;
}

static int perform(const char *script, const char *lock_path, const struct client_operation *operation,
                   char *name, char *days, const char *state)
{
    if (!valid_operation_arguments(operation, name, days))
        return CLIENT_INVALID;
    if (!trusted_script(script))
        return CLIENT_UNAVAILABLE;
    int lock = take_lock(lock_path);
    if (lock < 0)
        return CLIENT_TEMPORARY;
    bool openvpn = !strncmp(operation->name, "openvpn-", 8);
    if (state) {
        int existing = openvpn ? openvpn_state(state, name) : wireguard_state(state, name);
        int result = 0;
        if (existing == -1)
            result = CLIENT_UNAVAILABLE;
        else if (existing == -2 || (operation->creation &&
            (existing == (openvpn ? 1 : 2) ||
             (openvpn ? wireguard_state(state, name) : openvpn_state(state, name)) == -2)))
            result = CLIENT_CONFLICT;
        if (result || (!operation->creation && existing == 0)) {
            close(lock);
            return result;
        }
    }
    set_signal(SIGINT, mark_interrupted);
    set_signal(SIGTERM, mark_interrupted);
    set_signal(SIGHUP, mark_interrupted);
    char *const child_args[] = {(char *)script, (char *)operation->code, name, days, NULL};
    pid_t child = fork();
    if (!child)
        execute_script(child_args);
    if (child < 0) {
        close(lock);
        return CLIENT_TEMPORARY;
    }
    (void)setpgid(child, child);
    int result = wait_for_script(child, operation->timeout);
    if (state && !result) {
        int existing = openvpn ? openvpn_state(state, name) : wireguard_state(state, name);
        int expected = operation->creation ? (openvpn ? 1 : 2) : 0;
        if (existing != expected)
            result = CLIENT_SCRIPT_FAILED;
    }
    close(lock);
    return result;
}

static bool read_request(char request[CLIENT_REQUEST_CAP])
{
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) < 0)
        return false;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return false;
    time_t deadline = now.tv_sec + 5;
    size_t used = 0;
    struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN};
    while (used < CLIENT_REQUEST_CAP - 1 && !clock_gettime(CLOCK_MONOTONIC, &now) && now.tv_sec < deadline) {
        int ready = poll(&input, 1, 500);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0)
            return false;
        if (!ready)
            continue;
        ssize_t length = read(STDIN_FILENO, request + used, CLIENT_REQUEST_CAP - 1 - used);
        if (length < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (length <= 0 || memchr(request + used, '\0', (size_t)length))
            return false;
        used += (size_t)length;
        char *newline = memchr(request, '\n', used);
        if (newline) {
            if (newline != request + used - 1)
                return false;
            *newline = '\0';
            return true;
        }
    }
    return false;
}

static int socket_request(const char *script, const char *lock_path, const char *state)
{
    char request[CLIENT_REQUEST_CAP];
    int result = CLIENT_INVALID;
    if (read_request(request)) {
        char *context = NULL;
        char *operation = strtok_r(request, " ", &context);
        char *name = strtok_r(NULL, " ", &context);
        char *days = strtok_r(NULL, " ", &context);
        if (!strtok_r(NULL, " ", &context))
            result = perform(script, lock_path, find_operation(operation, true), name, days, state);
    }
    set_signal(SIGPIPE, SIG_IGN);
    (void)dprintf(STDOUT_FILENO, "%d\n", result);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 4 || argv[2][0] != '/')
        return CLIENT_INVALID;
    if (!strcmp(argv[3], "--socket"))
        return argc == 5 && argv[4][0] == '/' ? socket_request(argv[1], argv[2], argv[4]) : CLIENT_INVALID;
    const struct client_operation *operation = find_operation(argv[3], false);
    if (!operation || (size_t)argc != 4 + operation->argument_count)
        return CLIENT_INVALID;
    return perform(argv[1], argv[2], operation, argc > 4 ? argv[4] : NULL, argc > 5 ? argv[5] : NULL, NULL);
}
