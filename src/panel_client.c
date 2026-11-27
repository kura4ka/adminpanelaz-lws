#if defined(__linux__)
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_client.h"

#include <stddef.h>

#if defined(__linux__)
#include "client_operation.h"

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static struct {
    int fd;
    enum panel_client_result result;
    char request[CLIENT_REQUEST_CAP];
    size_t sent;
    size_t request_length;
    char reply[4];
    size_t received;
    time_t deadline;
} current = {.fd = -1, .result = PANEL_CLIENT_IDLE};

static enum panel_client_result finish(enum panel_client_result result)
{
    close(current.fd);
    current.fd = -1;
    current.result = result;
    return result;
}

static enum panel_client_result reply_status(const char *text)
{
    if (!strcmp(text, "0\n"))
        return PANEL_CLIENT_OK;
    if (!strcmp(text, "2\n"))
        return PANEL_CLIENT_INVALID;
    if (!strcmp(text, "5\n") || !strcmp(text, "75\n"))
        return PANEL_CLIENT_CONFLICT;
    if (!strcmp(text, "6\n"))
        return PANEL_CLIENT_NOT_CONFIGURED;
    if (!strcmp(text, "124\n"))
        return PANEL_CLIENT_TIMEOUT;
    return PANEL_CLIENT_FAILED;
}

static enum panel_client_result advance(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec >= current.deadline)
        return finish(PANEL_CLIENT_TIMEOUT);
    if (current.sent < current.request_length) {
        ssize_t sent = send(current.fd, current.request + current.sent, current.request_length - current.sent,
                            MSG_NOSIGNAL);
        if (sent < 0 && (errno == EAGAIN || errno == EINTR))
            return PANEL_CLIENT_RUNNING;
        if (sent <= 0)
            return finish(PANEL_CLIENT_FAILED);
        current.sent += (size_t)sent;
        if (current.sent < current.request_length)
            return PANEL_CLIENT_RUNNING;
    }
    size_t remaining = sizeof(current.reply) - current.received;
    ssize_t received = recv(current.fd, current.reply + current.received, remaining, 0);
    if (received < 0 && (errno == EAGAIN || errno == EINTR))
        return PANEL_CLIENT_RUNNING;
    if (received <= 0)
        return finish(PANEL_CLIENT_FAILED);
    current.received += (size_t)received;
    if (current.reply[current.received - 1] == '\n') {
        char reply[sizeof(current.reply) + 1] = {0};
        memcpy(reply, current.reply, current.received);
        return finish(reply_status(reply));
    }
    return current.received < sizeof(current.reply) ? PANEL_CLIENT_RUNNING : finish(PANEL_CLIENT_FAILED);
}

static bool available_socket(const char *path)
{
    struct stat info;
    return path && path[0] == '/' && strlen(path) < sizeof(((struct sockaddr_un *)0)->sun_path) &&
        lstat(path, &info) == 0 && S_ISSOCK(info.st_mode);
}
#endif

enum panel_client_result panel_client_start(const char *socket_path, const char *operation, const char *name,
                                            const char *days)
{
#if defined(__linux__)
    const struct client_operation *action = find_operation(operation, true);
    name = name && name[0] ? name : NULL;
    days = days && days[0] ? days : NULL;
    if (!valid_operation_arguments(action, name, days))
        return PANEL_CLIENT_INVALID;
    if (!available_socket(socket_path))
        return PANEL_CLIENT_UNAVAILABLE;
    if (current.fd >= 0 && advance() == PANEL_CLIENT_RUNNING)
        return PANEL_CLIENT_CONFLICT;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return PANEL_CLIENT_FAILED;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, socket_path);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return PANEL_CLIENT_FAILED;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        int error = errno;
        close(fd);
        return error == EAGAIN ? PANEL_CLIENT_CONFLICT : PANEL_CLIENT_UNAVAILABLE;
    }
    int length = snprintf(current.request, sizeof(current.request), "%s %s%s%s\n", operation, name,
                          days ? " " : "", days ? days : "");
    if (length <= 0 || (size_t)length >= sizeof(current.request)) {
        close(fd);
        return PANEL_CLIENT_INVALID;
    }
    current.fd = fd;
    current.result = PANEL_CLIENT_RUNNING;
    current.request_length = (size_t)length;
    current.sent = current.received = 0;
    current.deadline = now.tv_sec + action->timeout + 10;
    return advance();
#else
    (void)socket_path; (void)operation; (void)name; (void)days;
    return PANEL_CLIENT_UNAVAILABLE;
#endif
}

enum panel_client_result panel_client_poll(const char *socket_path)
{
#if defined(__linux__)
    if (current.fd >= 0)
        return advance();
    return available_socket(socket_path) ? current.result : PANEL_CLIENT_UNAVAILABLE;
#else
    (void)socket_path;
    return PANEL_CLIENT_UNAVAILABLE;
#endif
}

const char *panel_client_result_name(enum panel_client_result result)
{
    static const char *const names[] = {"unavailable", "idle", "running", "ok", "invalid", "conflict",
                                        "failed", "timeout", "not_configured"};
    return (unsigned int)result < sizeof(names) / sizeof(names[0]) ? names[result] : "failed";
}
