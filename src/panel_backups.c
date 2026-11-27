#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_backups.h"

#include <archive.h>
#include <archive_entry.h>
#include <zlib.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

enum {
    BACKUP_ID_LENGTH = 32,
    BACKUP_NAME_SIZE = BACKUP_ID_LENGTH + sizeof(".backup"),
    BACKUP_PATH_SIZE = 4096,
    MAX_LISTED_BACKUPS = 64,
    MAX_DIRECTORY_ENTRIES = 4096,
    MAX_ARCHIVE_MEMBERS = 1024,
    COMPRESSED_LIMIT = 200 * 1024 * 1024,
    INFLATED_LIMIT = 256 * 1024 * 1024,
    ARCHIVE_BUFFER_SIZE = 32 * 1024
};

struct backup_file {
    char name[BACKUP_NAME_SIZE];
    unsigned long long size;
    long long mtime;
};

struct backup_list {
    struct backup_file files[MAX_LISTED_BACKUPS];
    size_t count;
    bool truncated;
};

struct archive_input {
    FILE *file;
    z_stream stream;
    unsigned char input[ARCHIVE_BUFFER_SIZE];
    unsigned char output[ARCHIVE_BUFFER_SIZE];
    size_t source_remaining;
    size_t decoded_remaining;
    bool gzip;
    bool finished;
    bool limited;
};

static const struct {
    const char *path;
    const char *name;
} backup_components[] = {
    { "data/adminpanel.db", "db" },
    { "data/cidr/cidr.db", "cidr_db" },
    { "env/.env", "env" },
    { "data/lws-auth.db", "lws_auth" }
};

#define COMPONENT_COUNT (sizeof(backup_components) / sizeof(backup_components[0]))

static bool valid_name(const char *name)
{
    return name && strlen(name) == BACKUP_NAME_SIZE - 1 &&
           strspn(name, "0123456789abcdef") == BACKUP_ID_LENGTH &&
           !strcmp(name + BACKUP_ID_LENGTH, ".backup");
}

static bool join_path(char *out, size_t capacity, const char *directory, const char *name)
{
    int written = snprintf(out, capacity, "%s/%s", directory, name);
    return written >= 0 && (size_t)written < capacity;
}

static int compare_backups(const void *left, const void *right)
{
    const struct backup_file *a = left;
    const struct backup_file *b = right;
    if (a->mtime != b->mtime)
        return a->mtime > b->mtime ? -1 : 1;
    return strcmp(a->name, b->name);
}

static void add_backup(struct backup_list *list, const char *name, unsigned long long size,
                       long long mtime)
{
    struct backup_file item = { .size = size, .mtime = mtime };
    memcpy(item.name, name, sizeof(item.name));
    if (list->count < MAX_LISTED_BACKUPS) {
        list->files[list->count++] = item;
        return;
    }

    list->truncated = true;
    size_t oldest = 0;
    for (size_t i = 1; i < list->count; ++i) {
        if (compare_backups(&list->files[i], &list->files[oldest]) > 0)
            oldest = i;
    }
    if (compare_backups(&item, &list->files[oldest]) < 0)
        list->files[oldest] = item;
}

#ifdef _WIN32

static bool plain_directory(DWORD attributes)
{
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

static bool plain_file(DWORD attributes)
{
    return attributes != INVALID_FILE_ATTRIBUTES &&
           !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE));
}

static unsigned long long file_size(DWORD high, DWORD low)
{
    return ((unsigned long long)high << 32) | low;
}

static long long unix_mtime(FILETIME filetime)
{
    unsigned long long ticks = ((unsigned long long)filetime.dwHighDateTime << 32) |
                               filetime.dwLowDateTime;
    return (long long)(ticks / 10000000ULL) - 11644473600LL;
}

static bool read_directory(const char *directory, struct backup_list *list)
{
    char pattern[BACKUP_PATH_SIZE];
    if (!plain_directory(GetFileAttributesA(directory)) ||
        !join_path(pattern, sizeof(pattern), directory, "*"))
        return false;

    WIN32_FIND_DATAA info;
    HANDLE handle = FindFirstFileA(pattern, &info);
    if (handle == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;

    bool ok = true;
    for (size_t seen = 0;; ++seen) {
        if (seen == MAX_DIRECTORY_ENTRIES) {
            list->truncated = true;
            break;
        }
        if (valid_name(info.cFileName) && plain_file(info.dwFileAttributes))
            add_backup(list, info.cFileName, file_size(info.nFileSizeHigh, info.nFileSizeLow),
                       unix_mtime(info.ftLastWriteTime));
        if (!FindNextFileA(handle, &info)) {
            ok = GetLastError() == ERROR_NO_MORE_FILES;
            break;
        }
    }
    FindClose(handle);
    return ok;
}

bool panel_backup_path(char *out, size_t capacity, const char *directory, const char *name)
{
    if (!out || !capacity || !directory || !valid_name(name) ||
        !plain_directory(GetFileAttributesA(directory)) || !join_path(out, capacity, directory, name))
        return false;

    WIN32_FIND_DATAA info;
    HANDLE handle = FindFirstFileA(out, &info);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    FindClose(handle);
    return plain_file(info.dwFileAttributes) && !strcmp(info.cFileName, name);
}

static FILE *open_archive(const char *path, unsigned long long *size)
{
    HANDLE handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (handle == INVALID_HANDLE_VALUE)
        return NULL;

    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &info) ||
        !plain_file(info.dwFileAttributes)) {
        CloseHandle(handle);
        return NULL;
    }

    int fd = _open_osfhandle((intptr_t)handle, _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(handle);
        return NULL;
    }
    FILE *file = _fdopen(fd, "rb");
    if (!file)
        _close(fd);
    *size = file_size(info.nFileSizeHigh, info.nFileSizeLow);
    return file;
}

#else

static bool read_directory(const char *directory, struct backup_list *list)
{
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    DIR *dir = fdopendir(fd);
    if (!dir) {
        close(fd);
        return false;
    }

    bool ok = true;
    for (size_t seen = 0;; ++seen) {
        errno = 0;
        const struct dirent *entry = readdir(dir);
        if (!entry) {
            ok = errno == 0;
            break;
        }
        if (seen == MAX_DIRECTORY_ENTRIES) {
            list->truncated = true;
            break;
        }
        struct stat info;
        if (valid_name(entry->d_name) && fstatat(fd, entry->d_name, &info, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISREG(info.st_mode) && info.st_size >= 0)
            add_backup(list, entry->d_name, (unsigned long long)info.st_size, (long long)info.st_mtime);
    }
    closedir(dir);
    return ok;
}

bool panel_backup_path(char *out, size_t capacity, const char *directory, const char *name)
{
    if (!out || !capacity || !directory || !valid_name(name) || !join_path(out, capacity, directory, name))
        return false;

    struct stat info;
    return lstat(directory, &info) == 0 && S_ISDIR(info.st_mode) &&
           lstat(out, &info) == 0 && S_ISREG(info.st_mode);
}

static FILE *open_archive(const char *path, unsigned long long *size)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0) {
        close(fd);
        return NULL;
    }

    FILE *file = fdopen(fd, "rb");
    if (!file)
        close(fd);
    *size = (unsigned long long)info.st_size;
    return file;
}

#endif

static size_t checked_length(char *out, size_t capacity, int length)
{
    if (length >= 0 && (size_t)length < capacity)
        return (size_t)length;
    out[0] = '\0';
    return 0;
}

size_t panel_backups_json(char *out, size_t capacity, const char *directory)
{
    if (!out || !capacity)
        return 0;
    out[0] = '\0';
    const char prefix[] = "{\"archives\":[";
    const size_t suffix_space = sizeof("],\"truncated\":false}");
    size_t used = sizeof(prefix) - 1;
    struct backup_list list = { 0 };
    if (capacity < used + suffix_space || !directory || !read_directory(directory, &list))
        return 0;
    qsort(list.files, list.count, sizeof(list.files[0]), compare_backups);

    memcpy(out, prefix, used);
    for (size_t i = 0; i < list.count; ++i) {
        char row[128];
        const struct backup_file *file = &list.files[i];
        int length = snprintf(row, sizeof(row), "%s{\"name\":\"%s\",\"size_bytes\":%llu,\"mtime\":%lld}",
                              i ? "," : "", file->name, file->size, file->mtime);
        if (length < 0 || (size_t)length >= sizeof(row) || (size_t)length > capacity - used - suffix_space) {
            list.truncated = true;
            break;
        }
        memcpy(out + used, row, (size_t)length);
        used += (size_t)length;
    }
    const char *suffix = list.truncated ? "],\"truncated\":true}" : "],\"truncated\":false}";
    size_t suffix_size = strlen(suffix);
    memcpy(out + used, suffix, suffix_size + 1);
    return used + suffix_size;
}

static int read_source(struct archive_input *input)
{
    if (!input->source_remaining) {
        input->limited = fgetc(input->file) != EOF;
        return input->limited || ferror(input->file) ? -1 : 0;
    }
    size_t wanted = input->source_remaining < sizeof(input->input)
                        ? input->source_remaining : sizeof(input->input);
    size_t count = fread(input->input, 1, wanted, input->file);
    input->source_remaining -= count;
    return ferror(input->file) ? -1 : (int)count;
}

static la_ssize_t read_gzip(struct archive_input *input)
{
    if (input->finished)
        return 0;

    z_stream *stream = &input->stream;
    stream->next_out = input->output;
    stream->avail_out = sizeof(input->output);
    while (stream->avail_out == sizeof(input->output)) {
        if (!stream->avail_in) {
            int count = read_source(input);
            if (count < 0)
                return -1;
            stream->next_in = input->input;
            stream->avail_in = (uInt)count;
        }
        int status = inflate(stream, Z_NO_FLUSH);
        if (status == Z_STREAM_END) {
            if (stream->avail_in || read_source(input) != 0)
                return -1;
            input->finished = true;
            break;
        }
        if (status != Z_OK)
            return -1;
    }

    size_t produced = sizeof(input->output) - stream->avail_out;
    if (produced > input->decoded_remaining) {
        input->limited = true;
        return -1;
    }
    input->decoded_remaining -= produced;
    return (la_ssize_t)produced;
}

static la_ssize_t next_archive_block(struct archive *archive, void *context, const void **buffer)
{
    struct archive_input *input = context;
    *buffer = input->gzip ? input->output : input->input;
    la_ssize_t count = input->gzip ? read_gzip(input) : read_source(input);
    if (count < 0)
        archive_set_error(archive, EINVAL, "Cannot read backup archive");
    return count;
}

static unsigned int archive_component(const char *name)
{
    if (!name)
        return 0;
    if (!strncmp(name, "./", 2))
        name += 2;
    for (size_t i = 0; i < COMPONENT_COUNT; ++i) {
        if (!strcmp(name, backup_components[i].path))
            return 1u << i;
    }
    return 0;
}

static bool read_tar(struct archive *archive, struct archive_input *input, unsigned int *components)
{
    struct archive_entry *entry;
    int status = archive_read_next_header(archive, &entry);
    for (size_t i = 0; status == ARCHIVE_OK; ++i) {
        if (i == MAX_ARCHIVE_MEMBERS || archive_entry_size(entry) > INFLATED_LIMIT) {
            input->limited = true;
            return false;
        }
        if (archive_entry_filetype(entry) == AE_IFREG && !archive_entry_hardlink(entry) &&
            !archive_entry_symlink(entry))
            *components |= archive_component(archive_entry_pathname(entry));
        if (archive_read_data_skip(archive) != ARCHIVE_OK)
            return false;
        status = archive_read_next_header(archive, &entry);
    }
    if (status != ARCHIVE_EOF || (archive_format(archive) & ARCHIVE_FORMAT_BASE_MASK) != ARCHIVE_FORMAT_TAR)
        return false;

    /* Reading the gzip trailer checks the checksum even after tar's last entry. */
    if (input->gzip) {
        la_ssize_t trailing;
        do {
            trailing = read_gzip(input);
        } while (trailing > 0);
        return trailing == 0;
    }
    return true;
}

static bool inspect_tar(struct archive_input *input, unsigned int *components)
{
    if (input->gzip && inflateInit2(&input->stream, 16 + MAX_WBITS) != Z_OK)
        return false;
    struct archive *archive = archive_read_new();
    bool valid = archive && archive_read_support_filter_none(archive) == ARCHIVE_OK &&
                 archive_read_support_format_tar(archive) == ARCHIVE_OK &&
                 archive_read_open(archive, input, NULL, next_archive_block, NULL) == ARCHIVE_OK &&
                 read_tar(archive, input, components);
    if (archive)
        archive_read_free(archive);
    if (input->gzip)
        inflateEnd(&input->stream);
    return valid;
}

static size_t inspect_result(char *out, size_t capacity, const char *state, const char *format,
                             bool encrypted, unsigned int components)
{
    int length = snprintf(out, capacity, "{\"state\":\"%s\",\"format\":%s,\"encrypted\":%s,\"components\":[",
                          state, format, encrypted ? "true" : "false");
    size_t used = checked_length(out, capacity, length);
    if (!used)
        return 0;
    bool comma = false;
    for (size_t i = 0; i < COMPONENT_COUNT; ++i) {
        if (!(components & (1u << i)))
            continue;
        length = snprintf(out + used, capacity - used, "%s\"%s\"", comma ? "," : "", backup_components[i].name);
        if (length < 0 || (size_t)length >= capacity - used) {
            out[0] = '\0';
            return 0;
        }
        used += (size_t)length;
        comma = true;
    }
    const char suffix[] = "]}";
    if (capacity - used < sizeof(suffix)) {
        out[0] = '\0';
        return 0;
    }
    memcpy(out + used, suffix, sizeof(suffix));
    return used + sizeof(suffix) - 1;
}

size_t panel_backup_inspect_json(char *out, size_t capacity, const char *path)
{
    if (!out || !capacity)
        return 0;
    unsigned long long size;
    FILE *file = path ? open_archive(path, &size) : NULL;
    if (!file)
        return inspect_result(out, capacity, "unavailable", "null", false, 0);
    if (size > COMPRESSED_LIMIT) {
        fclose(file);
        return inspect_result(out, capacity, "limit_exceeded", "null", false, 0);
    }

    const char magic[] = "APAZBK1\n";
    unsigned char prefix[sizeof(magic) - 1];
    size_t count = fread(prefix, 1, sizeof(prefix), file);
    if (count == sizeof(prefix) && !memcmp(prefix, magic, count)) {
        fclose(file);
        return inspect_result(out, capacity, "available", "\"apazbk1\"", true, 0);
    }

    struct archive_input input = { .file = file, .source_remaining = COMPRESSED_LIMIT,
                                   .decoded_remaining = INFLATED_LIMIT };
    input.gzip = count >= 2 && prefix[0] == 0x1f && prefix[1] == 0x8b;
    unsigned int components = 0;
    bool valid = !ferror(file) && fseek(file, 0, SEEK_SET) == 0 && inspect_tar(&input, &components);
    fclose(file);
    if (!valid)
        return inspect_result(out, capacity, input.limited ? "limit_exceeded" : "invalid", "null", false, 0);
    return inspect_result(out, capacity, "available", input.gzip ? "\"tar.gz\"" : "\"tar\"", false, components);
}
