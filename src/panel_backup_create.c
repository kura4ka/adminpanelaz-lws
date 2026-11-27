#ifdef __linux__
#define _GNU_SOURCE
#elif !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_backup_create.h"

#include <archive.h>
#include <archive_entry.h>
#include <sqlite3.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <windows.h>
#define close_file _close
#define sync_file _commit
#define remove_directory _rmdir
#else
#include <unistd.h>
#define close_file close
#define sync_file fsync
#define remove_directory rmdir
#endif

enum { ID_SIZE = 32, PATH_SIZE = 4096, SNAPSHOT_LIMIT = 64 * 1024 * 1024, COPY_BUFFER = 16 * 1024 };

static bool join_path(char out[PATH_SIZE], const char *base, const char *name)
{
    int size = snprintf(out, PATH_SIZE, "%s/%s", base, name);
    return size >= 0 && size < PATH_SIZE;
}

static bool open_database(const char *path, int flags, sqlite3 **db)
{
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    return sqlite3_open_v2(path, db, flags, NULL) == SQLITE_OK && sqlite3_busy_timeout(*db, 250) == SQLITE_OK;
}

static bool execute(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool snapshot_size_ok(sqlite3 *db)
{
    sqlite3_stmt *query = NULL;
    bool bounded = false;
    static const char sql[] = "SELECT page_count, page_size FROM pragma_page_count(), pragma_page_size()";
    if (sqlite3_prepare_v2(db, sql, -1, &query, NULL) == SQLITE_OK && sqlite3_step(query) == SQLITE_ROW) {
        sqlite3_int64 pages = sqlite3_column_int64(query, 0);
        sqlite3_int64 size = sqlite3_column_int64(query, 1);
        bounded = pages > 0 && size > 0 && pages <= SNAPSHOT_LIMIT / size;
    }
    sqlite3_finalize(query);
    return bounded;
}

static bool copy_database(sqlite3 *source, sqlite3 *target)
{
    sqlite3_backup *backup = sqlite3_backup_init(target, "main", source, "main");
    if (!backup)
        return false;
    int copied = sqlite3_backup_step(backup, -1);
    int finished = sqlite3_backup_finish(backup);
    return copied == SQLITE_DONE && finished == SQLITE_OK;
}

static int open_private_file(const char *path)
{
#ifdef _WIN32
    return _open(path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT, _S_IREAD | _S_IWRITE);
#else
    return open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
#endif
}

static bool check_database(sqlite3 *db)
{
    sqlite3_stmt *statement = NULL;
    bool valid = sqlite3_prepare_v2(db, "PRAGMA integrity_check(1)", -1, &statement, NULL) == SQLITE_OK &&
                 sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_type(statement, 0) == SQLITE_TEXT &&
                 sqlite3_column_bytes(statement, 0) == 2 &&
                 !memcmp(sqlite3_column_text(statement, 0), "ok", 2) && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return valid;
}

bool panel_backup_snapshot_database(const char *original, const char *snapshot, enum panel_backup_database kind)
{
    const char *clean;
    switch (kind) {
    case PANEL_BACKUP_DATABASE_COPY:
        clean = "";
        break;
    case PANEL_BACKUP_DATABASE_AUTH:
        clean = "DELETE FROM panel_sessions; VACUUM;";
        break;
    case PANEL_BACKUP_DATABASE_SECURITY:
        clean = "PRAGMA foreign_keys = ON; DELETE FROM security_factor WHERE enabled=0; VACUUM;";
        break;
    default:
        return false;
    }
    if (!original || !snapshot)
        return false;
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(original);
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)))
        return false;
#else
    struct stat info;
    if (lstat(original, &info) != 0 || !S_ISREG(info.st_mode))
        return false;
#endif
    int fd = open_private_file(snapshot);
    if (fd < 0)
        return false;
    sqlite3 *source = NULL;
    sqlite3 *target = NULL;
    /* The source read transaction fixes both the size check and the copied pages at the same point in time. */
    bool success = close_file(fd) == 0 && open_database(original, SQLITE_OPEN_READONLY, &source) &&
                   execute(source, "BEGIN") && snapshot_size_ok(source) &&
                   open_database(snapshot, SQLITE_OPEN_READWRITE, &target) &&
                   copy_database(source, target);
    sqlite3_close(source);

    success = success && execute(target, "PRAGMA journal_mode = DELETE; PRAGMA temp_store = FILE;"
                                         "PRAGMA trusted_schema = OFF; PRAGMA cache_size = -1024;") &&
              execute(target, clean) && check_database(target);
    success = sqlite3_close(target) == SQLITE_OK && success;
    if (!success)
        remove(snapshot);
    return success;
}

static bool write_database_member(struct archive *archive, FILE *snapshot, long file_size)
{
    struct archive_entry *entry = archive_entry_new();
    if (!entry)
        return false;
    archive_entry_set_pathname(entry, "data/lws-auth.db");
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0600);
    archive_entry_set_size(entry, file_size);
    bool success = archive_write_header(archive, entry) == ARCHIVE_OK;
    archive_entry_free(entry);
    if (!success)
        return false;

    char buffer[COPY_BUFFER];
    long remaining = file_size;
    while (remaining > 0) {
        size_t length = (size_t)remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        if (fread(buffer, 1, length, snapshot) != length || archive_write_data(archive, buffer, length) != (la_ssize_t)length)
            return false;
        remaining -= (long)length;
    }
    return archive_write_finish_entry(archive) == ARCHIVE_OK;
}

static bool create_archive(const char *snapshot_path, const char *archive_path)
{
    FILE *snapshot = fopen(snapshot_path, "rb");
    if (!snapshot)
        return false;
    long size = fseek(snapshot, 0, SEEK_END) == 0 ? ftell(snapshot) : -1;
    if (size <= 0 || size > SNAPSHOT_LIMIT || fseek(snapshot, 0, SEEK_SET) != 0) {
        fclose(snapshot);
        return false;
    }

    int fd = open_private_file(archive_path);
    struct archive *archive = fd >= 0 ? archive_write_new() : NULL;
    bool success = archive && archive_write_set_format_ustar(archive) == ARCHIVE_OK &&
                   archive_write_add_filter_gzip(archive) == ARCHIVE_OK &&
                   archive_write_set_bytes_in_last_block(archive, 1) == ARCHIVE_OK &&
                   archive_write_open_fd(archive, fd) == ARCHIVE_OK &&
                   write_database_member(archive, snapshot, size);
    if (archive && archive_write_free(archive) != ARCHIVE_OK)
        success = false;
    if (fd >= 0) {
        if (success && sync_file(fd) != 0)
            success = false;
        if (close_file(fd) != 0)
            success = false;
    }
    fclose(snapshot);
    return success;
}

static bool create_private_directory(const char *root, const char *temporary)
{
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(root);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(attributes & FILE_ATTRIBUTE_REPARSE_POINT) && _mkdir(temporary) == 0;
#else
    struct stat info;
    return lstat(root, &info) == 0 && S_ISDIR(info.st_mode) && mkdir(temporary, 0700) == 0;
#endif
}

static bool publish_archive(const char *temporary, const char *final)
{
#ifdef _WIN32
    return MoveFileExA(temporary, final, MOVEFILE_WRITE_THROUGH) != 0;
#elif defined(__linux__)
    return renameat2(AT_FDCWD, temporary, AT_FDCWD, final, RENAME_NOREPLACE) == 0;
#else
    return link(temporary, final) == 0;
#endif
}

static void remove_temporary_files(const char *directory)
{
    static const char *const files[] = {
        "archive.tar.gz", "snapshot.sqlite", "snapshot.sqlite-journal", "snapshot.sqlite-wal", "snapshot.sqlite-shm"
    };
    char path[PATH_SIZE];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        if (join_path(path, directory, files[i]))
            remove(path);
    }
    remove_directory(directory);
}

bool panel_backup_create(const char *backup_dir, const char *auth_db, const char *id)
{
    if (!backup_dir || !backup_dir[0] || !auth_db || !auth_db[0] || !id ||
        strlen(id) != ID_SIZE || strspn(id, "0123456789abcdef") != ID_SIZE)
        return false;

    char name[ID_SIZE + sizeof(".create-")];
    char final[PATH_SIZE];
    snprintf(name, sizeof(name), "%s.backup", id);
    if (!join_path(final, backup_dir, name))
        return false;

    char directory[PATH_SIZE];
    char snapshot[PATH_SIZE];
    char archive[PATH_SIZE];
    snprintf(name, sizeof(name), ".create-%s", id);
    if (!join_path(directory, backup_dir, name) || !join_path(snapshot, directory, "snapshot.sqlite") ||
        !join_path(archive, directory, "archive.tar.gz") || !create_private_directory(backup_dir, directory))
        return false;

    bool success = panel_backup_snapshot_database(auth_db, snapshot, PANEL_BACKUP_DATABASE_AUTH) &&
                   create_archive(snapshot, archive) &&
                   publish_archive(archive, final);
    remove_temporary_files(directory);
    return success;
}
