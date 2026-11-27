#include "panel_cidr_job.h"
#include "cidr_routes.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <pthread.h>
#endif

struct panel_cidr_job {
    FILE *input;
    FILE *output;
    size_t budget;
    int status;
    unsigned int references;
    bool complete;
    bool reported;
    char database[4096];
    char action[17];
    char source[104];
    char format[40];
};

#ifdef _WIN32
static SRWLOCK mutex = SRWLOCK_INIT;
static CONDITION_VARIABLE idle = CONDITION_VARIABLE_INIT;
static void lock_job(void) { AcquireSRWLockExclusive(&mutex); }
static void unlock_job(void) { ReleaseSRWLockExclusive(&mutex); }
static void wait_idle(void) { SleepConditionVariableSRW(&idle, &mutex, INFINITE, 0); }
static void notify_idle(void) { WakeAllConditionVariable(&idle); }
#else
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t idle = PTHREAD_COND_INITIALIZER;
static void lock_job(void) { pthread_mutex_lock(&mutex); }
static void unlock_job(void) { pthread_mutex_unlock(&mutex); }
static void wait_idle(void) { pthread_cond_wait(&idle, &mutex); }
static void notify_idle(void) { pthread_cond_broadcast(&idle); }
#endif

static bool running;
static bool closing;

static void destroy_job(struct panel_cidr_job *job)
{
    if (job->output)
        fclose(job->output);
    free(job);
}

static void execute_job(struct panel_cidr_job *job)
{
    FILE *output = tmpfile();
    int status = 500;
    if (output) {
        status = cidr_routes_request(job->database, job->action, job->source,
                                     job->format[0] ? job->format : NULL, job->budget, job->input, output);
        if (ferror(output) || fseek(output, 0L, SEEK_SET) != 0) {
            fclose(output);
            output = NULL;
            status = 500;
        }
    }
    if (job->input)
        fclose(job->input);

    lock_job();
    job->output = output;
    job->status = status;
    job->complete = true;
    if (--job->references == 0)
        destroy_job(job);
    running = false;
    notify_idle();
    unlock_job();
}

#ifdef _WIN32
static unsigned int __stdcall worker(void *argument)
{
    execute_job(argument);
    return 0;
}

static bool start_thread(struct panel_cidr_job *job)
{
    uintptr_t thread = _beginthreadex(NULL, 0, worker, job, 0, NULL);
    if (!thread)
        return false;
    CloseHandle((HANDLE)thread);
    return true;
}
#else
static void *worker(void *argument)
{
    execute_job(argument);
    return NULL;
}

static bool start_thread(struct panel_cidr_job *job)
{
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes) != 0)
        return false;
    pthread_t thread;
    bool started = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0 &&
                   pthread_create(&thread, &attributes, worker, job) == 0;
    pthread_attr_destroy(&attributes);
    return started;
}
#endif

static bool copy_parameter(char *target, size_t capacity, const char *value)
{
    if (!value)
        return true;
    size_t length = strlen(value);
    if (length >= capacity)
        return false;
    memcpy(target, value, length + 1);
    return true;
}

bool panel_cidr_job_start(const char *database, const char *action, const char *source, const char *format,
                          size_t budget, FILE *input, struct panel_cidr_job **result)
{
    if (!result)
        return false;
    *result = NULL;
    if (!database || !action)
        return false;
    struct panel_cidr_job *job = calloc(1, sizeof(*job));
    if (!job)
        return false;
    if (!copy_parameter(job->database, sizeof(job->database), database) ||
        !copy_parameter(job->action, sizeof(job->action), action) ||
        !copy_parameter(job->source, sizeof(job->source), source) ||
        !copy_parameter(job->format, sizeof(job->format), format)) {
        free(job);
        return false;
    }
    job->input = input;
    job->budget = budget;
    job->references = 2;
    lock_job();
    bool started = !running && !closing && start_thread(job);
    if (started) {
        running = true;
        *result = job;
    }
    unlock_job();
    if (!started)
        free(job);
    return started;
}

bool panel_cidr_job_poll(struct panel_cidr_job *job, int *http_status, FILE **output)
{
    if (!job || !http_status || !output)
        return false;
    lock_job();
    bool complete = job->complete && !job->reported;
    if (complete) {
        *http_status = job->status;
        *output = job->output;
        job->output = NULL;
        job->reported = true;
    }
    unlock_job();
    return complete;
}

void panel_cidr_job_release(struct panel_cidr_job *job)
{
    if (!job)
        return;
    lock_job();
    bool last = --job->references == 0;
    unlock_job();
    if (last)
        destroy_job(job);
}

void panel_cidr_job_close(void)
{
    lock_job();
    closing = true;
    while (running)
        wait_idle();
    unlock_job();
}
