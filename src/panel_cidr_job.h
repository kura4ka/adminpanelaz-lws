#ifndef ADMINPANELAZ_PANEL_CIDR_JOB_H
#define ADMINPANELAZ_PANEL_CIDR_JOB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

struct panel_cidr_job;

/* Starts one operation and takes ownership of input on success. */
bool panel_cidr_job_start(const char *database, const char *action, const char *source, const char *format,
                          size_t budget, FILE *input, struct panel_cidr_job **job);

/* Transfers the output once. A NULL output indicates a worker I/O failure. */
bool panel_cidr_job_poll(struct panel_cidr_job *job, int *http_status, FILE **output);

/* Relinquishes the caller's reference, even while the worker is running. */
void panel_cidr_job_release(struct panel_cidr_job *job);

/* Prevents new requests and waits for any running request before shutdown. */
void panel_cidr_job_close(void);

#endif
