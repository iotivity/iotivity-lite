// Copyright 2015-2017 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include "esp_vfs.h"
#include "esp_vfs_dev.h"
#include "esp_attr.h"
#include "sdkconfig.h"
#include "port/oc_assert.h"
#include "debug_print.h"

// TODO: make the number of UARTs chip dependent
#define PIPE_NUM 4

typedef struct
{
    char buffer[2];
    int used;
    bool read_created;
    bool write_created;
    bool read_closed;
    bool write_closed;
} vfs_pipe_context_t;

static portMUX_TYPE s_registered_ctx_lock = portMUX_INITIALIZER_UNLOCKED;
static vfs_pipe_context_t *s_ctx[PIPE_NUM] = {0};

typedef struct
{
    esp_vfs_select_sem_t select_sem;
    fd_set *readfds;
    fd_set *writefds;
    fd_set *errorfds;
    fd_set readfds_orig;
    fd_set writefds_orig;
    fd_set errorfds_orig;
} pipe_select_args_t;

static pipe_select_args_t **s_registered_selects = NULL;
static int s_registered_select_num = 0;
static portMUX_TYPE s_registered_select_lock = portMUX_INITIALIZER_UNLOCKED;

static esp_err_t pipe_end_select(void *end_select_args);

static int get_index(int fd)
{
    return fd / 2;
}

static vfs_pipe_context_t *get_ctx_locked(int fd)
{
    assert(fd >= 0 && fd < PIPE_NUM);
    return s_ctx[get_index(fd)];
}

static void free_ctx_locked(int index)
{
    if (s_ctx[index] == NULL)
        return;
    free(s_ctx[index]);
    s_ctx[index] = NULL;
}

static int parse_index(const char *path)
{
    int index = -1;
    const char *p = path + 1;
    for (int i = 0; i < PIPE_NUM; ++i)
    {
        char buf[12];
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "%d", i);
        if (strcmp(p, buf) == 0)
        {
            index = i;
        }
    }

    if (index == -1)
    {
        errno = ENOENT;
        return -1;
    }
    return index;
}

static vfs_pipe_context_t *create_ctx_locked()
{
    vfs_pipe_context_t *ctx = malloc(sizeof(vfs_pipe_context_t));
    ctx->used = 0;
    ctx->read_created = false;
    ctx->write_created = false;
    ctx->write_closed = true;
    ctx->read_closed = true;
    return ctx;
}

static int pipe_open_read(const char *path, int flags, int mode)
{
    int index = parse_index(path);
    if (index < 0)
    {
        return index;
    }
    portENTER_CRITICAL(&s_registered_ctx_lock);
    bool created = false;
    vfs_pipe_context_t *ctx = get_ctx_locked(index * 2);
    if (ctx == NULL)
    {
        ctx = create_ctx_locked();
        created = true;
        s_ctx[index] = ctx;
    }

    if (ctx->read_created)
    {
        errno = ENOENT;
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        if (created)
        {
            free_ctx_locked(index);
        }
        print_error("pipe_open_read %s %d\n", path, errno);
        return -1;
    }
    ctx->read_created = true;
    ctx->read_closed = false;
    portEXIT_CRITICAL(&s_registered_ctx_lock);
    return 2 * index;
}

static int pipe_open_write(const char *path, int flags, int mode)
{
    int index = parse_index(path);
    if (index < 0)
    {
        return index;
    }
    portENTER_CRITICAL(&s_registered_ctx_lock);
    bool created = false;
    vfs_pipe_context_t *ctx = get_ctx_locked(index * 2);
    if (ctx == NULL)
    {
        ctx = create_ctx_locked();
        created = true;
        s_ctx[index] = ctx;
    }

    if (ctx->write_created)
    {
        errno = ENOENT;
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        if (created)
        {
            free_ctx_locked(index);
        }
        print_error("pipe_open_write %d\n", errno);
        return -1;
    }
    ctx->write_created = true;
    ctx->write_closed = false;
    portEXIT_CRITICAL(&s_registered_ctx_lock);
    return 2 * index + 1;
}

static bool prepare_notify_registered(pipe_select_args_t *args, int pipe_fd, bool read, bool write)
{
    bool notify = false;
    if (args)
    {
        if (read && FD_ISSET(pipe_fd, &args->readfds_orig))
        {
            FD_SET(pipe_fd, args->readfds);
            notify = true;
        }
        if (write && FD_ISSET(pipe_fd, &args->writefds_orig))
        {
            FD_SET(pipe_fd, args->writefds);
            notify = true;
        }
    }
    return notify;
}

static void select_notify(int pipe_fd, bool read, bool write)
{
    portENTER_CRITICAL_ISR(&s_registered_select_lock);
    for (int i = 0; i < s_registered_select_num; ++i)
    {
        pipe_select_args_t *args = s_registered_selects[i];
        if (prepare_notify_registered(args, pipe_fd, read, write))
        {
            esp_vfs_select_triggered(args->select_sem);
        }
    }
    portEXIT_CRITICAL_ISR(&s_registered_select_lock);
}

static ssize_t pipe_write(int fd, const void *data, size_t size)
{
    portENTER_CRITICAL(&s_registered_ctx_lock);
    vfs_pipe_context_t *ctx = get_ctx_locked(fd);
    if (ctx == NULL)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EINVAL;
        return -1;
    }
    if (data == NULL || size == 0)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EINVAL;
        return -1;
    }

    if (size > (sizeof(ctx->buffer) - ctx->used))
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        OC_DBG("pipe_write %d %d, (sizeof(ctx->buffer) - ctx->used)\n", sizeof(ctx->buffer), ctx->used);
        errno = EBUSY;
        return -1;
    }
    memcpy(&ctx->buffer[ctx->used], data, size);
    ctx->used += (int)size;
    portEXIT_CRITICAL(&s_registered_ctx_lock);
    select_notify(fd - 1, true, false);
    return size;
}

static ssize_t pipe_read(int fd, void *data, size_t size)
{
    portENTER_CRITICAL(&s_registered_ctx_lock);
    vfs_pipe_context_t *ctx = get_ctx_locked(fd);
    if (ctx == NULL)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EINVAL;
        return -1;
    }
    size_t s = size;
    if (data == NULL || s == 0)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EINVAL;
        return -1;
    }
    if (ctx->used == 0)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EAGAIN;
        return -1;
    }
    if (s > ctx->used)
    {
        s = ctx->used;
    }
    memcpy(data, ctx->buffer, s);
    ctx->used -= s;
    memmove(ctx->buffer, &ctx->buffer[s], ctx->used);
    portEXIT_CRITICAL(&s_registered_ctx_lock);
    select_notify(fd + 1, false, true);
    return s;
}

static int pipe_fstat(int fd, struct stat *st)
{
    assert(fd >= 0 && fd < 3);
    st->st_mode = S_IFCHR;
    return 0;
}

static int pipe_close_read(int fd)
{
    assert(fd >= 0 && fd < PIPE_NUM);
    portENTER_CRITICAL(&s_registered_ctx_lock);
    vfs_pipe_context_t *ctx = get_ctx_locked(fd);
    if (ctx == NULL)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EINVAL;
        return -1;
    }
    if (ctx->read_closed)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EINVAL;
        return -1;
    }
    ctx->read_closed = true;
    if (ctx->write_closed && ctx->read_closed)
    {
        free_ctx_locked(get_index(fd));
    }
    portEXIT_CRITICAL(&s_registered_ctx_lock);
    return 0;
}

static int pipe_close_write(int fd)
{
    assert(fd >= 0 && fd < PIPE_NUM);
    portENTER_CRITICAL(&s_registered_ctx_lock);
    vfs_pipe_context_t *ctx = get_ctx_locked(fd);
    if (ctx == NULL)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EINVAL;
        return -1;
    }
    if (ctx->write_closed)
    {
        portEXIT_CRITICAL(&s_registered_ctx_lock);
        errno = EINVAL;
        return -1;
    }
    select_notify(fd - 1, true, false);
    ctx->write_closed = true;
    if (ctx->write_closed && ctx->read_closed)
    {
        free_ctx_locked(get_index(fd));
    }
    portEXIT_CRITICAL(&s_registered_ctx_lock);
    return 0;
}

static esp_err_t register_select(pipe_select_args_t *args)
{
    esp_err_t ret = ESP_ERR_INVALID_ARG;

    if (args)
    {
        portENTER_CRITICAL(&s_registered_select_lock);
        const int new_size = s_registered_select_num + 1;
        if ((s_registered_selects = realloc(s_registered_selects, new_size * sizeof(pipe_select_args_t *))) == NULL)
        {
            ret = ESP_ERR_NO_MEM;
        }
        else
        {
            s_registered_selects[s_registered_select_num] = args;
            s_registered_select_num = new_size;
            ret = ESP_OK;
        }
        portEXIT_CRITICAL(&s_registered_select_lock);
    }

    return ret;
}

static esp_err_t unregister_select(pipe_select_args_t *args)
{
    esp_err_t ret = ESP_OK;
    if (args)
    {
        ret = ESP_ERR_INVALID_STATE;
        portENTER_CRITICAL(&s_registered_select_lock);
        for (int i = 0; i < s_registered_select_num; ++i)
        {
            if (s_registered_selects[i] == args)
            {
                const int new_size = s_registered_select_num - 1;
                // The item is removed by overwriting it with the last item. The subsequent rellocation will drop the
                // last item.
                s_registered_selects[i] = s_registered_selects[new_size];
                s_registered_selects = realloc(s_registered_selects, new_size * sizeof(pipe_select_args_t *));
                if (s_registered_selects || new_size == 0)
                {
                    s_registered_select_num = new_size;
                    ret = ESP_OK;
                }
                else
                {
                    ret = ESP_ERR_NO_MEM;
                }
                break;
            }
        }
        portEXIT_CRITICAL(&s_registered_select_lock);
    }
    return ret;
}

static esp_err_t pipe_start_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                                   esp_vfs_select_sem_t select_sem, void **end_select_args)
{
    const int max_fds = MIN(nfds, PIPE_NUM);
    *end_select_args = NULL;

    for (int i = 0; i < max_fds; ++i)
    {
        if (FD_ISSET(i, readfds))
        {
            if ((i % 2) != 0)
            {
                return ESP_ERR_INVALID_STATE;
            }
        }
        if (FD_ISSET(i, writefds))
        {
            if ((i % 2) != 1)
            {
                return ESP_ERR_INVALID_STATE;
            }
        }
    }

    pipe_select_args_t *args = malloc(sizeof(pipe_select_args_t));
    if (args == NULL)
    {
        return ESP_ERR_NO_MEM;
    }

    args->select_sem = select_sem;
    args->readfds = readfds;
    args->writefds = writefds;
    args->errorfds = exceptfds;
    args->readfds_orig = *readfds; // store the original values because they will be set to zero
    args->writefds_orig = *writefds;
    args->errorfds_orig = *exceptfds;
    FD_ZERO(readfds);
    FD_ZERO(writefds);
    FD_ZERO(exceptfds);

    bool notify = false;
    portENTER_CRITICAL(&s_registered_ctx_lock);
    for (int i = 0; i < max_fds; ++i)
    {
        if (FD_ISSET(i, &args->readfds_orig))
        {
            vfs_pipe_context_t *ctx = get_ctx_locked(i);
            if (ctx && ctx->used > 0 && prepare_notify_registered(args, i, true, false))
            {
                notify = true;
            }
        }
        if (FD_ISSET(i, &args->writefds_orig))
        {
            vfs_pipe_context_t *ctx = get_ctx_locked(i);
            if (ctx && ctx->used < sizeof(ctx->buffer) && prepare_notify_registered(args, i, false, true))
            {
                notify = true;
            }
        }
    }
    portEXIT_CRITICAL(&s_registered_ctx_lock);

    esp_err_t ret = register_select(args);
    if (ret != ESP_OK)
    {
        free(args);
        return ret;
    }

    if (notify)
    {
        esp_vfs_select_triggered(args->select_sem);
    }

    *end_select_args = args;
    return ESP_OK;
}

static esp_err_t pipe_end_select(void *end_select_args)
{
    pipe_select_args_t *args = end_select_args;
    esp_err_t ret = unregister_select(args);
    if (args)
    {
        free(args);
    }
    return ret;
}

void esp_vfs_dev_pipe_register(void)
{
    esp_vfs_t vfs_read = {
        .flags = ESP_VFS_FLAG_DEFAULT,
        .open = &pipe_open_read,
        .fstat = &pipe_fstat,
        .close = &pipe_close_read,
        .read = &pipe_read,

        .start_select = &pipe_start_select,
        .end_select = &pipe_end_select,
    };
    ESP_ERROR_CHECK(esp_vfs_register("/dev/pipe/read", &vfs_read, NULL));

    esp_vfs_t vfs_write = {
        .flags = ESP_VFS_FLAG_DEFAULT,
        .open = &pipe_open_write,
        .fstat = &pipe_fstat,
        .close = &pipe_close_write,
        .write = &pipe_write,

        .start_select = &pipe_start_select,
        .end_select = &pipe_end_select,
    };
    ESP_ERROR_CHECK(esp_vfs_register("/dev/pipe/write", &vfs_write, NULL));
}

int vfs_pipe(int pipefd[2])
{
    int index = -1;
    portENTER_CRITICAL(&s_registered_ctx_lock);
    for (int i = 0; i <= sizeof(s_ctx); ++i)
    {
        if (s_ctx[i] == NULL)
        {
            index = i;
            break;
        }
    }
    portEXIT_CRITICAL(&s_registered_ctx_lock);
    if (index < 0)
    {
        errno = ENFILE;
        print_error("pipe %d\n", errno);
        return -1;
    }
    char buf[32];
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "/dev/pipe/read/%d", index);
    int read_fd = open(buf, 0, 0);
    if (read_fd < 0)
    {
        return read_fd;
    }

    memset(buf, 0, sizeof(buf));
    sprintf(buf, "/dev/pipe/write/%d", index);
    int write_fd = open(buf, 0, 0);
    if (write_fd < 0)
    {
        close(read_fd);
        return write_fd;
    }
    pipefd[0] = read_fd;
    pipefd[1] = write_fd;
    return 0;
}
