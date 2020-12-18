#ifndef VFS_PIPE_H
#define VFS_PIPE_H

void esp_vfs_dev_pipe_register(void);
int vfs_pipe(int pipefd[2]);

#endif