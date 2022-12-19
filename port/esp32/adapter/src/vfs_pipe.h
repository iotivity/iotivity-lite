/****************************************************************************
 *
 * Copyright (c) 2023 Jozef Kralik, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef VFS_PIPE_H
#define VFS_PIPE_H

void esp_vfs_dev_pipe_register(void);
int vfs_pipe(int pipefd[2]);

#endif /* VFS_PIPE_H */
