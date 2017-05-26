/*
 * Access guest physical memory via a domain socket.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Original Author: Bryan D. Payne (bdpayne@acm.org)
 *
 * Refurbished for modern QEMU by Valerio Aimale (valerio@aimale.com), in 2015
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>

#include "memory-access.h"
#include "exec/cpu-common.h"
#include "libvmi_request.h"


static uint64_t
connection_read_memory (uint64_t user_paddr, void *buf, uint64_t user_len)
{
    hwaddr paddr = (hwaddr) user_paddr;
    hwaddr len = (hwaddr) user_len;
    void *guestmem = cpu_physical_memory_map(paddr, &len, 0);
    if (!guestmem){
        return 0;
    }
    memcpy(buf, guestmem, len);
    cpu_physical_memory_unmap(guestmem, len, 0, len);

    return len;
}

static uint64_t
connection_write_memory (uint64_t user_paddr, void *buf, uint64_t user_len)
{
    hwaddr paddr = (hwaddr) user_paddr;
    hwaddr len = (hwaddr) user_len;
    void *guestmem = cpu_physical_memory_map(paddr, &len, 1);
    if (!guestmem){
        return 0;
    }
    memcpy(guestmem, buf, len);
    cpu_physical_memory_unmap(guestmem, len, 0, len);

    return len;
}

static void
send_success_ack (int connection_fd)
{
    uint8_t success = 1;
    int nbytes = write(connection_fd, &success, 1);
    if (1 != nbytes){
        fprintf(stderr, "Qemu pmemaccess: failed to send success ack\n");
    }
}

static void
send_fail_ack (int connection_fd)
{
    uint8_t fail = 0;
    int nbytes = write(connection_fd, &fail, 1);
    if (1 != nbytes){
        fprintf(stderr, "Qemu pmemaccess: failed to send fail ack\n");
    }
}

static void
connection_handler (int connection_fd)
{
    int nbytes;
    struct request req;

    while (1){
        // client request should match the struct request format
        nbytes = read(connection_fd, &req, sizeof(struct request));
        if (nbytes != sizeof(struct request)){
            // error
            continue;
        }
        else if (req.type == 0){
            // request to quit, goodbye
            break;
        }
        else if (req.type == 1){
            // request to read
            char *buf = malloc(req.length + 1);
            nbytes = connection_read_memory(req.address, buf, req.length);
            if (nbytes != req.length){
                // read failure, return failure message
                buf[req.length] = 0; // set last byte to 0 for failure
                nbytes = write(connection_fd, buf, 1);
            }
            else{
                // read success, return bytes
                buf[req.length] = 1; // set last byte to 1 for success
                nbytes = write(connection_fd, buf, nbytes + 1);
            }
            free(buf);
        }
        else if (req.type == 2){
            // request to write
            void *write_buf = malloc(req.length);
            nbytes = read(connection_fd, write_buf, req.length);
            if (nbytes != req.length){
                // failed reading the message to write
                send_fail_ack(connection_fd);
            }
            else{
                // do the write
                nbytes = connection_write_memory(req.address, write_buf, req.length);
                if (nbytes == req.length){
                    send_success_ack(connection_fd);
                }
                else{
                    send_fail_ack(connection_fd);
                }
            }
            free(write_buf);
        }
        else{
            // unknown command
            fprintf(stderr, "Qemu pmemaccess: ignoring unknown command (%" PRIu64 ")\n", req.type);
            char *buf = malloc(1);
            buf[0] = 0;
            nbytes = write(connection_fd, buf, 1);
            free(buf);
        }
    }

    close(connection_fd);
}

static void *
memory_access_thread (void *p)
{
    int connection_fd;
    struct pmemaccess_args *pargs = (struct pmemaccess_args *)p;

    // accept incoming connections
    connection_fd = accept(pargs->socket_fd, (struct sockaddr *) pargs->address, &(pargs->address_length));
    connection_handler(connection_fd);

    close(pargs->socket_fd);
    unlink(pargs->path);
    free(pargs->path);
    free(pargs->address);
    free(pargs);
    return NULL;
}

void
qmp_pmemaccess (const char *path, Error **errp)
{
    pthread_t thread;
    sigset_t set, oldset;
    struct pmemaccess_args *pargs;

    // create the args struct
    pargs = (struct pmemaccess_args *) malloc(sizeof(struct pmemaccess_args));
    if (pargs == NULL){
        error_setg(errp, "Qemu pmemaccess: malloc failed");
        return;
    }

    pargs->errp = errp;
    // create a copy of path that we can safely use
    size_t path_size = strlen(path);
    pargs->path = malloc(path_size + 1);
    memcpy(pargs->path, path, path_size);
    pargs->path[path_size] = '\0';

    // create socket
    pargs->socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (pargs->socket_fd < 0){
        error_setg(pargs->errp, "Qemu pmemaccess: socket failed");
        return;
    }
    // unlink path if already exists
    unlink(path);
    // bind socket
    pargs->address = malloc(sizeof(struct sockaddr_un));
    if (pargs->address == NULL){
        error_setg(pargs->errp, "Qemu pmemaccess: malloc failed");
        return;
    }
    pargs->address->sun_family = AF_UNIX;
    pargs->address_length = sizeof(pargs->address->sun_family) + sprintf(pargs->address->sun_path, "%s", (char *) pargs->path);
    if (bind(pargs->socket_fd, (struct sockaddr *) pargs->address, pargs->address_length) != 0){
        printf("could not bind\n");
        error_setg(pargs->errp, "Qemu pmemaccess: bind failed");
        return;
    }

    // listen
    if (listen(pargs->socket_fd, 0) != 0){
        error_setg(pargs->errp, "Qemu pmemaccess: listen failed");
        return;
    }

    // start the thread
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &oldset);
    pthread_create(&thread, NULL, memory_access_thread, pargs);
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
}
