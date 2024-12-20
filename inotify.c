#include <sys/inotify.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

// Function to get process information for a given PID
void log_process_info(pid_t pid) {
    char proc_path[PATH_MAX];
    char exe_path[PATH_MAX];
    ssize_t len;

    // Construct the path to the process's exe link
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    // Resolve the symbolic link to get the binary location
    len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0';  // Null-terminate the path
        printf("Process ID: %d, Executable: %s\n", pid, exe_path);
    } else {
        printf("Process ID: %d, Unable to determine executable (error: %s)\n", pid, strerror(errno));
    }
}

// Function to interpret and display the event mask
void print_event_mask(uint32_t mask) {
    printf("Event mask: ");
    if (mask & IN_ACCESS)         printf("IN_ACCESS ");
    if (mask & IN_ATTRIB)         printf("IN_ATTRIB ");
    if (mask & IN_CLOSE_NOWRITE)  printf("IN_CLOSE_NOWRITE ");
    if (mask & IN_CLOSE_WRITE)    printf("IN_CLOSE_WRITE ");
    if (mask & IN_CREATE)         printf("IN_CREATE ");
    if (mask & IN_DELETE)         printf("IN_DELETE ");
    if (mask & IN_DELETE_SELF)    printf("IN_DELETE_SELF ");
    if (mask & IN_MODIFY)         printf("IN_MODIFY ");
    if (mask & IN_MOVE_SELF)      printf("IN_MOVE_SELF ");
    if (mask & IN_MOVED_FROM)     printf("IN_MOVED_FROM ");
    if (mask & IN_MOVED_TO)       printf("IN_MOVED_TO ");
    if (mask & IN_OPEN)           printf("IN_OPEN ");
    printf("\n");
}

// Function to handle an individual event
void handle_event(const char *path_to_watch, struct inotify_event *event) {
    char full_path[PATH_MAX];

    // Build the full path of the file
    if (event->len > 0) {
        snprintf(full_path, PATH_MAX, "%s/%s", path_to_watch, event->name);
        printf("Event on file: %s\n", full_path);
    } else {
        printf("Event on directory: %s\n", path_to_watch);
    }

    // Print event mask details
    print_event_mask(event->mask);

    // Log current process info (for demonstration purposes, logs only the monitor process)
    pid_t pid = getppid();
    printf("Triggered by:\n");
    log_process_info(pid);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_watch>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *path_to_watch = argv[1];
    int fd, watch_descriptor;
    char buffer[EVENT_BUF_LEN];

    // Initialize inotify
    fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    // Add watch for all events
    watch_descriptor = inotify_add_watch(fd, path_to_watch,
        IN_ACCESS | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_CREATE |
        IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM |
        IN_MOVED_TO | IN_OPEN);
    if (watch_descriptor == -1) {
        perror("inotify_add_watch");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("Monitoring %s for all events...\n", path_to_watch);

    // Event loop
    while (1) {
        ssize_t length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            perror("read");
            close(fd);
            exit(EXIT_FAILURE);
        }

        ssize_t i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            printf("\n--- Event Detected ---\n");
            handle_event(path_to_watch, event);
            printf("----------------------\n");

            i += EVENT_SIZE + event->len;
        }
    }

    // Cleanup (not reached in this example)
    inotify_rm_watch(fd, watch_descriptor);
    close(fd);
    return 0;
}