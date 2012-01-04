#ifndef PROCESS_H
#define PROCESS_H

void trace_attach(pid_t pid);

pid_t run_traceable(char *path, char *args[], int no_randomize, int notsc);

pid_t run_traceable_env(char *path, char *args[], char *envp[],
                        int no_randomize, int notsc);

/* caller frees */
char *get_proc_exe(pid_t pid);
char *get_proc_cwd(pid_t pid);
char *get_proc_fd(pid_t pid, int fd);

#endif /* PROCESS_H */
