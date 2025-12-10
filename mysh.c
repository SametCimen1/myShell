#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_TOKENS 256
#define MAX_TOKEN_LEN 1024
#define MAX_ARGS 128
#define BUFFER_SIZE 4096
#define PATH_SEARCH_DIRS 3

typedef struct {
    char *tokens[MAX_TOKENS];
    int count;
} TokenList;

typedef struct {
    char *args[MAX_ARGS];
    int arg_count;
    char *input_file;
    char *output_file;
} Command;

typedef struct {
    Command commands[MAX_ARGS];
    int count;
    int is_conditional;
    int condition_type;
} Pipeline;


int tokenize(const char *line, TokenList *tokens);
int parse_pipeline(TokenList *tokens, Pipeline *pipeline);
int execute_pipeline(Pipeline *pipeline, int *last_status, int is_batch, int *terminate_parent, int *terminate_status);
int execute_builtin_in_parent(Command *cmd, int *status);
int execute_builtin_in_child(Command *cmd);
char *find_program(const char *name);
void free_pipeline(Pipeline *pipeline);
void free_tokens(TokenList *tokens);


static const char *search_dirs[PATH_SEARCH_DIRS] = { "/usr/local/bin", "/usr/bin", "/bin" };


int main(int argc, char *argv[]) {
    int input_fd = STDIN_FILENO;
    int input_is_tty = isatty(STDIN_FILENO);
    int interactive = 0;  
    int batch_from_stdin = 0; 
    int have_executed_any = 0;
    int last_status = EXIT_SUCCESS;

    if (argc == 2) {
        input_fd = open(argv[1], O_RDONLY);
        if (input_fd < 0) {
            perror("mysh");
            return EXIT_FAILURE;
        }

        interactive = 0;
        batch_from_stdin = 0;
    } else if (argc == 1) {
        if (input_is_tty) {
            interactive = 1;
            batch_from_stdin = 0;
        } else {
            interactive = 0;
            batch_from_stdin = 1;
        }
        input_fd = STDIN_FILENO;
    } else {
        fprintf(stderr, "Usage: %s [script]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (interactive) {
        printf("Welcome to my shell!\n");
    }

    char buffer[BUFFER_SIZE];
    int buffer_pos = 0;

    while (1) {
        if (interactive) {
            printf("mysh> ");
            fflush(stdout);
        }

        int found_newline = 0;
        buffer_pos = 0;
        while (!found_newline) {
            ssize_t n = read(input_fd, buffer + buffer_pos, BUFFER_SIZE - buffer_pos - 1);
            if (n < 0) {
                perror("read");
                goto done;
            }
            if (n == 0) {
       
                if (buffer_pos == 0) goto done;

                buffer[buffer_pos] = '\0';
                found_newline = 1;
                break;
            }
            buffer_pos += n;

            for (int i = 0; i < buffer_pos; ++i) {
                if (buffer[i] == '\n') {
                    buffer[i] = '\0';
                    found_newline = 1;
                                  break;
                }
            }

            if (!found_newline && buffer_pos >= BUFFER_SIZE - 1) {

                fprintf(stderr, "mysh: input line too long\n");

                buffer_pos = 0;
                break;
            }
        }

        if (buffer_pos == 0) {

            continue;
        }

        char *comment = strchr(buffer, '#');
        if (comment) *comment = '\0';


        int len = strlen(buffer);
        while (len > 0 && (buffer[len - 1] == ' ' || buffer[len - 1] == '\t')) buffer[--len] = '\0';

        int start = 0;
        while (start < len && (buffer[start] == ' ' || buffer[start] == '\t')) start++;

        if (start >= len) {
        
            continue;
        }

        TokenList tokens;
        if (tokenize(buffer + start, &tokens) <= 0) {
            continue;
        }

        Pipeline pipeline;
        if (parse_pipeline(&tokens, &pipeline) != 0) {
        
            last_status = EXIT_FAILURE;
            free_tokens(&tokens);
            continue;
        }

        
        if (pipeline.is_conditional && !have_executed_any) {
            fprintf(stderr, "mysh: syntax error: conditional with no previous command\n");
            last_status = EXIT_FAILURE;
            free_pipeline(&pipeline);
            free_tokens(&tokens);
            continue;
        }

        
        if (pipeline.is_conditional) {
            if (pipeline.condition_type == 1) {
        
                if (last_status != EXIT_SUCCESS) {

                    free_pipeline(&pipeline);
                    free_tokens(&tokens);
                    continue;
                }
            } else if (pipeline.condition_type == 2) {

                if (last_status == EXIT_SUCCESS) {
                    free_pipeline(&pipeline);
                    free_tokens(&tokens);
                    continue;
                }
            }
        }

       
        int terminate_parent = 0;
        int terminate_status = EXIT_SUCCESS;
        if (execute_pipeline(&pipeline, &last_status, batch_from_stdin, &terminate_parent, &terminate_status) != 0) {
       
        }

        have_executed_any = 1;

        if (terminate_parent) {
       
            free_pipeline(&pipeline);
            free_tokens(&tokens);
            if (input_fd != STDIN_FILENO) close(input_fd);
            if (interactive) printf("Exiting my shell.\n");
            exit(terminate_status);
        }

        free_pipeline(&pipeline);
        free_tokens(&tokens);
    }

done:
    if (interactive) {
        printf("Exiting my shell.\n");
    }
    if (input_fd != STDIN_FILENO) close(input_fd);
    return EXIT_SUCCESS;
}

int tokenize(const char *line, TokenList *tokens) {
    tokens->count = 0;
    const char *p = line;

    while (*p && tokens->count < MAX_TOKENS) {

        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (!*p) break;

        char token[MAX_TOKEN_LEN];
        int len = 0;

        if (*p == '<' || *p == '>' || *p == '|') {
            token[len++] = *p++;
        } else {
            while (*p && *p != ' ' && *p != '\t' && *p != '<' && *p != '>' && *p != '|') {
                if (len < MAX_TOKEN_LEN - 1) token[len++] = *p;
                p++;
            }
        }
        token[len] = '\0';
        tokens->tokens[tokens->count] = malloc(len + 1);
        if (!tokens->tokens[tokens->count]) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        strcpy(tokens->tokens[tokens->count], token);
        tokens->count++;
    }

    return tokens->count;
}


int parse_pipeline(TokenList *tokens, Pipeline *pipeline) {
    pipeline->count = 0;
    pipeline->is_conditional = 0;
    pipeline->condition_type = 0;

    int idx = 0;
    if (idx < tokens->count && (strcmp(tokens->tokens[idx], "and") == 0 || strcmp(tokens->tokens[idx], "or") == 0)) {
        pipeline->is_conditional = 1;
        pipeline->condition_type = (strcmp(tokens->tokens[idx], "and") == 0) ? 1 : 2;
        idx++;
        if (idx >= tokens->count) {
            fprintf(stderr, "mysh: syntax error: conditional with no command\n");
            return -1;
        }
    }

    int saw_pipe = 0;
    while (idx < tokens->count && pipeline->count < MAX_ARGS) {
        if (strcmp(tokens->tokens[idx], "|") == 0) {
       
            fprintf(stderr, "mysh: syntax error: unexpected '|'\n");
            return -1;
        }

        Command cmd;
        cmd.arg_count = 0;
        cmd.input_file = NULL;
        cmd.output_file = NULL;

        while (idx < tokens->count) {
            char *tok = tokens->tokens[idx];

            if (strcmp(tok, "|") == 0) {
                saw_pipe = 1;
                idx++;
                break;
            } else if (strcmp(tok, "<") == 0) {
                idx++;
                if (idx >= tokens->count) {
                    fprintf(stderr, "mysh: syntax error: missing file after <\n");

                    for (int j = 0; j < cmd.arg_count; ++j) free(cmd.args[j]);
                    return -1;
                }
                if (cmd.input_file) {
                    fprintf(stderr, "mysh: syntax error: multiple input redirections\n");
                    for (int j = 0; j < cmd.arg_count; ++j) free(cmd.args[j]);
                    return -1;
                }
                cmd.input_file = malloc(strlen(tokens->tokens[idx]) + 1);
                if (!cmd.input_file) { perror("malloc"); exit(EXIT_FAILURE); }
                strcpy(cmd.input_file, tokens->tokens[idx]);
                idx++;
            } else if (strcmp(tok, ">") == 0) {
                idx++;
                if (idx >= tokens->count) {
                    fprintf(stderr, "mysh: syntax error: missing file after >\n");
                    for (int j = 0; j < cmd.arg_count; ++j) free(cmd.args[j]);
                    return -1;
                }
                if (cmd.output_file) {
                    fprintf(stderr, "mysh: syntax error: multiple output redirections\n");
                    for (int j = 0; j < cmd.arg_count; ++j) free(cmd.args[j]);
                    return -1;
                }
                cmd.output_file = malloc(strlen(tokens->tokens[idx]) + 1);
                if (!cmd.output_file) { perror("malloc"); exit(EXIT_FAILURE); }
                strcpy(cmd.output_file, tokens->tokens[idx]);
                idx++;
            } else if (strcmp(tok, "and") == 0 || strcmp(tok, "or") == 0) {
                
                if (saw_pipe) {
                    fprintf(stderr, "mysh: syntax error: conditional after pipe\n");
                    for (int j = 0; j < cmd.arg_count; ++j) free(cmd.args[j]);
                    if (cmd.input_file) free(cmd.input_file);
                    if (cmd.output_file) free(cmd.output_file);
                    return -1;
                } else {

                    fprintf(stderr, "mysh: syntax error: unexpected conditional\n");
                    for (int j = 0; j < cmd.arg_count; ++j) free(cmd.args[j]);
                    if (cmd.input_file) free(cmd.input_file);
                    if (cmd.output_file) free(cmd.output_file);
                    return -1;
                }
            } else {
                if (cmd.arg_count >= MAX_ARGS - 1) {
                    fprintf(stderr, "mysh: too many arguments\n");
                    for (int j = 0; j < cmd.arg_count; ++j) free(cmd.args[j]);
                    return -1;
                }
                cmd.args[cmd.arg_count] = malloc(strlen(tok) + 1);
                if (!cmd.args[cmd.arg_count]) { perror("malloc"); exit(EXIT_FAILURE); }
                strcpy(cmd.args[cmd.arg_count], tok);
                cmd.arg_count++;
                idx++;
            }
        }

        if (cmd.arg_count == 0) {
            fprintf(stderr, "mysh: syntax error\n");
            if (cmd.input_file) free(cmd.input_file);
            if (cmd.output_file) free(cmd.output_file);
            return -1;
        }
        cmd.args[cmd.arg_count] = NULL;
        pipeline->commands[pipeline->count++] = cmd;
    }

   
    if (pipeline->count > 1) {
        for (int i = 0; i < pipeline->count; ++i) {
            if (pipeline->commands[i].input_file || pipeline->commands[i].output_file) {
                fprintf(stderr, "mysh: syntax error: redirection in pipeline not allowed\n");
                return -1;
            }
        }
    }

    return 0;
}


int execute_pipeline(Pipeline *pipeline, int *last_status, int is_batch, int *terminate_parent, int *terminate_status) {
    *terminate_parent = 0;
    *terminate_status = EXIT_SUCCESS;

    if (pipeline->count == 0) return 0;

    
    int is_single = (pipeline->count == 1);
    Command *single_cmd = &pipeline->commands[0];


    int job_has_exit = 0;
    int job_has_die = 0;
    for (int i = 0; i < pipeline->count; ++i) {
        if (pipeline->commands[i].arg_count > 0) {
            if (strcmp(pipeline->commands[i].args[0], "exit") == 0) job_has_exit = 1;
            if (strcmp(pipeline->commands[i].args[0], "die") == 0) job_has_die = 1;
        }
    }


    if (is_single && single_cmd->input_file == NULL && single_cmd->output_file == NULL) {
        int builtin_ret = execute_builtin_in_parent(single_cmd, last_status);
        if (builtin_ret == 0) {

            if (job_has_die) {
                *terminate_parent = 1;
                *terminate_status = EXIT_FAILURE;
            } else if (job_has_exit) {
                *terminate_parent = 1;
                *terminate_status = EXIT_SUCCESS;
            }
            return 0;
        }

    }


    int nproc = pipeline->count;
    int pipes[nproc - 1][2];
    for (int i = 0; i < nproc - 1; ++i) {
        if (pipe(pipes[i]) < 0) {
            perror("pipe");
            *last_status = EXIT_FAILURE;
            return -1;
        }
    }

    pid_t pids[nproc];
    for (int i = 0; i < nproc; ++i) pids[i] = -1;

    for (int i = 0; i < nproc; ++i) {
        Command *cmd = &pipeline->commands[i];

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            *last_status = EXIT_FAILURE;
        
            for (int j = 0; j < nproc - 1; ++j) {
                close(pipes[j][0]); close(pipes[j][1]);
            }
            return -1;
        }

        if (pid == 0) {

            if (i > 0) {
                if (dup2(pipes[i-1][0], STDIN_FILENO) < 0) { perror("dup2"); _exit(EXIT_FAILURE); }
            } else {

                if (is_batch) {
                   
                    int fd = open("/dev/null", O_RDONLY);
                    if (fd >= 0) {
                        if (dup2(fd, STDIN_FILENO) < 0) { perror("dup2"); close(fd); _exit(EXIT_FAILURE); }
                        close(fd);
                    }
                }
            }

 
            if (i < nproc - 1) {
                if (dup2(pipes[i][1], STDOUT_FILENO) < 0) { perror("dup2"); _exit(EXIT_FAILURE); }
            }


            if (cmd->input_file) {
                int fd = open(cmd->input_file, O_RDONLY);
                if (fd < 0) { fprintf(stderr, "mysh: %s: %s\n", cmd->input_file, strerror(errno)); _exit(EXIT_FAILURE); }
                if (dup2(fd, STDIN_FILENO) < 0) { perror("dup2"); close(fd); _exit(EXIT_FAILURE); }
                close(fd);
            }
            if (cmd->output_file) {
                int fd = open(cmd->output_file, O_WRONLY | O_CREAT | O_TRUNC, 0640);
                if (fd < 0) { fprintf(stderr, "mysh: %s: %s\n", cmd->output_file, strerror(errno)); _exit(EXIT_FAILURE); }
                if (dup2(fd, STDOUT_FILENO) < 0) { perror("dup2"); close(fd); _exit(EXIT_FAILURE); }
                close(fd);
            }

        
            for (int j = 0; j < nproc - 1; ++j) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }


            if (cmd->arg_count > 0 && (strcmp(cmd->args[0], "cd") == 0 || strcmp(cmd->args[0], "pwd") == 0 ||
                                       strcmp(cmd->args[0], "which") == 0 || strcmp(cmd->args[0], "exit") == 0 ||
                                       strcmp(cmd->args[0], "die") == 0)) {
                int code = execute_builtin_in_child(cmd);
                _exit(code);
            }


            char *program = find_program(cmd->args[0]);
            if (!program) {
                fprintf(stderr, "mysh: %s: command not found\n", cmd->args[0]);
                _exit(EXIT_FAILURE);
            }
            execv(program, cmd->args);

            perror("execv");
            _exit(EXIT_FAILURE);
        } else {

            pids[i] = pid;
    
        }
    }


    for (int j = 0; j < nproc - 1; ++j) {
        close(pipes[j][0]);
        close(pipes[j][1]);
    }


    int status;
    for (int i = 0; i < nproc; ++i) {
        if (pids[i] > 0) {
            if (waitpid(pids[i], &status, 0) < 0) {
                perror("waitpid");
                *last_status = EXIT_FAILURE;
            } else {
                if (i == nproc - 1) {
                    if (WIFEXITED(status)) *last_status = WEXITSTATUS(status);
                    else *last_status = EXIT_FAILURE;
                }
            }
        }
    }

    
    if (job_has_die) {
        *terminate_parent = 1;
        *terminate_status = EXIT_FAILURE;
    } else if (job_has_exit) {
        *terminate_parent = 1;
        *terminate_status = EXIT_SUCCESS;
    }

    return 0;
}

int execute_builtin_in_parent(Command *cmd, int *status) {
    if (cmd->arg_count == 0) return 1;

    if (strcmp(cmd->args[0], "cd") == 0) {
        if (cmd->arg_count != 2) {
            fprintf(stderr, "mysh: cd: wrong number of arguments\n");
            *status = EXIT_FAILURE;
            return 0;
        }
        if (chdir(cmd->args[1]) < 0) {
            fprintf(stderr, "cd: %s: %s\n", cmd->args[1], strerror(errno));
            *status = EXIT_FAILURE;
            return 0;
        }
        *status = EXIT_SUCCESS;
        return 0;
    }

    if (strcmp(cmd->args[0], "pwd") == 0) {
        if (cmd->arg_count != 1) {
            fprintf(stderr, "mysh: pwd: wrong number of arguments\n");
            *status = EXIT_FAILURE;
            return 0;
        }
        char cwd[4096];
        if (!getcwd(cwd, sizeof(cwd))) {
            perror("getcwd");
            *status = EXIT_FAILURE;
            return 0;
        }
        printf("%s\n", cwd);
        *status = EXIT_SUCCESS;
        return 0;
    }

    if (strcmp(cmd->args[0], "which") == 0) {
        if (cmd->arg_count != 2) {
            fprintf(stderr, "mysh: which: wrong number of arguments\n");
            *status = EXIT_FAILURE;
            return 0;
        }

        if (strcmp(cmd->args[1], "cd") == 0 || strcmp(cmd->args[1], "pwd") == 0 ||
            strcmp(cmd->args[1], "which") == 0 || strcmp(cmd->args[1], "exit") == 0 ||
            strcmp(cmd->args[1], "die") == 0) {
            *status = EXIT_FAILURE;
            return 0;
        }
        char *prog = find_program(cmd->args[1]);
        if (prog) {
            printf("%s\n", prog);
            *status = EXIT_SUCCESS;
            return 0;
        }
        *status = EXIT_FAILURE;
        return 0;
    }

    if (strcmp(cmd->args[0], "exit") == 0) {
     
        exit(EXIT_SUCCESS);
    }

    if (strcmp(cmd->args[0], "die") == 0) {

        for (int i = 1; i < cmd->arg_count; ++i) {
            if (i > 1) printf(" ");
            printf("%s", cmd->args[i]);
        }
        if (cmd->arg_count > 1) printf("\n");
        exit(EXIT_FAILURE);
    }

    return 1; 
}


int execute_builtin_in_child(Command *cmd) {
    if (cmd->arg_count == 0) return EXIT_FAILURE;

    if (strcmp(cmd->args[0], "cd") == 0) {

        if (cmd->arg_count != 2) {
            fprintf(stderr, "mysh: cd: wrong number of arguments\n");
            return EXIT_FAILURE;
        }
        if (chdir(cmd->args[1]) < 0) {
            fprintf(stderr, "cd: %s: %s\n", cmd->args[1], strerror(errno));
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    if (strcmp(cmd->args[0], "pwd") == 0) {
        if (cmd->arg_count != 1) {
            fprintf(stderr, "mysh: pwd: wrong number of arguments\n");
            return EXIT_FAILURE;
        }
        char cwd[4096];
        if (!getcwd(cwd, sizeof(cwd))) {
            perror("getcwd");
            return EXIT_FAILURE;
        }
        printf("%s\n", cwd);
        return EXIT_SUCCESS;
    }

    if (strcmp(cmd->args[0], "which") == 0) {
        if (cmd->arg_count != 2) {
            fprintf(stderr, "mysh: which: wrong number of arguments\n");
            return EXIT_FAILURE;
        }
        if (strcmp(cmd->args[1], "cd") == 0 || strcmp(cmd->args[1], "pwd") == 0 ||
            strcmp(cmd->args[1], "which") == 0 || strcmp(cmd->args[1], "exit") == 0 ||
            strcmp(cmd->args[1], "die") == 0) {
            return EXIT_FAILURE;
        }
        char *prog = find_program(cmd->args[1]);
        if (prog) {
            printf("%s\n", prog);
            return EXIT_SUCCESS;
        }
        return EXIT_FAILURE;
    }

    if (strcmp(cmd->args[0], "exit") == 0) {
        return EXIT_SUCCESS; 
    }
    if (strcmp(cmd->args[0], "die") == 0) {
        for (int i = 1; i < cmd->arg_count; ++i) {
            if (i > 1) printf(" ");
            printf("%s", cmd->args[i]);
        }
        if (cmd->arg_count > 1) printf("\n");
        return EXIT_FAILURE;
    }

    return EXIT_FAILURE;
}


char *find_program(const char *name) {
    static char pathbuf[2048];

    if (strchr(name, '/')) {
        if (access(name, X_OK) == 0) {
            strncpy(pathbuf, name, sizeof(pathbuf) - 1);
            pathbuf[sizeof(pathbuf) - 1] = '\0';
            return pathbuf;
        }
        return NULL;
    }

    for (int i = 0; i < PATH_SEARCH_DIRS; ++i) {
        int len = snprintf(pathbuf, sizeof(pathbuf), "%s/%s", search_dirs[i], name);
        if (len < 0 || len >= (int)sizeof(pathbuf)) continue;
        if (access(pathbuf, X_OK) == 0) return pathbuf;
    }
    return NULL;
}


void free_pipeline(Pipeline *pipeline) {
    for (int i = 0; i < pipeline->count; ++i) {
        Command *c = &pipeline->commands[i];
        for (int j = 0; j < c->arg_count; ++j) {
            free(c->args[j]);
        }
        if (c->input_file) free(c->input_file);
        if (c->output_file) free(c->output_file);
    }
}


void free_tokens(TokenList *tokens) {
    for (int i = 0; i < tokens->count; ++i) {
        free(tokens->tokens[i]);
    }
}