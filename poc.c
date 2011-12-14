#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <netinet/in.h>

/* Attach to process pid */
void ptrace_attach(int pid)
{
	if ((ptrace(PTRACE_ATTACH , pid , NULL , NULL)) < 0) {
		perror("ptrace_attach");
		exit(-1);
	}

	waitpid(pid, NULL, WUNTRACED);
}

/* Continue execution */
void ptrace_cont(int pid)
{
	int s;

	if ((ptrace(PTRACE_CONT, pid, NULL, NULL)) < 0) {
		perror("ptrace_cont");
		exit(-1);
	}

	do {
	//	waitpid(pid, &s, WNOHANG);
		waitpid(pid, &s, 0);
	} while (!WIFSTOPPED(s));
}

/* Detach from process pid */
void ptrace_detach(int pid)
{
	if (ptrace(PTRACE_DETACH, pid , NULL , NULL) < 0) {
		perror("ptrace_detach");
		exit(-1);
	}
}

/*************
 ************* FIXME: alignment etc. on x86-64 ?
 *************/

/* Read data from location addr */
void *ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
	int i , count;
	uint32_t word;
	unsigned long *ptr = (unsigned long *) vptr;

	count = i = 0;

	while (count < len) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
		count += 4;
		ptr[i++] = word;
	}
}

/* Write data to location addr */
void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
	int i, count;
	uint32_t word;

	i = count = 0;

	while (count < len) {
		memcpy(&word, vptr+count, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
		count +=4;
	}
}

/*****/

int main(int argc, char *argv[])
{
	/* a trick for GCC */
	int foo = 1;
	if (foo == 1) goto code_end;

code_start:
/*
 * Run bind(fd, {AF_INET, INADDR_ANY, 0}, 16)
 *
 * bind() is a system call run through a multiplexing system call of socketcall(2). So indeed, we do
 * the syscall %eax=102 (the multiplexer gateway), with a subcode of %ebx=2 (the bind function).
 *
 */
asm(
	"jmp data\n\t"

"run_bind:\n\t"
	/* load address of data to %ecx */
	"popl   %esi\n\t"
	"movl   %esi, %ecx\n\t"

	/* run bind */
	"movl   $102, %eax\n\t"    /* 102 <-> socketcall(2) */
	"movl   $2, %ebx\n\t"      /*   2 <-> bind(2) */
	"int    $0x80\n\t"         /* syscall! */

	/* done: go back to the sniffer */
	"int3\n\t"

	/* data part */
"data: call run_bind\n\t"

	/* socketcall arguments: fd, *addr, addrlen */
	".long 0x12345678\n\t"  /* fd = 0 */
	".long 0x00000000\n\t"  /* *addr = NULL */
	".long 0x00000010\n\t"  /* addrlen = 16 */

	/* struct sockaddr addr */
	".long 0x0002\n\t"      /* .sin_family = AF_INET */
	".long 0x0000\n\t"      /* .sin_port = 0 */
	".long 0x00000000\n\t"  /* .sin_addr = 0.0.0.0 */
	".long 0x00000000\n\t"  /* .sin_zero */
	".long 0x00000000\n\t"  /* .sin_zero */
);
code_end: if (0);

	int i;
	int len, len_aligned;
	uint32_t *args;
	struct sockaddr_in *sa;

	/***************** get the machine code */

	/* get length */
	len = &&code_end - &&code_start;
	len_aligned = len + (len % 4 ? (4 - len%4) : 0);

	/* copy the code */
	char code[len_aligned], *data;
	memset(code, 0, len_aligned);
	memcpy(code, &&code_start, len);

	/* find args location */
	for (data = code + len - 4; data > code; data--) {
		if (*((uint32_t *) data) == 0x12345678)
			break;
	}

	args = (uint32_t *) (data);

	/**************** attach */
#if 1

	pid_t traced_process;
	struct user_regs_struct regs;
	char backup[len_aligned];

	if (argc != 2) {
		printf("Usage: %s <pid to be traced>\n", argv[0], argv[1]);
		exit(1);
	}

	/* attach */
	traced_process = atoi(argv[1]);
	ptrace_attach(traced_process);

	/* Store registers at regs */
	ptrace(PTRACE_GETREGS, traced_process, NULL, &regs);

	/* Patch our code */
	args[0] = 3; /* FIXME: fd */
//	args[1] = regs.eip + (data - code) + 12;
	args[1] = regs.eip + (data - code) + 12;

	/* Overwrite code at EIP, making a backup first */
	ptrace_read(traced_process, regs.eip, backup, len_aligned);
	ptrace_write(traced_process, regs.eip, code, len_aligned);

	/* Execute the code and wait until the breakpoint is hit */
	ptrace_cont(traced_process);

	/* User input */
/*	printf("The process stopped, putting back the original instructions\n");
	printf("Press <enter> to continue\n");
	getchar();*/

	/* Restore original code and register values */
	ptrace_write(traced_process, regs.eip, backup, len);
	ptrace(PTRACE_SETREGS, traced_process, NULL, &regs);

	/* detach */
	ptrace_detach(traced_process);
#endif

	return 0;
}
