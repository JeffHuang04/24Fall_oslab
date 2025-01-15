
#include "klib.h"
#include "cte.h"
#include "proc.h"

#define PROC_NUM 64

static __attribute__((used)) int next_pid = 1;

proc_t pcb[PROC_NUM];
static proc_t *curr = &pcb[0];

void init_proc() {
  // WEEK1: init proc status
  pcb[0].status = RUNNING;
  // WEEK2: add ctx and kstack for interruption
  pcb[0].kstack = (void *)(KER_MEM - PGSIZE);
  pcb[0].ctx = &pcb[0].kstack->ctx;
  // WEEK3: add pgdir
  pcb[0].pgdir = vm_curr();
  pcb[0].tgid = pcb[0].pid;
  pcb[0].group_leader = &pcb[0];
  pcb[0].thread_num = 1;
  pcb[0].thread_group = NULL;
  pcb[0].joinable = 1;
  pcb[0].detached = 0;
  sem_init(&pcb[0].join_sem, 0);
  pcb[0].sigblocked = 0;
  for(int i = 0;i < SIGNAL_NUM;i++){
    pcb[0].sigaction[i] = handle_signal;
  }
  list_init(&pcb[0].sigpending_queue);
  // WEEK5: semaphore
  //TODO();
  // Lab2-1, set status and pgdir
  // Lab2-4, init zombie_sem
  // Lab3-2, set cwd
}

proc_t *proc_alloc() {
  // WEEK1: alloc a new proc, find a unused pcb from pcb[1..PROC_NUM-1], return NULL if no such one
  //TODO();
  for (int i = 1; i < PROC_NUM; i++){
      if (pcb[i].status == UNUSED){
        pcb[i].pid = next_pid++;
        pcb[i].status = UNINIT;
        //pcb[i].kstack = (kstack_t *)(KER_MEM - 2 * PGSIZE);
        pcb[i].pgdir = vm_alloc();
        pcb[i].kstack = kalloc();
        pcb[i].ctx = &pcb[i].kstack->ctx;
        pcb[i].parent = NULL;
        pcb[i].child_num = 0;
        sem_init(&pcb[i].zombie_sem, 0);
        for(int j = 0; j< MAX_USEM;j++){
          pcb[i].usems[j] = NULL;
        }
        //TODO();初始化其他所有成员
        pcb[i].tgid = pcb[i].pid;
        pcb[i].group_leader = &pcb[i];
        pcb[i].thread_num = 1;
        pcb[i].thread_group = NULL;
        pcb[i].joinable = 1;
        pcb[i].detached = 0;
        sem_init(&pcb[i].join_sem, 0);
        pcb[i].sigblocked = 0;
        for(int j = 0;j < SIGNAL_NUM;j++){
          pcb[i].sigaction[j] = handle_signal;
        }
        list_init(&pcb[i].sigpending_queue);
        return &pcb[i];
      }
  }
  return NULL;
}

void proc_free(proc_t *proc) {
  // WEEK3-virtual-memory: free proc's pgdir and kstack and mark it UNUSED
  //TODO();
  proc->status = UNUSED;
  vm_teardown(proc->pgdir);
  proc->pgdir = NULL;
  proc->kstack = NULL;
  proc->ctx = NULL;
  proc->pid = -1;
  proc->brk = 0;
}

void thread_free(proc_t *thread){
  thread->status = UNUSED;
  thread->kstack = NULL;
  thread->group_leader = NULL;
  thread->thread_group = NULL;
  thread->ctx = NULL;
  thread->pid = -1;
  thread->brk = 0;
}

proc_t *proc_curr() {
  return curr;
}
void proc_run(proc_t *proc) {
  // WEEK3: virtual memory
  proc->status = RUNNING;
  curr = proc;
  set_cr3(proc->pgdir);
  set_tss(KSEL(SEG_KDATA), (uint32_t)STACK_TOP(proc->kstack));
  do_signal(proc);
  irq_iret(proc->ctx);
}



void proc_addready(proc_t *proc) {
  // WEEK4-process-api: mark proc READY
  //TODO();
  proc->status = READY;
}

void proc_yield() {
  // WEEK4-process-api: mark curr proc READY, then int $0x81
  curr->status = READY;
  INT(0x81);
}

void proc_copycurr(proc_t *proc) {
  // WEEK4-process-api: copy curr proc
  proc_t *curr_proc = proc_curr();
  proc_t *leader = curr_proc->group_leader;
  vm_copycurr(proc->pgdir);
  proc->brk = leader->brk;
  proc->kstack->ctx = curr_proc->kstack->ctx;
  proc->kstack->ctx.eax = 0;
  proc->parent = leader;
  leader->child_num++;
  // WEEK5-semaphore: dup opened usems
  for(int i = 0;i< MAX_USEM;i++){
    if(leader->usems[i] != NULL){
      proc->usems[i] = leader->usems[i];
      usem_dup(proc->usems[i]);
    }
  }
  // Lab3-1: dup opened files
  // Lab3-2: dup cwd
  // TODO();
}


void proc_makezombie(proc_t *proc, int exitcode) {
  // WEEK4-process-api: mark proc ZOMBIE and record exitcode, set children's parent to NULL
  proc->status = ZOMBIE;
  proc->exit_code = exitcode;
  for(int i = 0; i< PROC_NUM;i++){
    if(pcb[i].parent == proc){
      //pcb[i].parent = NULL;
      proc_set_kernel_parent(&pcb[i]);
    }
  }
  // WEEK5-semaphore: release parent's semaphore
  if (proc->parent != NULL){
    sem_v(&proc->parent->zombie_sem);
  }
  for (int i = 0; i < MAX_USEM; i++){
    if (proc->usems[i] != NULL){
      usem_close(proc->usems[i]);
    }
  }
  sem_v(&(proc->join_sem));
  // Lab3-1: close opened files
  // Lab3-2: close cwd
  //TODO();
}

proc_t *proc_findzombie(proc_t *proc) {
  // WEEK4-process-api: find a ZOMBIE whose parent is proc, return NULL if none
  //TODO();
  for(int i = 0; i< PROC_NUM;i++){
    if(pcb[i].parent == proc && pcb[i].status == ZOMBIE){
      return &pcb[i];
    }
  }
  return NULL;
}

void proc_block() {
  // WEEK4-process-api: mark curr proc BLOCKED, then int $0x81
  curr->status = BLOCKED;
  INT(0x81);
}

int proc_allocusem(proc_t *proc) {
  // WEEK5: find a free slot in proc->usems, return its index, or -1 if none
  //TODO();
  for(int i = 0; i < MAX_USEM; i++){
    if (proc->group_leader->usems[i] == NULL){
      return i;
    }
  }
  return -1;
}

usem_t *proc_getusem(proc_t *proc, int sem_id) {
  // WEEK5: return proc->usems[sem_id], or NULL if sem_id out of bound
  //TODO();
  if(sem_id >= MAX_USEM|| sem_id < 0){
    return NULL;
  }
  return proc->group_leader->usems[sem_id];
}

int proc_allocfile(proc_t *proc) {
  // Lab3-1: find a free slot in proc->files, return its index, or -1 if none
  TODO();
}

file_t *proc_getfile(proc_t *proc, int fd) {
  // Lab3-1: return proc->files[fd], or NULL if fd out of bound
  TODO();
}

void schedule(Context *ctx) {
  // WEEK4-process-api: save ctx to curr->ctx, then find a READY proc and run it
  //TODO();
  proc_t *proc = proc_curr();
  proc->ctx = ctx;
  int next_proc_index = (proc - pcb + 1) % PROC_NUM;
  for(int i = 0;i < PROC_NUM;i++){
    proc_t *next_proc = &pcb[next_proc_index];
    if(next_proc->status == READY){
      proc_run(next_proc);
      return;
    } 
    next_proc_index = (next_proc_index + 1) % PROC_NUM;
  }
  proc_run(proc);
}

int thread_detach(int tid){
  proc_t *find_thread = NULL;
  for(int i = 0;i < PROC_NUM;i++){
    if(pcb[i].pid == tid){
      find_thread = &pcb[i];
    }
  }
  if(find_thread == NULL && find_thread->detached == 1){
    return -1;  
  }
  find_thread->detached = 1;
  find_thread->joinable = 0;
  return 0;
}
void proc_set_kernel_parent(proc_t *proc){
  proc_t *kernel = proc_curr();
  proc->parent = kernel;
  kernel->child_num++;
}
proc_t *pid2proc(int pid){
  for(int i = 0;i < PROC_NUM;i++){
    if(pcb[i].pid == pid){
      return &pcb[i];
    }
  }
  return NULL;
}

void do_signal(proc_t *proc){
  list_t *node = proc->sigpending_queue.next;
  while (node != &proc->sigpending_queue){
    int signo = (int)(intptr_t)(node->ptr);
    if (!(proc->sigblocked & (1 << signo))) {
            proc->sigaction[signo](signo,proc);
            list_remove(&proc->sigpending_queue,node);
            break;
        } else {
            node = node->next;
        }
  }
}


void handle_signal(int signo, proc_t *proc) {
  // WEEK8-signal
  assert(signo >= 0 && signo < SIGNAL_NUM);
  switch (signo) {
    case SIGSTOP:
      // Handle SIGHUP logic
      //TODO();
      if(proc->status == RUNNING){
        INT(0x81);
      }
      proc->status = BLOCKED;
      break;

    case SIGCONT:
      // TODO: Implement SIGCONT logic here
      //TODO();
      proc->status = READY;
      break;

    case SIGKILL:
      // Handle SIGKILL signal
      //TODO();
      // proc_t *thread = find_proc->thread_group;
      proc_t *find_proc = proc;
      if(find_proc == NULL|| find_proc->group_leader != find_proc){
        //return -1;
        break;
      }
      proc_t *thread = proc->thread_group;
      while (thread != NULL){
        proc_t *next = thread->thread_group;
        thread_free(thread);
        thread = next;
      }
      proc_makezombie(find_proc,9);
      if(find_proc == proc_curr()){
        INT(0x81);
      }
      //return 0;
      break;

    case SIGUSR1:
      printf("Signal SIGUSR1 in proc %d is not defined.\n", proc_curr()->tgid);
      break;

    case SIGUSR2:
      printf("Signal SIGUSR2 in proc %d is not defined.\n", proc_curr()->tgid);
      break;

    default:
      printf("Received an invalid signal number: %d\n", signo);
      panic("Signal error");
      break;
  }
}