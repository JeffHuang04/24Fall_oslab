
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
        //TODO();初始化其他所有成员
        return &pcb[i];
      }
  }
  return NULL;
}

void proc_free(proc_t *proc) {
  // WEEK3-virtual-memory: free proc's pgdir and kstack and mark it UNUSED

  TODO();
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
  irq_iret(proc->ctx);
}



void proc_addready(proc_t *proc) {
  // WEEK4-process-api: mark proc READY
  TODO();
}

void proc_yield() {
  // WEEK4-process-api: mark curr proc READY, then int $0x81
  curr->status = READY;
  INT(0x81);
}

void proc_copycurr(proc_t *proc) {
  // WEEK4-process-api: copy curr proc
  // WEEK5-semaphore: dup opened usems
  // Lab3-1: dup opened files
  // Lab3-2: dup cwd
  // TODO();
}

void proc_makezombie(proc_t *proc, int exitcode) {
  // WEEK4-process-api: mark proc ZOMBIE and record exitcode, set children's parent to NULL

  // WEEK5-semaphore: release parent's semaphore

  // Lab3-1: close opened files
  // Lab3-2: close cwd
  TODO();
}

proc_t *proc_findzombie(proc_t *proc) {
  // WEEK4-process-api: find a ZOMBIE whose parent is proc, return NULL if none
  TODO();
}

void proc_block() {
  // WEEK4-process-api: mark curr proc BLOCKED, then int $0x81
  curr->status = BLOCKED;
  INT(0x81);
}

int proc_allocusem(proc_t *proc) {
  // WEEK5: find a free slot in proc->usems, return its index, or -1 if none
  TODO();
}

usem_t *proc_getusem(proc_t *proc, int sem_id) {
  // WEEK5: return proc->usems[sem_id], or NULL if sem_id out of bound
  TODO();
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
  TODO();
}