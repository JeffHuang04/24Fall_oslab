#include "klib.h"
#include "cte.h"
#include "sysnum.h"
#include "vme.h"
#include "serial.h"
#include "loader.h"
#include "proc.h"
#include "timer.h"
#include "file.h"

typedef int (*syshandle_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

extern void *syscall_handle[NR_SYS];

void do_syscall(Context *ctx) {
  // TODO: WEEK2-interrupt call specific syscall handle and set ctx register
  int sysnum = ctx->eax;
  uint32_t arg1 = ctx->ebx;
  uint32_t arg2 = ctx->ecx;
  uint32_t arg3 = ctx->edx;
  uint32_t arg4 = ctx->esi;
  uint32_t arg5 = ctx->edi;
  int res;
  if (sysnum < 0 || sysnum >= NR_SYS) {
    res = -1;
  } else {
    res = ((syshandle_t)(syscall_handle[sysnum]))(arg1, arg2, arg3, arg4, arg5);
  }
  ctx->eax = res;
}

int sys_write(int fd, const void *buf, size_t count) {
  // TODO: rewrite me at Lab3-1
  //return serial_write(buf, count);
  proc_t *curr_proc = proc_curr()->group_leader;
  file_t *fp = proc_getfile(curr_proc, fd);
  if (fp == NULL)
    return -1;
  return fwrite(fp, buf, count);
}

int sys_read(int fd, void *buf, size_t count) {
  // TODO: rewrite me at Lab3-1
  //return serial_read(buf, count);
  proc_t *curr_proc = proc_curr()->group_leader;
  file_t *fp = proc_getfile(curr_proc, fd);
  if (fp == NULL)
    return -1;
  return fread(fp, buf, count);
}

int sys_brk(void *addr) {
  // TODO: WEEK3-virtual-memory
  proc_t * proc = proc_curr();// uncomment me in WEEK3-virtual-memory
  size_t brk = proc->group_leader->brk; // rewrite me
  size_t new_brk = PAGE_UP((size_t)addr); // rewrite me
  if (brk == 0) {
    proc->group_leader->brk = new_brk; // uncomment me in WEEK3-virtual-memory
  } else if (new_brk > brk) {
    vm_map(proc->group_leader->pgdir, brk, new_brk - brk, 7);
    proc->group_leader->brk = new_brk;
  } else if (new_brk < brk) {
    // can just do nothing
    proc->group_leader->brk = new_brk;
    // recover memory, Lab 1 extend
  }
  return 0;
}

void sys_sleep(int ticks) {
  // TODO(); // WEEK2-interrupt
  uint32_t beg_tick = get_tick();
  while(get_tick() - beg_tick <= ticks){
    //sti(); hlt(); cli(); // chage to me in WEEK2-interrupt
    proc_yield(); // change to me in WEEK4-process-api
    // thread_yield();
  }
  return;
}

int sys_exec(const char *path, char *const argv[]) {
  // TODO(); // WEEK2-interrupt, WEEK3-virtual-memory
  // DEFAULT
  proc_t *proc = proc_curr()->group_leader;
  PD *pgdir = vm_alloc();
  if (load_user(pgdir, proc->ctx, path, argv) != 0) {
    return -1;
  }
  proc->pgdir = pgdir;
  set_cr3(pgdir);

  proc_t *thread = proc->thread_group;
  while(thread != NULL){
    if(thread == proc){
      thread = thread->thread_group;
      continue;
    }else{
      thread_free(thread);
      thread = thread->thread_group;
    }
  }
  proc->thread_num = 1;
  proc->thread_group = NULL;
  set_tss(KSEL(SEG_KDATA), (uint32_t)proc->kstack + PGSIZE);
  //irq_iret(proc->ctx);
  proc_run(proc);
  return 0;
}

int sys_getpid() {
  //TODO(); // WEEK3-virtual-memory
  return proc_curr()->tgid;
}

int sys_gettid() {
  //TODO(); // Lab2-1
  return proc_curr()->pid;
}

void sys_yield() {
  proc_yield();
}

int sys_fork() {
  //TODO(); // WEEK4-process-api
  proc_t *pcb = proc_alloc();
  if(pcb == NULL){
    return -1;
  }
  proc_copycurr(pcb);
  proc_addready(pcb);
  return pcb->pid;
}

void sys_exit_group(int status) {
  //TODO();
  // WEEK4 process api
  // while (1) proc_yield();
  proc_t *curr_proc = proc_curr();
  proc_t *now_proc = curr_proc->group_leader->thread_group;
  while(now_proc != NULL){
    proc_t *next = now_proc->thread_group;
    thread_free(now_proc);
    now_proc = next;
  }
  proc_makezombie(curr_proc->group_leader,status);
  INT(0x81);
  assert(0);
}


void sys_exit(int status) {
  //TODO();
  proc_t *curr = proc_curr();
  proc_t *leader = curr->group_leader;
  if(curr != leader){
    if(curr->detached == 1){
        proc_t *currPtr = leader->thread_group;
        while (currPtr != NULL){
          if(currPtr == curr){
            currPtr->thread_group = currPtr->thread_group;
            break;
          }
          currPtr = currPtr->thread_group;
        }
      proc_set_kernel_parent(curr);
    }
      curr->group_leader->thread_num--;
      proc_makezombie(curr,status);
      INT(0x81);
  }else{
    while(curr->group_leader->thread_num > 1){
      proc_yield();
    }
    //assert(curr->group_leader->thread_num > 1);
    sys_exit_group(status);
  }
}


int sys_wait(int *status) {
  //TODO(); // WEEK4 process api
  // sys_sleep(250);
  // return 0;
  proc_t *curr_proc = proc_curr()->group_leader;
  if (curr_proc->child_num == 0){
    return -1;
  }
  sem_p(&curr_proc->zombie_sem);
  proc_t *child_proc = proc_findzombie(curr_proc);
  while(child_proc == NULL)
  {
    proc_yield();
    child_proc = proc_findzombie(curr_proc);
  }
  
  if (status != NULL){
    *status = child_proc->exit_code;
  }
  int pid = child_proc->pid;
  proc_free(child_proc);
  curr_proc->child_num--;
  return pid;
}

int sys_sem_open(int value) {
  //TODO(); // WEEK5-semaphore
  proc_t *curr_proc = proc_curr()->group_leader;
  int index = proc_allocusem(curr_proc);
  if (index == -1){
    return -1;
  }
  usem_t *usem_ptr = usem_alloc(value);
  if(usem_ptr == NULL){
    return -1;
  }
  curr_proc->usems[index] = usem_ptr;
  return index;
}

int sys_sem_p(int sem_id) {
  //TODO(); // WEEK5-semaphore
  usem_t *tmp = proc_getusem(proc_curr()->group_leader,sem_id);
  if(tmp == NULL){
    return -1;
  }
  sem_p(&tmp->sem);
  return 0;
}

int sys_sem_v(int sem_id) {
  //TODO(); // WEEK5-semaphore
  usem_t *tmp = proc_getusem(proc_curr()->group_leader,sem_id);
  if(tmp == NULL){
    return -1;
  }
  sem_v(&tmp->sem);
  return 0;
}

int sys_sem_close(int sem_id) {
  //TODO(); // WEEK5-semaphore
  usem_t *tmp = proc_getusem(proc_curr()->group_leader,sem_id);
  if(tmp == NULL){
    return -1;
  }
  usem_close(tmp);
  tmp = NULL;
  //proc_curr()->usems[sem_id] = NULL;
  return 0;
}

int sys_open(const char *path, int mode) {
  //TODO(); // Lab3-1
  proc_t *curr_proc = proc_curr()->group_leader;
  int fd = proc_allocfile(curr_proc);
  if (fd == -1)
    return -1;
  file_t *fp = fopen(path, mode,0);
  if (fp == NULL)
    return -1;
  curr_proc->files[fd] = fp;
  return fd;
}

int sys_close(int fd) {
  //TODO(); // Lab3-1
  proc_t *curr_proc = proc_curr()->group_leader;
  file_t *fp = proc_getfile(curr_proc, fd);
  if (fp == NULL)
    return -1;
  fclose(fp);
  curr_proc->files[fd] = NULL;
  return 0;
}

int sys_dup(int fd) {
  //TODO(); // Lab3-1
  proc_t *curr_proc = proc_curr()->group_leader;
  file_t *fp = proc_getfile(curr_proc, fd);
  if (fp == NULL)
    return -1;
  int new_fd = proc_allocfile(curr_proc);
  if (new_fd == -1)
    return -1;
  curr_proc->files[new_fd] = fdup(fp);
  return new_fd;
}

uint32_t sys_lseek(int fd, uint32_t off, int whence) {
  //TODO(); // Lab3-1
  proc_t *curr_proc = proc_curr()->group_leader;
  file_t *fp = proc_getfile(curr_proc, fd);
  if (fp == NULL)
    return -1;
  return fseek(fp, off, whence);
}

int sys_fstat(int fd, struct stat *st) {
  //TODO(); // Lab3-1
  proc_t *curr_proc = proc_curr()->group_leader;
  file_t *fp = proc_getfile(curr_proc, fd);
  if (fp == NULL)
    return -1;
  if (fp->type == TYPE_FILE){
    st->type = itype(fp->inode);
    st->size = isize(fp->inode);
    st->node = ino(fp->inode);
  }else if (fp->type == TYPE_DEV){
    st->type = TYPE_DEV;
    st->size = 0;
    st->node = 0;
  }else if (fp->type == TYPE_PIPE){
    st->type = TYPE_PIPE;
    st->size = fp->pipe->full; 
    st->node = 0;
  }else if (fp->type == TYPE_FIFO) {
    st->type = TYPE_FIFO;
    st->size = ((pipe_t *)ififoaddr(fp->inode))->full;
    st->node = 0;
  }

  return 0;
}

int sys_chdir(const char *path) {
  //TODO(); // Lab3-2
  inode_t *dir = iopen(path, TYPE_NONE);
  if (dir == NULL)
    return -1;
  if (itype(dir) != TYPE_DIR)
  {
    iclose(dir);
    return -1;
  }
  proc_t *curr_proc = proc_curr();
  iclose(curr_proc->cwd);
  curr_proc->cwd = dir;
  return 0;
}

int sys_unlink(const char *path) {
  return iremove(path);
}

// optional syscall

void *sys_mmap() {
  //TODO();
    size_t len = PGSIZE;
    int prot = PTE_P | PTE_W | PTE_U;
    for (uint32_t mmap_va = USR_MEM; mmap_va < VIR_MEM; mmap_va += PGSIZE) {
        // 检查该虚拟地址是否已经映射
        PTE *pte = vm_walkpte(proc_curr()->pgdir, mmap_va, 0);
        if (pte == NULL || pte->present == 0) {
            // 调用 vm_map 为该虚拟地址分配物理内存
            vm_map(proc_curr()->pgdir, mmap_va, len, prot);
            return (void *)mmap_va;  // 返回找到的虚拟地址
        }
    }

    // 没有找到空闲页，返回 NULL 表示 mmap 失败
    return NULL;
}

void sys_munmap(void *addr) {
  //TODO();
   vm_unmap(proc_curr()->pgdir, (size_t)addr, PGSIZE);
}


int sys_clone(int (*entry)(void*), void *stack, void *arg, void (*ret_entry)(void)){
  //TODO();
  proc_t *np = proc_alloc();
  if(np == NULL){
    return -1;
  }
  proc_t *curr = proc_curr();
  np->tgid = curr->tgid;
  np->group_leader = curr->group_leader;

  np->thread_group = curr->group_leader->thread_group;
  curr->group_leader->thread_group = np;

  np->parent = NULL;
  curr->group_leader->thread_num++;
  np->pgdir = curr->pgdir;

  *((uint32_t*)(stack - 4)) = (uint32_t)arg;
  stack -=4;
  *((uint32_t*)(stack - 4)) = (uint32_t)ret_entry;
  stack-=4;
  np->ctx = &np->kstack->ctx;
  np->ctx->cs = USEL(SEG_UCODE);
  np->ctx->ds = USEL(SEG_UDATA);
  np->ctx->eip = (uint32_t)entry;
  np->ctx->ss = USEL(SEG_UDATA);
  np->ctx->esp = (uint32_t)stack;
  np->ctx->ebp = (uint32_t)stack;
  np->ctx->eflags = 0x202;
  proc_addready(np);
  return np->pid;
}

int sys_join(int tid, void **retval) {
  //TODO();
  proc_t *curr = proc_curr();
  proc_t *find_thread = pid2proc(tid);
  if(curr == find_thread || find_thread->joinable != 1){
    return 3;
  }
  find_thread->joinable = 0;
  sem_p(&find_thread->join_sem);
  if (retval != NULL) {
    *retval = (void *)find_thread->exit_code;
  }
  return 0;
}

int sys_detach(int tid) {
  //TODO();
  return thread_detach(tid);
}

int sys_kill(int pid, int signo) {
  //TODO();
  proc_t *find_proc = pid2proc(pid);
  if(find_proc == NULL){// || find_proc->group_leader != find_proc){
    return 3;
  }
  if(!(signo >= 0 && signo < SIGNAL_NUM)){
    return 22;
  }
  if(signo == SIGSTOP || signo == SIGCONT || signo == SIGKILL){
    find_proc->sigaction[signo](signo,find_proc);
  }else{
    list_t *node = find_proc->sigpending_queue.next;
    while (node != &find_proc->sigpending_queue) {
      int existing_signo = (int)(uintptr_t)(node->ptr);
      if (existing_signo == signo) {
        return 0;
      }
      node = node->next;
    }
    list_enqueue(&find_proc->sigpending_queue,(void *)signo);
    }
  return 0;
}


int sys_cv_open() {
  //TODO();
  return sys_sem_open(0);
}

int sys_cv_wait(int cv_id, int sem_id) {
  //TODO();
  sys_sem_v(sem_id);
  sys_sem_p(cv_id);
  return 1 ;
}

int sys_cv_sig(int cv_id) {
  //TODO();
  return sys_sem_v(cv_id);
}

int sys_cv_sigall(int cv_id) {
  //TODO();
  int result = 0;
    while (sys_sem_v(cv_id)) {
        result++;
    }
    return result;
}

int sys_cv_close(int cv_id) {
  //TODO();
  return sys_sem_close(cv_id);
}

int sys_pipe(int fd[2]) {
  //TODO();
    file_t *pipe_files[2];
    if (pipe_open(pipe_files) < 0) {
        return -1;
    }
    int fd0 = proc_allocfile(proc_curr());
    if (fd0 < 0) {
        return -1;
    }
    proc_curr()->group_leader->files[fd0] = pipe_files[0];
    int fd1 = proc_allocfile(proc_curr());
    if (fd1 < 0) {
        return -1;
    }
    proc_curr()->group_leader->files[fd1] = pipe_files[1];
    fd[0] = fd0;
    fd[1] = fd1;
    return 0;
}

int sys_mkfifo(const char *path, int mode){
  //TODO();
  file_t * file = mkfifo(path,mode);
  if(!file){
    return -1;
  }
  int fd = proc_allocfile(proc_curr());
  if (fd < 0) {
        return -1;
    }
  proc_curr()->group_leader->files[fd] = file;
  return fd;
}

int sys_link(const char *oldpath, const char *newpath) {
  //TODO();
  return flink(oldpath,newpath);
}

int sys_symlink(const char *oldpath, const char *newpath) {
  //TODO();
  return fsymlink(oldpath,newpath);
}

int sys_sigaction(int signo, const void *act, void **oldact){
  // WEEK8-signal: set new signal action handler
  //TODO();
  if(signo < 0 || signo >= SIGNAL_NUM){
    return 22;
  }
  proc_t *curr_proc = proc_curr();
  if(oldact!= NULL){
    //oldact = (void *)(uintptr_t)curr_proc->sigaction[signo];
    *oldact = curr_proc->sigaction[signo];
  }
  // curr_proc->sigaction[signo] = (void (*)(int, struct proc *))(uintptr_t)act;
  curr_proc->sigaction[signo] = (void *)act;
  return 0;
}


int sys_sigprocmask(int how, const int set, int *oldset){
  // WEEK8-signal: set new signal action handler
  //TODO();
  proc_t *curr_proc = proc_curr();
  if (oldset!=NULL) {
    *oldset = curr_proc->sigblocked;
  }
  switch (how) {
        case SIG_BLOCK:
            curr_proc->sigblocked |= set;
            break;
        case SIG_UNBLOCK:
            curr_proc->sigblocked &= ~set;
            break;
        case SIG_SETMASK: 
            curr_proc->sigblocked = set;
            break;
        default:
            return -22;
    }
    return 0;
}


void *syscall_handle[NR_SYS] = {
  [SYS_write] = sys_write,
  [SYS_read] = sys_read,
  [SYS_brk] = sys_brk,
  [SYS_sleep] = sys_sleep,
  [SYS_exec] = sys_exec,
  [SYS_getpid] = sys_getpid,
  [SYS_gettid] = sys_gettid,
  [SYS_yield] = sys_yield,
  [SYS_fork] = sys_fork,
  [SYS_exit] = sys_exit,
  [SYS_exit_group] = sys_exit_group,
  [SYS_wait] = sys_wait,
  [SYS_sem_open] = sys_sem_open,
  [SYS_sem_p] = sys_sem_p,
  [SYS_sem_v] = sys_sem_v,
  [SYS_sem_close] = sys_sem_close,
  [SYS_open] = sys_open,
  [SYS_close] = sys_close,
  [SYS_dup] = sys_dup,
  [SYS_lseek] = sys_lseek,
  [SYS_fstat] = sys_fstat,
  [SYS_chdir] = sys_chdir,
  [SYS_unlink] = sys_unlink,
  [SYS_mmap] = sys_mmap,
  [SYS_munmap] = sys_munmap,
  [SYS_clone] = sys_clone,
  [SYS_join] = sys_join,
  [SYS_detach] = sys_detach,
  [SYS_kill] = sys_kill,
  [SYS_cv_open] = sys_cv_open,
  [SYS_cv_wait] = sys_cv_wait,
  [SYS_cv_sig] = sys_cv_sig,
  [SYS_cv_sigall] = sys_cv_sigall,
  [SYS_cv_close] = sys_cv_close,
  [SYS_pipe] = sys_pipe,
  [SYS_mkfifo] = sys_mkfifo,
  [SYS_link] = sys_link,
  [SYS_symlink] = sys_symlink,
  [SYS_sigaction] = sys_sigaction,
  [SYS_sigprocmask] = sys_sigprocmask
  // [SYS_spinlock_open] = sys_spinlock_open,
  // [SYS_spinlock_acquire] = sys_spinlock_acquire,
  // [SYS_spinlock_release] = sys_spinlock_release,
  // [SYS_spinlock_close] = sys_spinlock_close,
};
