#include "klib.h"
#include "serial.h"
#include "vme.h"
#include "cte.h"
#include "loader.h"
#include "fs.h"
#include "proc.h"
#include "timer.h"
#include "dev.h"

void init_user_and_go();

int main() {
  init_gdt();
  init_serial();
  init_fs();
  init_page(); // uncomment me at WEEK3-virtual-memory
  init_cte(); // uncomment me at WEEK2-interrupt
  init_timer(); // uncomment me at WEEK2-interrupt
  init_proc(); // uncomment me at WEEK1-os-start
  init_dev(); // uncomment me at Lab3-1
  printf("Hello from OS!\n");
  init_user_and_go();
  panic("should never come back");
}

void init_user_and_go() {
  // // WEEK3: virtual memory
  // proc_t *proc = proc_alloc();
  // assert(proc);
  // char *argv[] = {"ping2", NULL}; 
  // assert(load_user(proc->pgdir, proc->ctx, "ping2", argv) == 0);
  // proc_addready(proc); 
  // //proc_run(proc);
  // while (1) proc_yield();
proc_t *proc = proc_alloc();
proc->cwd = iopen("/", TYPE_NONE);
assert(proc);
//char *argv[] = {"ping3", "114514", "1919810", NULL};
char *argv[] = {"sh", NULL};
assert(load_user(proc->pgdir, proc->ctx, "sh", argv) == 0);
proc_addready(proc);

// proc = proc_alloc();
// assert(proc);
// argv[1] = "1919810";
// assert(load_user(proc->pgdir, proc->ctx, "ping1", argv) == 0);
// proc_addready(proc);

sti();
proc_t *kernel = proc_curr();
while(1){
    proc_t *proc_child; 
    // Don't use zombie_sem cause there should always be one process being runnable.
    cli(); // close interrupt first
    while(!(proc_child=proc_findzombie(kernel))){
      sti();
      proc_yield();
    }
    if(proc_child->group_leader == proc_child){
      proc_free(proc_child);
    }else{
      thread_free(proc_child);
    }
    kernel->child_num--;
}



}


