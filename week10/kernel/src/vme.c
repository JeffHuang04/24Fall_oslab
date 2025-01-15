#include "klib.h"
#include "vme.h"
#include "proc.h"

static TSS32 tss;
static size_t pm_ref[PHY_MEM/PGSIZE];

void init_gdt() {
  static SegDesc gdt[NR_SEG];
  gdt[SEG_KCODE] = SEG32(STA_X | STA_R,   0,     0xffffffff, DPL_KERN);
  gdt[SEG_KDATA] = SEG32(STA_W,           0,     0xffffffff, DPL_KERN);
  gdt[SEG_UCODE] = SEG32(STA_X | STA_R,   0,     0xffffffff, DPL_USER);
  gdt[SEG_UDATA] = SEG32(STA_W,           0,     0xffffffff, DPL_USER);
  gdt[SEG_TSS]   = SEG16(STS_T32A,     &tss,  sizeof(tss)-1, DPL_KERN);
  set_gdt(gdt, sizeof(gdt[0]) * NR_SEG);
  set_tr(KSEL(SEG_TSS));
}

void set_tss(uint32_t ss0, uint32_t esp0) {
  tss.ss0 = ss0;
  tss.esp0 = esp0;
}

typedef union free_page {
  union free_page *next;
  char buf[PGSIZE];
} page_t;

page_t *free_page_list;

static PT kpt[PHY_MEM / PT_SIZE] __attribute__((used));
static PD kpd;
// WEEK3-virtual-memory

void init_page() {
  extern char end;
  panic_on((size_t)(&end) >= KER_MEM - PGSIZE, "Kernel too big (MLE)");
  static_assert(sizeof(PTE) == 4, "PTE must be 4 bytes");
  static_assert(sizeof(PDE) == 4, "PDE must be 4 bytes");
  static_assert(sizeof(PT) == PGSIZE, "PT must be one page");
  static_assert(sizeof(PD) == PGSIZE, "PD must be one page");


  // WEEK3-virtual-memory: init kpd and kpt, identity mapping of [0 (or 4096), PHY_MEM)
  for (int i = 0; i < PHY_MEM / PT_SIZE; i++){
    kpd.pde[i].val = MAKE_PDE(&kpt[i],1);
    for (int j = 0; j < NR_PTE;j++){
      kpt[i].pte[j].val = MAKE_PTE((i << DIR_SHIFT) | (j << TBL_SHIFT), 1);
    }
  }
  kpt[0].pte[0].val = 0;
  set_cr3(&kpd);
  set_cr0(get_cr0() | CR0_PG);


  // WEEK3-virtual-memory: init free memory at [KER_MEM, PHY_MEM), a heap for kernel
  free_page_list = NULL;
  for (uint32_t addr = KER_MEM; addr < PHY_MEM; addr += PGSIZE) {
    page_t* tmp = free_page_list;
    free_page_list = (page_t*)addr;
    free_page_list->next = tmp;
  }
  memset(pm_ref, 0, sizeof(pm_ref));
}

void *kalloc() {
  // WEEK3-virtual-memory: alloc a page from kernel heap, abort when heap empty
  if (free_page_list == NULL) {
    assert(0);
  }
  page_t *allocated_page = free_page_list;
  free_page_list = free_page_list->next;
  memset(allocated_page, 0, PGSIZE);
  //lab6
  size_t page_index = ((size_t)allocated_page - KER_MEM) / PGSIZE;
  pm_ref[page_index] = 1;

  return allocated_page;
}

void kfree(void *ptr) {
  // WEEK3-virtual-memory: free a page to kernel heap
  // you can just do nothing :)
  page_t *page = (page_t *)ptr;
  //lab6
  size_t page_index = ((size_t)page - KER_MEM) / PGSIZE;
  if (pm_ref[page_index] > 0) {
    pm_ref[page_index]--;
  }
  if (pm_ref[page_index] == 0) {
    page->next = free_page_list;
    free_page_list = page;
  }
}

PD *vm_alloc() {
  // WEEK3-virtual-memory: alloc a new pgdir, map memory under PHY_MEM identityly
  PD* new_pgdir=(PD*)kalloc();
  for(int i=0;i<NR_PDE;i++){
    new_pgdir->pde[i].val = 0;
  }
  for(int i=0;i<PHY_MEM / PT_SIZE;i++){
    new_pgdir->pde[i].val = MAKE_PDE(&kpt[i],1);
  }
  return new_pgdir;
}

void vm_teardown(PD *pgdir) {
  // WEEK3-virtual-memory: free all pages mapping above PHY_MEM in pgdir, then free itself
  // you can just do nothing :)
  //TODO();
}

PD *vm_curr() {
  return (PD*)PAGE_DOWN(get_cr3());
}

PTE *vm_walkpte(PD *pgdir, size_t va, int prot) {
  // WEEK3-virtual-memory: return the pointer of PTE which match va
  // if not exist (PDE of va is empty) and prot&1, alloc PT and fill the PDE
  // if not exist (PDE of va is empty) and !(prot&1), return NULL
  // remember to let pde's prot |= prot, but not pte
  assert((prot & ~7) == 0);
  uint32_t pd_index=ADDR2DIR(va);
  uint32_t pt_index=ADDR2TBL(va);
  PDE *pde = &(pgdir->pde[pd_index]);
  if (!(pde->val & 1)){
    if (prot == 0){
      return NULL;
    }
    PT *new_pt = (PT *)kalloc();
    memset(new_pt,0,PGSIZE);
    pde->val = MAKE_PDE(new_pt,prot);
    return &new_pt->pte[pt_index];
  }else{
    PT* pt=PDE2PT(*pde);
    return &pt->pte[pt_index];
  }
  
}

void *vm_walk(PD *pgdir, size_t va, int prot) {
  // WEEK3-virtual-memory: translate va to pa
  // if prot&1 and prot voilation ((pte->val & prot & 7) != prot), call vm_pgfault
  // if va is not mapped and !(prot&1), return NULL
  //TODO();
  PTE *pte = vm_walkpte(pgdir, va, prot);
  if(pte == NULL){
    return NULL;
  }else{
    return PTE2PG(*pte);
  }
}

void vm_map(PD *pgdir, size_t va, size_t len, int prot) {
  // WEEK3-virtual-memory: map [PAGE_DOWN(va), PAGE_UP(va+len)) at pgdir, with prot
  // if have already mapped pages, just let pte->prot |= prot
  assert(prot & PTE_P);
  assert((prot & ~7) == 0);
  size_t start = PAGE_DOWN(va);
  size_t end = PAGE_UP(va + len);
  assert(end >= start);
  
  for (uint32_t addr = start; addr < end; addr += PGSIZE) {
    PTE *pte = vm_walkpte(pgdir, addr, prot);
    if (pte->present == 0){
      void *new_page = kalloc();
      pte->val = MAKE_PTE(new_page, prot);
    }
    pte->cow = pte->read_write;
  }
  
}

void vm_unmap(PD *pgdir, size_t va, size_t len) {
  // WEEK3-virtual-memory: unmap and free [va, va+len) at pgdir
  // you can just do nothing :)
  //assert(ADDR2OFF(va) == 0);
  //assert(ADDR2OFF(len) == 0);
  //TODO();
}

void vm_copycurr(PD *pgdir) {
  // WEEK4-process-api: copy memory mapped in curr pd to pgdir
  //TODO();
  for(uint32_t va = PHY_MEM;va < USR_MEM; va += PGSIZE){
    PTE *curr_pte = vm_walkpte(vm_curr(),va,0);
    if(curr_pte != NULL && curr_pte->present == 1){
      if(curr_pte->cow == 1){
        curr_pte->read_write = 0;
        size_t phys_addr = curr_pte->page_frame << 12;
        size_t page_index = (phys_addr - KER_MEM) / PGSIZE;
        pm_ref[page_index]++;
        PTE * newPTE = vm_walkpte(pgdir, va, 7);
        newPTE->val = curr_pte->val;
      }else{
        vm_map(pgdir,va,PGSIZE,7);
        void* new = vm_walk(pgdir,va,7);
        void* curr = vm_walk(vm_curr(),va,7);
        memcpy(new,curr,PGSIZE);
      }
    }
  }
  for (uint32_t va = USR_MEM; va < VIR_MEM; va += PGSIZE) {
    PTE *curr_pte = vm_walkpte(vm_curr(), va, 0);
    if (curr_pte != NULL && curr_pte->present == 1) {
      size_t phys_addr = curr_pte->page_frame << 12;
      size_t page_index = (phys_addr - KER_MEM) / PGSIZE;
      pm_ref[page_index]++;
      PTE * newPTE = vm_walkpte(pgdir, va, 7);
      newPTE->val = curr_pte->val;
    }
  }
}

// void vm_pgfault(size_t va, int errcode) {
//   printf("pagefault @ 0x%p, errcode = %d\n", va, errcode);
//   panic("pgfault");
// }

// WEEK6-sychronization
void vm_pgfault(size_t va, int errcode) {
  if (errcode & 2) { // write error
        PD *pgdir = vm_curr();
        PTE *pte = vm_walkpte(pgdir, va, 0);
        // Cases that are not real cow: goto bad
        //TODO();
        if (pte == NULL || !(pte->read_write == 0 && pte->cow == 1)) {
            goto bad;
        }
        // Copy on Write: allocates a new physical page and copies the contents of the original page to the new page
        //TODO();
        pte->read_write = 1;
        size_t phys_addr = pte->page_frame << 12;
        size_t page_index = (phys_addr - KER_MEM) / PGSIZE;
        if (pm_ref[page_index] > 1) {
            void *new_page = kalloc();
            memcpy(new_page, (void *)phys_addr, PGSIZE);
            pte->val = MAKE_PTE(new_page,7);
        }
    } else {
        goto bad;
    }

    set_cr3(vm_curr());
    return;

bad:
    printf("pagefault @ 0x%p, errcode = %d\n", va, errcode);
    panic("pgfault");
}


