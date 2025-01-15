#include "klib.h"
#include "file.h"
#include "proc.h"
#include "vme.h"

#define TOTAL_FILE 128

file_t files[TOTAL_FILE];

static file_t *falloc() {
  // Lab3-1: find a file whose ref==0, init it, inc ref and return it, return NULL if none
  //TODO();
  file_t *p = NULL;
  for(int i = 0;i < TOTAL_FILE;i++){
    if(files[i].ref == 0){
      p = &files[i];
      break;
    }
  }
  p->ref++;
  p->type = TYPE_NONE;
  return p;
}

file_t *fopen(const char *path, int mode) {
  file_t *fp = falloc();
  inode_t *ip = NULL;
  if (!fp) goto bad;
  // TODO: Lab3-2, determine type according to mode
  // iopen in Lab3-2: if file exist, open and return it
  //       if file not exist and type==TYPE_NONE, return NULL
  //       if file not exist and type!=TYPE_NONE, create the file as type
  // you can ignore this in Lab3-1
  int open_type = 114514;
  ip = iopen(path, open_type);
  if (!ip) goto bad;
  int type = itype(ip);
  if (type == TYPE_FILE || type == TYPE_DIR) {
    // TODO: Lab3-2, if type is not DIR, go bad if mode&O_DIR

    // TODO: Lab3-2, if type is DIR, go bad if mode WRITE or TRUNC

    // TODO: Lab3-2, if mode&O_TRUNC, trunc the file

    fp->type = TYPE_FILE; // file_t don't and needn't distingush between file and dir
    fp->inode = ip;
    fp->offset = 0;
  } else if (type == TYPE_DEV) {
    fp->type = TYPE_DEV;
    fp->dev_op = dev_get(idevid(ip));
    iclose(ip);
    ip = NULL;
  } else assert(0);
  fp->readable = !(mode & O_WRONLY);
  fp->writable = (mode & O_WRONLY) || (mode & O_RDWR);
  return fp;
bad:
  if (fp) fclose(fp);
  if (ip) iclose(ip);
  return NULL;
}

int fread(file_t *file, void *buf, uint32_t size) {
  // Lab3-1, distribute read operation by file's type
  // remember to add offset if type is FILE (check if iread return value >= 0!)
  if (!file->readable) return -1;
  //TODO();
  PD *pgdir = vm_curr();
  for (size_t offset = 0; offset < size; offset += PGSIZE) {
    void *addr = buf + offset;
    PTE *pte = vm_walkpte(pgdir,(size_t)addr,0);
    if(pte == NULL || pte->read_write == 0){
      vm_pgfault((size_t)addr,2);
    }
  }
  int bytes_read = 0;
  if (file->type == TYPE_FILE) {
    bytes_read = iread(file->inode, file->offset,buf, size);
    if (bytes_read > 0) {
      file->offset += bytes_read;
      }
    } else if (file->type == TYPE_DEV) {
      return file->dev_op->read(buf, size);
    }
    return bytes_read;
}

int fwrite(file_t *file, const void *buf, uint32_t size) {
  // Lab3-1, distribute write operation by file's type
  // remember to add offset if type is FILE (check if iwrite return value >= 0!)
  if (!file->writable) return -1;
  //TODO();
  int bytes_write = 0;
  if(file->type == TYPE_FILE){
    bytes_write = iwrite(file->inode, file->offset,buf, size);
    if(bytes_write > 0){
      file->offset += bytes_write;
    }
  }else if (file->type == TYPE_DEV){
    return file->dev_op->write(buf,size);
  }
  return bytes_write;
}

uint32_t fseek(file_t *file, uint32_t off, int whence) {
  // Lab3-1, change file's offset, do not let it cross file's size
  if (file->type == TYPE_FILE) {
    //TODO();
    int file_size = isize(file->inode);
    switch (whence){
    case SEEK_SET:
      file->offset = off;
      return file->offset;
      break;
    case SEEK_CUR:
      file->offset += off;
      return file->offset;
      break;
    case SEEK_END:
      file->offset = file_size + off;
      return file->offset;
      break;
    default:
      assert(0);
      break;
    }
  }
  return -1;
}

file_t *fdup(file_t *file) {
  // Lab3-1, inc file's ref, then return itself
  //TODO();
  file->ref++;
  return file;
}

void fclose(file_t *file) {
  // Lab3-1, dec file's ref, if ref==0 and it's a file, call iclose
  //TODO();
  file->ref--;
  if (file->ref == 0 && file->type == TYPE_FILE){
    iclose(file->inode);
  }
}

