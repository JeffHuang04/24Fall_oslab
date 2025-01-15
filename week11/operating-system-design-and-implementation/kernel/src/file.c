#include "klib.h"
#include "file.h"
#include "proc.h"
#include "vme.h"

#define TOTAL_FILE 128

file_t files[TOTAL_FILE];

#define TOTAL_PIPE 32

static pipe_t pipes[TOTAL_PIPE];

static pipe_t *pipe_alloc();
void pipe_init(pipe_t *pipe);


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

file_t *fopen(const char *path, int mode,int depth) {
  if(depth>40){
    return NULL;
  }
  file_t *fp = falloc();
  inode_t *ip = NULL;
  if (!fp) goto bad;
  // TODO: Lab3-2, determine type according to mode
  // iopen in Lab3-2: if file exist, open and return it
  //       if file not exist and type==TYPE_NONE, return NULL
  //       if file not exist and type!=TYPE_NONE, create the file as type
  // you can ignore this in Lab3-1
  int open_type = 114514;
  if (mode & O_CREATE){
    if (mode & O_DIR)
      open_type = TYPE_DIR;
    else
      open_type = TYPE_FILE;
  }else{
    open_type = TYPE_NONE;
  }
  ip = iopen(path, open_type);
  if (!ip) goto bad;
  int type = itype(ip);
  if (type == TYPE_FILE || type == TYPE_DIR) {
    // TODO: Lab3-2, if type is not DIR, go bad if mode&O_DIR
    if ((mode & O_DIR) && type != TYPE_DIR)
      goto bad;
    // TODO: Lab3-2, if type is DIR, go bad if mode WRITE or TRUNC
    if (type == TYPE_DIR && ((mode & O_WRONLY) || (mode & O_RDWR) || (mode & O_TRUNC)))
      goto bad;
    // TODO: Lab3-2, if mode&O_TRUNC, trunc the file
    if (type == TYPE_FILE && (mode & O_TRUNC))
      itrunc(ip);

    fp->type = TYPE_FILE; // file_t don't and needn't distingush between file and dir
    fp->inode = ip;
    fp->offset = 0;
  } else if (type == TYPE_DEV) {
    fp->type = TYPE_DEV;
    fp->dev_op = dev_get(idevid(ip));
    iclose(ip);
    ip = NULL;
  } else if (type == TYPE_SYMLINK) {
        char target_path[MAX_NAME + 1] = {0};
        if (iread(ip, 0, target_path, MAX_NAME + 1) != MAX_NAME + 1) 
            goto bad;
        iclose(ip);
        ip = NULL;
        return fopen(target_path, mode,depth + 1);
  } else if(type == TYPE_FIFO){
    pipe_t *pipe = (pipe_t *)ififoaddr(ip);
    if(pipe->no != ino(ip)){
      pipe = pipe_alloc();
      pipe_init(pipe);
      isetfifo(ip,pipe);
      pipe->no = ino(ip);
    }
    fp->type = TYPE_FIFO;
    fp->pipe = pipe;
    fp->inode = ip;
  }else assert(0);
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
    }else if (file->type == TYPE_PIPE || file->type == TYPE_FIFO) {
      return pipe_read(file, buf, size);  // 管道读取
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
  }else if (file->type == TYPE_PIPE|| file->type == TYPE_FIFO) {
    return pipe_write(file, buf, size);  // 管道写入
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
  if (file->ref == 0){
    if(file->type == TYPE_FILE|| file->type == TYPE_FIFO){
      iclose(file->inode);
    }else if (file->type == TYPE_PIPE) {
      pipe_t *pipe = file->pipe;
      if (!pipe) return;
      sem_p(&pipe->mutex);
      if (file->readable) {
          pipe->read_open = 0;
      }
      if (file->writable) {
          pipe->write_open = 0;
      }
      if (!pipe->read_open && !pipe->write_open) {
          pipe_close(pipe);
      }
      if (&pipe->cv_buf.value < 0){
          sem_v(&pipe->cv_buf);
      }
      sem_v(&pipe->mutex);    
    }
  }
}

int flink(const char *oldpath, const char *newpath){
  inode_t *old_inode = iopen(oldpath,TYPE_NONE);
    if (!old_inode) {
        return -1;
    }
    inode_t *new_inode = ilink(newpath, old_inode);
    if (!new_inode) {
        iclose(old_inode);
        return -1;
    }
    iclose(old_inode);
    return 0;
}

int fsymlink(const char *oldpath, const char *newpath){
  inode_t *existing_inode = iopen(newpath,TYPE_NONE);
    if (existing_inode) {
        iclose(existing_inode);
        return -1; // newpath 已存在，返回失败
    }
    // 创建 newpath 文件
    inode_t *new_inode = iopen(newpath, TYPE_SYMLINK);
    char buffer[MAX_NAME + 1] = {0}; // 初始化为全 0
    strncpy(buffer, oldpath, MAX_NAME); // 拷贝 oldpath 到缓冲区，确保不会溢出
    if (iwrite(new_inode, 0, buffer, MAX_NAME + 1) != MAX_NAME + 1) {
        iclose(new_inode);
        return -1; // 写入失败，返回错误
    }
    iclose(new_inode);
    return 0; // 返回成功
}

static pipe_t *pipe_alloc(){
    for (int i = 0; i < TOTAL_PIPE; i++) {
        if (pipes[i].read_open == 0 && pipes[i].write_open == 0) {
            return &pipes[i];
        }
    }
    return NULL;
}

void pipe_init(pipe_t *pipe){
    // 初始化分配的管道
    pipe->read_pos = 0;
    pipe->write_pos = 0;
    pipe->read_open = 1;
    pipe->write_open = 1;
    pipe->full = 0;
    pipe->empty = PIPE_SIZE;
    sem_init(&pipe->mutex, 1);
    sem_init(&pipe->cv_buf, 0);
    pipe->no = 0;
}

int pipe_open(file_t *pipe_files[2]) {
  // TODO: WEEK11-link-pipe
  pipe_t *pipe = pipe_alloc();
  if(!pipe) return -1;

  // alloc read_side and write_side
  file_t *read_side = falloc();
  file_t *write_side = falloc();
  if (!read_side || !write_side) {
      if (read_side) fclose(read_side);
      if (write_side) fclose(write_side);
      return -1;
  }
  assert(read_side && write_side);

  // 设置文件结构
  read_side->type = TYPE_PIPE;
  read_side->pipe = pipe;
  read_side->inode = NULL;
  read_side->dev_op = NULL;
  read_side->readable = 1;
  read_side->writable = 0;
  read_side->offset = 0;
  read_side->ref = 1;

  write_side->type = TYPE_PIPE;
  write_side->pipe = pipe;
  write_side->inode = NULL;
  write_side->dev_op = NULL;
  write_side->readable = 0;
  write_side->writable = 1;
  write_side->offset = 0;
  write_side->ref = 1;

  // 初始化管道结构
  pipe_init(pipe);

  pipe_files[0] = read_side;
  pipe_files[1] = write_side;

  assert(pipe_files[0] && pipe_files[1]);

  return 0;
}

void pipe_close(pipe_t *pipe) {
  // TODO: WEEK11-link-pipe
  assert(pipe);
  pipe->read_open = 0;
  pipe->write_open = 0;
  memset(pipe->buffer, 0, PIPE_SIZE);
}

int pipe_write(file_t *file, const void *buf, uint32_t size) {
 void *buff = (void *)buf;
  int n = 0;
  while (size) {
    sem_p(&file->pipe->mutex);
    if (file->pipe->write_open == 0) {
      sem_v(&file->pipe->mutex);
      return -1;
    }
    if (file->pipe->read_open == 0 && !file->pipe->empty) {
      sem_v(&file->pipe->mutex);
      return n;
    }
    if (!file->pipe->empty && file->pipe->read_open) {
      sem_v(&file->pipe->mutex);
      sem_p(&file->pipe->cv_buf);
      sem_p(&file->pipe->mutex);
    }
    if (file->pipe->read_open == 0 && !file->pipe->empty) {
      sem_v(&file->pipe->mutex);
      return n;
    }
    if (file->pipe->read_open == 0 && file->pipe->write_open == 0) {
      sem_v(&file->pipe->mutex);
      continue;
    }
    int len = MIN(size, file->pipe->empty);
    len = MIN(len, PIPE_SIZE - file->pipe->write_pos);
    memcpy(file->pipe->buffer + file->pipe->write_pos, buff, len);
    file->pipe->write_pos += len;
    file->pipe->write_pos %= PIPE_SIZE;
    file->pipe->empty -= len;
    file->pipe->full += len;
    if(file->pipe->cv_buf.value < 0){
      sem_v(&file->pipe->cv_buf);
    }
    sem_v(&file->pipe->mutex);
    size -= len;
    buff += len;
    n += len;
  }  
  return n;
}

int pipe_read(file_t *file, void *buf, uint32_t size) {
 int n = 0;
  while (size) {
    sem_p(&file->pipe->mutex);
    if (file->pipe->read_open == 0) {
      sem_v(&file->pipe->mutex);
      return -1;
    }
    if (file->pipe->write_open == 0 && !file->pipe->full) {
      sem_v(&file->pipe->mutex);
      return n;
    }
    while (!file->pipe->full && file->pipe->write_open) {
      sem_v(&file->pipe->mutex);
      sem_p(&file->pipe->cv_buf);
      sem_p(&file->pipe->mutex);
    }
    if (file->pipe->write_open == 0 && !file->pipe->full) {
      sem_v(&file->pipe->mutex);
      return n;
    }
    if (file->pipe->read_open == 0 && file->pipe->write_open == 0) {
      sem_v(&file->pipe->mutex);
      continue;
    }
    
    int tlen = MIN(size, file->pipe->full);
    while (tlen) {
      int len = MIN(tlen, PIPE_SIZE - file->pipe->read_pos);
      memcpy(buf, file->pipe->buffer + file->pipe->read_pos, len);

      file->pipe->read_pos += len;
      file->pipe->read_pos %= PIPE_SIZE;
      file->pipe->empty += len;
      file->pipe->full -= len;
      if(file->pipe->cv_buf.value < 0){
        sem_v(&file->pipe->cv_buf);
      }
      sem_v(&file->pipe->mutex);
      size -= len;
      buf += len;
      n += len;
      tlen -= len;
    }
    break;

  }
  return n;     
}
file_t *mkfifo(const char *path, int mode) {
    inode_t *existing_inode = iopen(path, TYPE_NONE);
    if (existing_inode != NULL) {
        return NULL;
    }
    inode_t *inode = iopen(path, TYPE_FIFO);
    if (inode == NULL) {
        return NULL;
    }
    pipe_t *pipe = pipe_alloc();
    pipe_init(pipe);
    isetfifo(inode,pipe);
    pipe->no = ino(inode);
    file_t *file = falloc();
    if (file == NULL) {
        return NULL;
    }
    file->readable = 1;
    file->writable = 1;
    file->inode = inode;
    file->pipe = pipe;
    file->type = TYPE_FIFO;
    file->offset = 0;
    iclose(inode);
    return file;
}

void rmfifo(int no){
  pipe_close((pipe_t *)no);
};
