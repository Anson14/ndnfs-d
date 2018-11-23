/*
 * Copyright (c) 2013 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Wentao Shang <wentao@cs.ucla.edu>
 *         Qiuhan Ding <dingqiuhan@gmail.com>
 *         Zhehao Wang <wangzhehao410305@gmail.com>
 */

#include "file.h"

#include "signature-states.h"

using namespace std;

int ndnfs_open(const char *path, struct fuse_file_info *fi)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_open: path=" << path << endl;
  // // The actual open operation
  // char full_path[PATH_MAX];
  // abs_path(full_path, path);

  // // Full Path is at /tmp/dir not /tmp/ndnfs

  // int ret = 0;
  // FILE_LOG(LOG_DEBUG)<< "file->flags:"<<fi->flags<< endl;
  // ret = open(full_path, fi->flags);
  // FILE_LOG(LOG_DEBUG)<< "file->flags:"<<fi->flags<< endl;

  // if (ret == -1)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_open: open failed. Full path: " << full_path << ". Errno: " << -errno << endl;
  //   return -errno;
  // }
  // close(ret);

  // Ndnfs versioning operation
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT current_version FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_ROW)
  {
    FILE_LOG(LOG_DEBUG) << "open error!" << endl;
    sqlite3_finalize(stmt);
    return -ENOENT;
  }

  int curr_ver = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);

  int temp_ver = time(0);

  switch (fi->flags & O_ACCMODE)
  { // O_ACCMODE 是一个
  case O_RDONLY:
    // Should we also update version in this case (since the atime has changed)?
    break;
  case O_WRONLY:
  case O_RDWR:

    // Copy old data from current version to the temp version
    // if (duplicate_version(path, curr_ver, temp_ver) < 0) //This function has not been implenmented
    copycurr_segment(path, curr_ver);
    // return -EACCES;

    break;
  default:
    break;
  }

  return 0;
}

/**
 * Create function is replaced with mknod
 * TODO:
 * In Linux(Ubuntu), current implementation reports "utimens: no such file" when executing touch; digging out why.
 * For the newly created file, getattr is called before mknod/open(O_CREAT); wonder how that works.
 */
int ndnfs_mknod(const char *path, mode_t mode, dev_t dev)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_mknod: path=" << path << ", mode=0" << std::oct << mode << endl;

  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT * FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res == SQLITE_ROW)
  {
    // Cannot create file that has conflicting file name
    sqlite3_finalize(stmt);
    return -ENOENT;
  }

  sqlite3_finalize(stmt);

  // We cannot create file without creating necessary folders in advance
  // Get father dir's level
  int level = 0;
  string path_father;
  string name;
  split_last_component(path, path_father, name);
  sqlite3_prepare_v2(db, "SELECT level FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path_father.c_str(), -1, SQLITE_STATIC);
  res = sqlite3_step(stmt);
  if (res != SQLITE_ROW)
  {
    sqlite3_finalize(stmt);
    return -ENOENT;
  }
  level = sqlite3_column_int(stmt, 0);
  level += 1;

  sqlite3_finalize(stmt);
  // Infer the mime_type of the file based on extension
  char mime_type[100] = "";
  mime_infer(mime_type, path); // Get Type of New File

  // Generate first version entry for the new file
  int ver = time(0);

  sqlite3_prepare_v2(db, "INSERT INTO file_versions (path, version) VALUES (?, ?);", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, ver);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  // Add the file entry to database
  sqlite3_prepare_v2(db, "INSERT INTO file_system (path, current_version, mime_type, ready_signed, type, mode, atime, nlink, size, level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, ver);                           // current version
  sqlite3_bind_text(stmt, 3, mime_type, -1, SQLITE_STATIC); // mime_type based on ext

  enum SignatureState signatureState = NOT_READY;
  sqlite3_bind_int(stmt, 4, signatureState);

  enum FileType fileType = REGULAR;

  switch (S_IFMT & mode)
  {
  case S_IFDIR:
    // expect this to call mkdir instead
    break;
  case S_IFCHR:
    fileType = CHARACTER_SPECIAL;
    break;
  case S_IFREG:
    fileType = REGULAR;
    break;
  case S_IFLNK:
    fileType = SYMBOLIC_LINK;
    break;
  case S_IFSOCK:
    fileType = UNIX_SOCKET;
    break;
  case S_IFIFO:
    fileType = FIFO_SPECIAL;
    break;
  default:
    fileType = REGULAR;
    break;
  }
  sqlite3_bind_int(stmt, 5, fileType);
  sqlite3_bind_int(stmt, 6, mode);
  sqlite3_bind_int(stmt, 7, ver);
  // sqlite3_bind_int(stmt, 8, ver);
  sqlite3_bind_int(stmt, 8, 0);
  sqlite3_bind_int(stmt, 9, 0);
  sqlite3_bind_int(stmt, 10, level);

  res = sqlite3_step(stmt);
  // FILE_LOG(LOG_DEBUG) << " Insert into file_system error! fileType= " << mime_type << " ??" << endl;
  // sqlite3_finalize(stmt);
  sqlite3_finalize(stmt);

  // Create the actual file
  // char full_path[PATH_MAX];
  // abs_path(full_path, path);

  // int ret = 0;

  // if (S_ISREG(mode))
  // {
  //   ret = open(full_path, O_CREAT | O_EXCL | O_WRONLY, mode);
  //   if (ret >= 0)
  //   {
  //     ret = close(ret);
  //   }
  // }
  // else if (S_ISFIFO(mode))
  // {
  //   ret = mkfifo(full_path, mode);
  // }
  // else
  // {
  //   ret = mknod(full_path, mode, dev);
  // }

  // if (ret == -1)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_mknod: mknod failed. Full path: " << full_path << ". Errno " << errno << endl;
  //   return -errno;
  // }

  return 0;
}

int ndnfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_read: path=" << path << ", offset=" << std::dec << offset << ", size=" << size << endl;

  // First check if the file entry exists in the database,
  // this now presumes we don't want to do anything with older versions of the file
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT size FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_ROW)
  {
    sqlite3_finalize(stmt);
    return -ENOENT;
  }
  if (sqlite3_column_int(stmt, 0) == 0)
  {
    sqlite3_finalize(stmt);
    return 0;
  }
  sqlite3_finalize(stmt);

  // BIG CHANGE!
  // Read from  db now
  // test bt Anson at 2018.11.20
  int seg_size = ndnfs::seg_size;
  int seg = offset / seg_size;
  int len = 0;
  // Get the segment which nearst to offset
  sqlite3_prepare_v2(db, "SELECT content FROM file_segments WHERE path = ? AND segment =  ? AND version = (SELECT current_version FROM file_system WHERE path = ?);", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, seg);
  sqlite3_bind_text(stmt, 3, path, -1, SQLITE_STATIC);
  res = sqlite3_step(stmt);
  if (res == SQLITE_ROW)
  {
    int content_size = sqlite3_column_bytes(stmt, 0);
    char *content[seg_size];
    memmove(content, (char *)sqlite3_column_blob(stmt, 0), content_size);
    int content_offset = offset - seg * seg_size;
    len += content_size - content_offset;
    memmove(buf, content + content_offset, len);
    // FILE_LOG(LOG_DEBUG)<< "content:"<< content_size<< endl;
    sqlite3_finalize(stmt);
    if (content_size < seg_size)
    {
      // means this segment is the last segment
      return len;
    }
    // If the nearst segment is not enough (missing segment)
    while (len < size)
    {
      seg++;
      // FILE_LOG(LOG_DEBUG) << " len=" << len << " size=" << size << endl;
      sqlite3_prepare_v2(db, "SELECT content FROM file_segments WHERE path = ? AND segment =  ? AND version = (SELECT current_version FROM file_system WHERE path = ?);", -1, &stmt, 0);
      sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
      sqlite3_bind_int(stmt, 2, seg);
      sqlite3_bind_text(stmt, 3, path, -1, SQLITE_STATIC);
      res = sqlite3_step(stmt);
      char *read_content[seg_size];
      if (res == SQLITE_ROW)
      {
        memset(content, '\0', seg_size);
        memset(read_content, '\0', seg_size);
        content_size = sqlite3_column_bytes(stmt, 0);
        // FILE_LOG(LOG_DEBUG)<< "circle: "<< content_size<< endl;
        memmove(content, (char *)sqlite3_column_blob(stmt, 0), content_size);
        int read_len = min(content_size, (int)size - len);
        memmove(read_content, content, read_len);
        sqlite3_finalize(stmt);
        // strcat(buf, read_content);
        // FILE_LOG(LOG_DEBUG)<< "circle: "<< read_len<< endl;
        memmove(buf + len, read_content, read_len);
        len += read_len;
        if (read_len < seg_size)
        {
          return len;
        }
      }
      else
      {
        FILE_LOG(LOG_DEBUG) << "db error!!!" << endl;
        sqlite3_finalize(stmt);
        // break;
        return -errno;
      }
    }
  }

  // Then read from the actual file
  // char full_path[PATH_MAX];
  // abs_path(full_path, path);

  // int fd = open(full_path, O_RDONLY);

  // if (fd == -1)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_read: open error. Errno: " << errno << endl;
  //   return -errno;
  // }

  // int read_len = pread(fd, buf, size, offset);

  // if (read_len < 0)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_read: read error. Errno: " << errno << endl;
  //   return -errno;
  // }
  // // FILE_LOG(LOG_DEBUG)<<" read_len"<< read_len<< endl;
  // close(fd);
  // return read_len;
}

int ndnfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_write: path=" << path << std::dec << ", size=" << size << ", offset=" << offset << endl;

  // First check if the entry exists in the database
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT current_version FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_ROW)
  {
    sqlite3_finalize(stmt);
    return -ENOENT;
  }

  sqlite3_finalize(stmt);

  addtemp_segment(path, buf, size, offset);
  return size;

  // Create or change tmp_version in db (100000 means temp version)
  // char buf_seg[ndnfs::seg_size];
  // int seg_size = ndnfs::seg_size;
  // int seg = 0; // current segment
  // int offset_saved = 0;

  // // Add ".segtemp" after path to indicate this is a temp version
  // char temp_char[9] = ".segtemp";
  // char path_temp[strlen(path) + strlen(temp_char)+1];
  // strcpy(path_temp, path);
  // strcat(path_temp, temp_char);

  // // Insert temp segment into db
  // long long buf_size = (long long ) size;
  // memset(buf_seg, '\0', seg_size);
  // if (offset % seg_size != 0)
  // {
  //   // Get latest content we have inserted into db
  //   seg = offset/(seg_size);
  //   sqlite3_prepare_v2(db, "SELECT content FROM file_segments WHERE path = ? AND segment =  ?", -1, &stmt, 0);
  //   sqlite3_bind_text(stmt, 1, path_temp, -1, SQLITE_STATIC);
  //   sqlite3_bind_int(stmt, 2, seg);
  //   int res = sqlite3_step(stmt);
  //   const char * content_saved = (const char *)sqlite3_column_blob(stmt, 0);
  //   if (res  == SQLITE_ROW)
  //     offset_saved = sqlite3_column_bytes(stmt,0);
  //   sqlite3_finalize(stmt);

  //   int seg_remain = seg_size - offset_saved;
  //   memcpy(buf_seg, content_saved, offset_saved);
  //   char content_add[seg_remain];
  //   memcpy(content_add, buf, min((long long)seg_remain, buf_size));
  //   FILE_LOG(LOG_DEBUG)<< "seg:" << seg<< " "<< " seg_remain:"<< seg_remain<< "offset_saved: "<< offset_saved<<" buf_size:"<< buf_size<<" why???\n";
  //   strcat(buf_seg, content_add);
  //   // FILE_LOG(LOG_DEBUG)<< buf_seg<< " :buf_seg  "<< endl;
  //   sqlite3_prepare_v2(db, "REPLACE INTO file_segments (path,version,segment, signature, content) VALUES (?,100000,?,'NONE', ?);", -1, &stmt, 0);
  //   sqlite3_bind_text(stmt, 1, path_temp, -1, SQLITE_STATIC);
  //   sqlite3_bind_int(stmt, 2, seg);
  //   sqlite3_bind_blob(stmt, 3, buf_seg, offset_saved + min((long long)seg_remain, buf_size), SQLITE_STATIC);
  //   res = sqlite3_step(stmt);
  //   // FILE_LOG(LOG_DEBUG)<< " res:"<< res<<endl;
  //   sqlite3_finalize(stmt);
  //   offset_saved = seg_remain;
  //   FILE_LOG(LOG_DEBUG)<< " Write first success\n";
  // }

  // FILE_LOG(LOG_DEBUG)<< buf_size<<" " << offset_saved<<"  "<<buf_size-offset_saved<< endl;
  // while ((buf_size-offset_saved)> 0)
  // {
  //   FILE_LOG(LOG_DEBUG)<<"Wrinte a new segment"<<endl;
  //   memset(buf_seg, '\0', seg_size);
  //   strncpy(buf_seg, buf + offset_saved, min((long long)seg_size, buf_size+offset - seg * seg_size));
  //   // memset(buf_seg+min((long long)seg_size, buf_size - seg * seg_size),'\0', seg_size - min((long long)seg_size, buf_size - seg * seg_size));
  //   sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO file_segments (path,version,segment, signature, content) VALUES (?,100000,?,'NONE', ?);", -1, &stmt, 0);
  //   sqlite3_bind_text(stmt, 1, path_temp, -1, SQLITE_STATIC);
  //   sqlite3_bind_int(stmt, 2, seg);
  //   sqlite3_bind_blob(stmt, 3, buf_seg, min((long long)seg_size, buf_size-offset_saved), SQLITE_STATIC);
  //   int res = sqlite3_step(stmt);
  //   sqlite3_finalize(stmt);
  //   seg++;

  //   offset_saved += min((long long)seg_size, buf_size+offset_saved);
  //   // FILE_LOG(LOG_DEBUG) << "seg: " << seg << " buf_size: " << buf_size << " seg_size: " << seg_size << " path_temp: " << path_temp << " path: " << path << "answer=" << buf_size - (seg_size * seg)<<" bufseg:"<<buf_seg<<" " <<sizeof(buf_seg) << endl;
  //   if ((buf_size-offset_saved) < 0)
  //   {
  //     break;
  //   }
  // }
  // while (size == ndnfs::seg_size) {
  //   size = pread(fd, buf, ndnfs::seg_size, seg << ndnfs::seg_size_shift);
  //   if (size == -1) {
  //     FILE_LOG(LOG_ERROR) << "ndnfs_release: read error. Errno: " << errno << endl;
  //     return -errno;
  //   }
  //   sign_segment (path, curr_version, seg, buf, size);
  //   seg ++;
  // }

  // Then write the actual file
  // char full_path[PATH_MAX];
  // abs_path(full_path, path);
  // int fd = open(full_path, O_RDWR);
  // if (fd == -1)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_write: open error. Errno: " << errno << endl;
  //   return -errno;
  // }

  // int write_len = pwrite(fd, buf, size, offset);
  // if (write_len < 0)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_write: write error. Errno: " << errno << endl;
  //   return -errno;
  // }

  // close(fd);

  // return write_len; // return the number of bytes written on success
}

int ndnfs_truncate(const char *path, off_t length)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_truncate: path=" << path << " length=" << length << endl;
  // First we check if the entry exists in database
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT MAX(current_version) FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_ROW)
  {
    sqlite3_finalize(stmt);
    return -ENOENT;
  }
  int ver = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);

  truncate_all_segment(path, ver, length);
  
  // For implentation version control, We can not truncate the
  // real file in database
  // easiler, we can just rewrite the segments that user demand.
// 
  // int curr_len = 0;
  // int seg = 0;
  // char data[length];
  // while (curr_len < length)
  // {
  //   sqlite3_prepare_v2(db, "SELECT content FROM file_segments WHERE path = ? AND version = ? AND segment = ?;", -1, &stmt, 0);
  //   sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  //   sqlite3_bind_int(stmt, 2, ver);
  //   sqlite3_bind_int(stmt, 3, seg);
  //   if (sqlite3_step(stmt) != SQLITE_ROW)
  //   {
  //     FILE_LOG(LOG_ERROR) << "No such file!" << endl;
  //     sqlite3_finalize(stmt);
  //     return -ENOENT;
  //   }
  //   int size = sqlite3_column_bytes(stmt, 0);
  //   int len_use = length - (seg * ndnfs::seg_size);
  //   memmove(data+curr_len, (char *)sqlite3_column_blob(stmt, 0), len_use);
  //   curr_len += size;
  //   sqlite3_finalize(stmt);
  //   seg++;
  // }
  // ndnfs_write(path, data, length, 0, NULL);
  // removetemp_segment(path, time(0));
  return 0;

  // Then we truncate the actual file
  // char full_path[PATH_MAX];
  // abs_path(full_path, path);

  // int trunc_ret = truncate(full_path, length);
  // if (trunc_ret == -1)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_truncate: error. Full path " << full_path << ". Errno " << errno << endl;
  //   return -errno;
  // }

  // return res;
}

int ndnfs_unlink(const char *path)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_unlink: path=" << path << endl;

  // It's hard to implement rm -f *
  // string  pre;
  // string name;
  // char prefix[100];
  // split_last_component(path, pre, name);
  // strcpy(prefix, pre.c_str());
  // if (strcmp(name.c_str(), "*") == 0)
  // {
  // if (strcmp(prefix, "/") != 0) {
  //   strcat(prefix, "/");
  // }
  // remove_all_file_entry(path);

  // // Then, remove file entry
  // sqlite3_stmt *stmt;
  // sqlite3_prepare_v2(db, "DELETE FROM file_system WHERE path LIKE ? AND path != '/';", -1, &stmt, 0);
  // sqlite3_bind_text(stmt, 1, p, -1, SQLITE_STATIC);
  // sqlite3_step(stmt);
  // sqlite3_finalize(stmt);
  // }
  // else
  // {

  // TODO: update remove_versions
  remove_file_entry(path);

  // Then, remove file entry
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "DELETE FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  // }

  // char full_path[PATH_MAX];
  // abs_path(full_path, path);
  // int ret = unlink(full_path);

  // if (ret == -1)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_unlink: unlink failed. Errno: " << errno << endl;
  //   return -errno;
  // }

  return 0;
}

int ndnfs_release(const char *path, struct fuse_file_info *fi)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_release: path=" << path << ", flag=0x" << std::hex << fi->flags << endl;
  int curr_version = time(0);
  int latest_version = 0;

  // First we check if the file exists
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT current_version FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_ROW)
  {
    sqlite3_finalize(stmt);
    return -ENOENT;
  }
  latest_version = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);

  if ((fi->flags & O_ACCMODE) != O_RDONLY)
  {

    // TODO: since older version is removed anyway, it makes sense to rely on system
    // function calls for multiple file accesses. Simplification of versioning method?
    //if (curr_ver != -1)
    //  remove_version (path, curr_ver);

    // remove temp version
    removetemp_segment(path, latest_version);

    sqlite3_prepare_v2(db, "UPDATE file_system SET current_version = ? WHERE path = ?;", -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, curr_version); // set current_version to the current timestamp
    sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
    res = sqlite3_step(stmt);
    if (res != SQLITE_OK && res != SQLITE_DONE)
    {
      FILE_LOG(LOG_ERROR) << "ndnfs_release: update file_system error. " << res << endl;
      return res;
    }
    sqlite3_finalize(stmt);

    sqlite3_prepare_v2(db, "INSERT INTO file_versions (path, version) VALUES (?,?);", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, curr_version);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // After releasing, start a new signing thread for the file;
    // If a signing thread for the file in question has already started, kill that thread.
    int seg_all = 0;
    sqlite3_prepare_v2(db, "SELECT MAX(segment) FROM file_segments WHERE path = ? AND version =  ?", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, latest_version);
    res = sqlite3_step(stmt);
    seg_all = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    for (int seg = 0; seg <= seg_all; ++seg)
    {
      sqlite3_prepare_v2(db, "SELECT content FROM file_segments WHERE path = ? AND segment =  ?  AND version = ?", -1, &stmt, 0);
      sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
      sqlite3_bind_int(stmt, 2, seg);
      sqlite3_bind_int(stmt, 3, latest_version);
      res = sqlite3_step(stmt);
      int len = 0;
      if (res == SQLITE_ROW)
      {
        len = sqlite3_column_bytes(stmt, 0);
        char data[len];
        memmove(data, (char *)sqlite3_column_blob(stmt, 0), len);
        sign_segment(path, curr_version, seg, data, len);
      }
      sqlite3_finalize(stmt);
      // FILE_LOG(LOG_DEBUG) << "release:::" << path << " " << curr_version << " " << seg << " " << len << endl;
    }

    ndnfs_updateattr(path, curr_version);

    //   char full_path[PATH_MAX];
    //   abs_path(full_path, path);

    //   int fd = open(full_path, O_RDONLY);

    //   if (fd == -1)
    //   {
    //     FILE_LOG(LOG_ERROR) << "ndnfs_release: open error. Errno: " << errno << endl;
    //     return -errno;
    //   }

    //   char buf[ndnfs::seg_size];
    //   int size = ndnfs::seg_size;
    //   int seg = 0;

    //   while (size == ndnfs::seg_size)
    //   {
    //     size = pread(fd, buf, ndnfs::seg_size, seg << ndnfs::seg_size_shift);
    //     if (size == -1)
    //     {
    //       FILE_LOG(LOG_ERROR) << "ndnfs_release: read error. Errno: " << errno << endl;
    //       return -errno;
    //     }
    //     sign_segment(path, curr_version, seg, buf, size);
    //     seg++;
    //   }

    //   close(fd);
  }

  return 0;
}

int ndnfs_utimens(const char *path, const struct timespec ts[2])
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_utimens: path=" << path << " 0:" << ts[0].tv_sec << " 1" << ts[1].tv_sec << endl;
  // int res;

  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT * FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_ROW)
  {
    // No such file
    sqlite3_finalize(stmt);
    return -ENOENT;
  }
  sqlite3_finalize(stmt);
  return 0;

  // // sqlite3_prepare_v2(db, "UPDATE file_system SET  WHERE path = ?;", -1, &stmt, 0);
  // // sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

  // struct timeval tv[2];

  // char full_path[PATH_MAX];
  // abs_path(full_path, path);

  // tv[0].tv_sec = ts[0].tv_sec;
  // tv[0].tv_usec = ts[0].tv_nsec / 1000;
  // tv[1].tv_sec = ts[1].tv_sec;
  // tv[1].tv_usec = ts[1].tv_nsec / 1000;

  // res = utimes(full_path, tv);
  // if (res == -1)
  //   return -errno;

  // return 0;
}

/*
* As a DISTRIBUTED file system, SYMBOL LINK as well as HARD LINK
* is USELESS. 
*/

int ndnfs_readlink(const char *path, char *buf, size_t size)
{
  int res;

  char full_path[PATH_MAX];
  abs_path(full_path, path);

  res = readlink(full_path, buf, size - 1);
  if (res == -1)
    return -errno;

  buf[res] = '\0';
  return 0;
}

/**
 * symlink handling inserts file and version entry for the symlink name, 
 * but does not create segments entry;
 * TODO: file_segments entries should be linked to another name in file_system;
 * Symlink, as well as hard links will not be available for remote fetching.
 */
int ndnfs_symlink(const char *from, const char *to)
{
  int res;

  /*
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT * FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, to, -1, SQLITE_STATIC);
  res = sqlite3_step(stmt);
  if (res == SQLITE_ROW) {
      // Cannot create symlink that has conflicting file name
      sqlite3_finalize(stmt);
      return -ENOENT;
  }
  
  sqlite3_finalize(stmt);
  
  // Generate first version entry for the new symlink
  int ver = time(0);
  
  sqlite3_prepare_v2(db, "INSERT INTO file_versions (path, version) VALUES (?, ?);", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, to, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, ver);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  // Add the symlink entry to database
  sqlite3_prepare_v2(db, 
                     "INSERT INTO file_system \
                      (path, current_version, mime_type, type) \
                      VALUES (?, ?, ?, ?);", 
                     -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, to, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, ver);  // current version
  sqlite3_bind_text(stmt, 3, "", -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 4, SYMBOLIC_LINK);
  
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);  
  */

  char full_path_from[PATH_MAX];
  abs_path(full_path_from, from);

  char full_path_to[PATH_MAX];
  abs_path(full_path_to, to);

  res = symlink(full_path_from, full_path_to);
  if (res == -1)
    return -errno;

  return 0;
}

/**
 * Link is called on the creation of hard links
 * TODO: file_segments entries should be linked to another name in file_system;
 * This is not implemented and hard links will not be available for remote fetching.
 */
int ndnfs_link(const char *from, const char *to)
{
  int res;

  // actual linking of paths
  char full_path_from[PATH_MAX];
  abs_path(full_path_from, from);

  char full_path_to[PATH_MAX];
  abs_path(full_path_to, to);

  res = link(full_path_from, full_path_to);
  if (res == -1)
    return -errno;

  return 0;
}

/**
 * Right now, rename changes every entry related with the content, without creating new version
 * TODO: Rename would require checking if rename target (avoid collision error in db) already exists, and resigning of everything...
 * Rename should better work as a duplicate.
 */
int ndnfs_rename(const char *from, const char *to)
{
  int res = 0;
  sqlite3_stmt *stmt;

  sqlite3_prepare_v2(db, "UPDATE file_system SET PATH = ? WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, to, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, from, -1, SQLITE_STATIC);
  sqlite3_step(stmt);

  if (res != SQLITE_OK && res != SQLITE_DONE)
  {
    FILE_LOG(LOG_ERROR) << "ndnfs_rename: update file_system error. " << res << endl;
    return res;
  }
  sqlite3_finalize(stmt);

  sqlite3_prepare_v2(db, "UPDATE file_versions SET PATH = ? WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, to, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, from, -1, SQLITE_STATIC);
  sqlite3_step(stmt);

  if (res != SQLITE_OK && res != SQLITE_DONE)
  {
    FILE_LOG(LOG_ERROR) << "ndnfs_rename: update file_versions error. " << res << endl;
    return res;
  }
  sqlite3_finalize(stmt);

  sqlite3_prepare_v2(db, "UPDATE file_segments SET PATH = ? WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, to, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, from, -1, SQLITE_STATIC);
  sqlite3_step(stmt);

  if (res != SQLITE_OK && res != SQLITE_DONE)
  {
    FILE_LOG(LOG_ERROR) << "ndnfs_rename: update file_segments error. " << res << endl;
    return res;
  }
  sqlite3_finalize(stmt);

  // actual renaming
  char full_path_from[PATH_MAX];
  abs_path(full_path_from, from);

  char full_path_to[PATH_MAX];
  abs_path(full_path_to, to);

  res = rename(full_path_from, full_path_to);

  FILE_LOG(LOG_ERROR) << "ndnfs_rename: rename should trigger resign of everything, which is not yet implemented" << endl;
  if (res == -1)
    return -errno;

  return 0;
}

int ndnfs_statfs(const char *path, struct statvfs *si)
{
  char full_path[PATH_MAX];
  abs_path(full_path, path);

  int ret = statvfs(full_path, si);

  if (ret == -1)
  {
    FILE_LOG(LOG_ERROR) << "ndnfs_statfs: stat failed. Errno " << errno << endl;
    return -errno;
  }

  return 0;
}

int ndnfs_access(const char *path, int mask)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_acess: path = " << path << endl;
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT * FROM file_system WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_ROW)
  {
    // No such file
    sqlite3_finalize(stmt);
    return -ENOENT;
  }
  sqlite3_finalize(stmt);
  return 0;

  // char full_path[PATH_MAX];
  // abs_path(full_path, path);

  // int ret = access(full_path, mask);

  // if (ret == -1)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_access: access failed. Errno " << errno << endl;
  //   return -errno;
  // }

  // return 0;
}
