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

#include "attribute.h"
#include "file-type.h"

using namespace std;

int ndnfs_getattr(const char *path, struct stat *stbuf)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_getattr: path=" << path << endl;

  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT mode, atime, current_version, size, nlink, type FROM file_system WHERE path = ?", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res == SQLITE_ROW)
  {
    int type = sqlite3_column_int(stmt, 5);
    if (type == DIRECTORY)
    {
      stbuf->st_mode = S_IFDIR | sqlite3_column_int(stmt, 0);
    }
    else if (type == REGULAR)
    {
      stbuf->st_mode = S_IFREG | sqlite3_column_int(stmt, 0);
    }
    else
      return -errno;
    stbuf->st_atime = sqlite3_column_int(stmt, 1);
    stbuf->st_mtime = sqlite3_column_int(stmt, 2);
    stbuf->st_size = sqlite3_column_int(stmt, 3);
    stbuf->st_nlink = sqlite3_column_int(stmt, 4);
    stbuf->st_uid = ndnfs::user_id;
    stbuf->st_gid = ndnfs::group_id;
    sqlite3_finalize(stmt);
    return 0;
  }
  else
  {
    sqlite3_finalize(stmt);
    FILE_LOG(LOG_ERROR) << "ndnfs_getattr: get_attr failed. path:" << path << ". Errno " << errno << endl;
    return -errno;
  }

  // char fullPath[PATH_MAX];
  // abs_path(fullPath, path);

  // int ret = lstat(fullPath, stbuf);

  // if (ret == -1)
  // {
  //   FILE_LOG(LOG_ERROR) << "ndnfs_getattr: get_attr failed. Full path " << fullPath << ". Errno " << errno << endl;
  //   return -errno;
  // }
  // // FILE_LOG(LOG_DEBUG) << "   ???????" << ret << endl;
  // return ret;
}

int ndnfs_chmod(const char *path, mode_t mode)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_chmod: path=" << path << ", change mode to " << std::oct << mode << endl;

  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "UPDATE file_system SET mode = ? WHERE path = ?", -1, &stmt, 0);
  sqlite3_bind_int(stmt, 1, mode);
  sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  char fullPath[PATH_MAX];
  abs_path(fullPath, path);

  res = chmod(fullPath, mode);
  if (res == -1)
  {
    FILE_LOG(LOG_ERROR) << "ndnfs_chmod: chmod failed. Errno: " << -errno << endl;
    return -errno;
  }
  return 0;
}

int ndnfs_updateattr(const char *path, int ver)
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_updateattr path:" << path << endl;
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT length(content), segment FROM file_segments WHERE path = ? AND version = ? AND segment = (SELECT MAX(segment) FROM file_segments WHERE path = ? AND version = ?);", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, ver);
  sqlite3_bind_text(stmt, 3, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 4, ver);
  // sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  int size = sqlite3_column_int(stmt, 0);
  int seg = sqlite3_column_int(stmt, 1);
  sqlite3_finalize(stmt);

  size += seg * ndnfs::seg_size;

  sqlite3_prepare_v2(db, "UPDATE file_system SET size = ? WHERE path = ?", -1, &stmt, 0);
  sqlite3_bind_int(stmt, 1, size);
  sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
  res = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

// Dummy function to stop commands such as 'cp' from complaining

#ifdef NDNFS_OSXFUSE
int ndnfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags, uint32_t position)
#elif NDNFS_FUSE
int ndnfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
#endif
{
  FILE_LOG(LOG_DEBUG) << "ndnfs_setxattr path:" << path << " name:" << name << " size:" << size << endl;
  return 0;
}
