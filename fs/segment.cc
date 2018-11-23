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

#include "segment.h"
#include "signature-states.h"

#include <ndn-cpp/data.hpp>
#include <ndn-cpp/common.hpp>
#include <ndn-cpp/security/security-exception.hpp>

#include <iostream>
#include <cstdio>

#define INT2STRLEN 100

using namespace std;
using namespace ndn;

/**
 * version parameter is not used right now, as duplicate_version is now a stub, 
 * and write does not create/write to a new file by the name of the version.
 */
int sign_segment(const char *path, int ver, int seg, const char *data, int len)
{
  FILE_LOG(LOG_DEBUG) << "sign_segment: path=" << path << std::dec << ", ver=" << ver << ", seg=" << seg << ", len=" << len << endl;

  string file_path(path);
  string full_name = ndnfs::global_prefix + file_path;
  // We want the Name(uri) constructor to split the path into components between "/", but we first need
  // to escape the characters in full_name which the Name(uri) constructor will unescape.  So, create a component
  // from the raw string and use its toEscapedString.

  string escapedString = Name::Component((uint8_t *)&full_name[0], full_name.size()).toEscapedString();
  // The "/" was escaped, so unescape.
  while (1)
  {
    size_t found = escapedString.find("%2F");
    if (found == string::npos)
      break;
    escapedString.replace(found, 3, "/");
  }
  Name seg_name(escapedString);

  seg_name.appendVersion(ver);
  seg_name.appendSegment(seg);
  FILE_LOG(LOG_DEBUG) << "sign_segment: segment name is " << seg_name.toUri() << endl;

  Data data0;
  data0.setName(seg_name);
  data0.setContent((const uint8_t *)data, len);
  // instead of putting the whole content object into sqlite, we put only the signature field.

  // FILE_LOG(LOG_DEBUG)<<"THIS IS GOING TO DETECT "<< seg_name<< "    "<< data<<endl;

  ndnfs::keyChain->sign(data0, ndnfs::certificateName);
  Blob signature = data0.getSignature()->getSignature();

  const char *sig_raw = (const char *)signature.buf();
  int sig_size = signature.size();

  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO file_segments (signature ,path, version, segment, content) VALUES (?, ?, ?, ?, ?);", -1, &stmt, 0);
  // sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  // sqlite3_bind_int(stmt, 2, ver);
  // sqlite3_bind_int(stmt, 3, seg);
  sqlite3_bind_blob(stmt, 1, sig_raw, sig_size, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 3, ver);
  sqlite3_bind_int(stmt, 4, seg);
  sqlite3_bind_blob(stmt, 5, data, len, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_OK)
  {
    // FILE_LOG(LOG_DEBUG) << "WHY????" << endl;
  }
  sqlite3_finalize(stmt);

  // change ready_signed to ready;
  sqlite3_prepare_v2(db, "UPDATE file_system SET ready_signed = ? WHERE path = ? AND current_version = ? ;", -1, &stmt, 0);
  enum SignatureState signatureState = READY;
  sqlite3_bind_int(stmt, 1, signatureState);
  sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 3, ver);
  res = sqlite3_step(stmt);
  return sig_size;
}

void remove_segments(const char *path, const int ver, const int start /* = 0 */)
{
  FILE_LOG(LOG_DEBUG) << "remove_segments: path=" << path << std::dec << ", ver=" << ver << ", starting from segment #" << start << endl;
  /*
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT totalSegments FROM file_versions WHERE path = ? AND version = ?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, ver);
    int res = sqlite3_step(stmt);
    if (res != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return;
    }
    int segs = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    for (int i = start; i < segs; i++) {
        sqlite3_prepare_v2(db, "DELETE FROM file_segments WHERE path = ? AND version = ? AND segment = ?;", -1, &stmt, 0);
        sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, ver);
        sqlite3_bind_int(stmt, 3, i);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
  */
}

// truncate is not tested in current implementation
void truncate_segment(const char *path, const int ver, const int seg, const off_t length)
{
  FILE_LOG(LOG_DEBUG) << "truncate_segment: path=" << path << std::dec << ", ver=" << ver << ", seg=" << seg << ", length=" << length << endl;

  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT * FROM file_segments WHERE path = ? AND version = ? AND segment = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, ver);
  sqlite3_bind_int(stmt, 3, seg);

  if (sqlite3_step(stmt) == SQLITE_ROW)
  {
    if (length == 0)
    {
      sqlite3_finalize(stmt);
      sqlite3_prepare_v2(db, "DELETE FROM file_segments WHERE path = ? AND version = ? AND segment = ?;", -1, &stmt, 0);
      sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
      sqlite3_bind_int(stmt, 2, ver);
      sqlite3_bind_int(stmt, 3, seg);
      sqlite3_step(stmt);
      sqlite3_finalize(stmt);
    }
    else
    {
      // the file is already truncated, so we only update the signature here.
      char fullPath[PATH_MAX];
      abs_path(fullPath, path);
      int fd = open(fullPath, O_RDONLY);
      if (fd == -1)
      {
        FILE_LOG(LOG_ERROR) << "truncate_segment: open error. Errno: " << errno << endl;
        return;
      }

      char *data = new char[ndnfs::seg_size];
      int read_len = pread(fd, data, length, segment_to_size(seg));
      if (read_len < 0)
      {
        FILE_LOG(LOG_ERROR) << "truncate_segment: write error. Errno: " << errno << endl;
        return;
      }

      string file_path(path);
      string full_name = ndnfs::global_prefix + file_path;
      // We want the Name(uri) constructor to split the path into components between "/", but we first need
      // to escape the characters in full_name which the Name(uri) constructor will unescape.  So, create a component
      // from the raw string and use its toEscapedString.

      string escapedString = Name::Component((uint8_t *)&full_name[0], full_name.size()).toEscapedString();
      // The "/" was escaped, so unescape.
      while (1)
      {
        size_t found = escapedString.find("%2F");
        if (found == string::npos)
          break;
        escapedString.replace(found, 3, "/");
      }
      Name seg_name(escapedString);

      seg_name.appendVersion(ver);
      seg_name.appendSegment(seg);

      Data trunc_data;
      trunc_data.setContent((const uint8_t *)data, length);

      ndnfs::keyChain->sign(trunc_data, ndnfs::certificateName);
      Blob signature = trunc_data.getSignature()->getSignature();

      const char *sig_raw = (const char *)signature.buf();
      int sig_size = signature.size();

      sqlite3_finalize(stmt);
      sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO file_segments (path,version,segment,signature) VALUES (?,?,?,?);", -1, &stmt, 0);
      sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
      sqlite3_bind_int(stmt, 2, ver);
      sqlite3_bind_int(stmt, 3, seg);
      sqlite3_bind_blob(stmt, 4, sig_raw, sig_size, SQLITE_STATIC);
      sqlite3_step(stmt);
      sqlite3_finalize(stmt);

      delete data;
      close(fd);
    }
  }
}

int truncate_all_segment(const char *path, const int ver, const off_t length)
{
  FILE_LOG(LOG_DEBUG) << "truncate_all_segment: path=" << path << std::dec << ", ver=" << ver << ", length=" << length << endl;

  sqlite3_stmt *stmt_main;
  sqlite3_prepare_v2(db, "SELECT * FROM file_segments WHERE path = ? AND version = ?;", -1, &stmt_main, 0);
  sqlite3_bind_text(stmt_main, 1, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt_main, 2, ver);
  int seg = -1;
  int res;
  int length_curr = 0;
  bool flag_over = false;
  int curr_ver = time(0);

  while (sqlite3_step(stmt_main) == SQLITE_ROW)
  {
    seg++;
    if (length == 0 || flag_over)
    {
      sqlite3_stmt *stmt;
      sqlite3_prepare_v2(db, "UPDATE file_system SET current_version = ? WHERE path = ?;", -1, &stmt, 0);
      sqlite3_bind_int(stmt, 1, curr_ver); // set current_version to the current timestamp
      sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
      res = sqlite3_step(stmt);
      if (res != SQLITE_OK && res != SQLITE_DONE)
      {
        FILE_LOG(LOG_ERROR) << "truncate all segment: update file_system error. " << res << endl;
        return res;
      }
      sqlite3_finalize(stmt);
      FILE_LOG(LOG_DEBUG) << "here:" << curr_ver << endl;
      return 0;
      // sqlite3_stmt *stmt;
      // sqlite3_prepare_v2(db, "DELETE FROM file_segments WHERE path = ? AND version = ? AND segment = ?;", -1, &stmt, 0);
      // sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
      // sqlite3_bind_int(stmt, 2, ver);
      // sqlite3_bind_int(stmt, 3, seg);
      // sqlite3_step(stmt);
      // sqlite3_finalize(stmt);
    }
    else
    {
      int size = sqlite3_column_bytes(stmt_main, 4);
      char data[size];
      int len_use = 0;
      if ((long) size < (length - (seg * ndnfs::seg_size)))
      {
        len_use = size;
      }
      else
      {
        len_use = (length - (seg * ndnfs::seg_size));
        flag_over = true;
      }
      length_curr += len_use;
      memmove(data, (char *)sqlite3_column_blob(stmt_main, 4), len_use);
      sqlite3_stmt *stmt;
      // sqlite3_prepare_v2(db, "IPDATE file_segments SET content = ? WHERE path = ? AND segment = ? and version = ?;", -1, &stmt, 0);
      sqlite3_prepare_v2(db, "INSERT INTO file_segments (content, path, segment, version, signature) VALUES (?, ?, ?, ?, 'NONE');", -1, &stmt, 0);
      sqlite3_bind_blob(stmt, 1, data, len_use, SQLITE_STATIC);
      sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
      sqlite3_bind_int(stmt, 3, seg);
      sqlite3_bind_int(stmt, 4, curr_ver);
      res = sqlite3_step(stmt);
      sqlite3_finalize(stmt);
      FILE_LOG(LOG_DEBUG)<< "len_use"<<len_use<< " min" << length - (seg * ndnfs::seg_size)<< endl;
      if (length_curr > length)
        break;
      // sign_segment(path, ver, seg, data, len_use);
    }
  }
  if (flag_over)
  {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "UPDATE file_system SET current_version = ? WHERE path = ?;", -1, &stmt, 0);
    sqlite3_bind_int(stmt, 1, curr_ver); // set current_version to the current timestamp
    sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
    res = sqlite3_step(stmt);
    if (res != SQLITE_OK && res != SQLITE_DONE)
    {
      FILE_LOG(LOG_ERROR) << "truncate all segment: update file_system error. " << res << endl;
      return res;
    }
    sqlite3_finalize(stmt);
    FILE_LOG(LOG_DEBUG) << "here:" << curr_ver << endl;
    return 0;
  }
}

// int truncate_all_segment(const char *path, const int ver, const off_t length)
// {
//   FILE_LOG(LOG_DEBUG) << "truncate_all_segment: path=" << path << std::dec << ", ver=" << ver << ", length=" << length << endl;

//   sqlite3_stmt *stmt_main;
//   sqlite3_prepare_v2(db, "SELECT * FROM file_segments WHERE path = ? AND version = ?;", -1, &stmt_main, 0);
//   sqlite3_bind_text(stmt_main, 1, path, -1, SQLITE_STATIC);
//   sqlite3_bind_int(stmt_main, 2, ver);
//   int seg = -1;
//   int res;
//   int length_curr = 0;
//   bool flag_over = false;
//   int curr_ver = time(0);

//   while (sqlite3_step(stmt_main) == SQLITE_ROW)
//   {
//     seg++;
//     if (length == 0 || flag_over)
//     {
//       sqlite3_stmt *stmt;
//       sqlite3_prepare_v2(db, "UPDATE file_system SET current_version = ? WHERE path = ?;", -1, &stmt, 0);
//       sqlite3_bind_int(stmt, 1, curr_ver); // set current_version to the current timestamp
//       sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
//       res = sqlite3_step(stmt);
//       if (res != SQLITE_OK && res != SQLITE_DONE)
//       {
//         FILE_LOG(LOG_ERROR) << "truncate all segment: update file_system error. " << res << endl;
//         return res;
//       }
//       sqlite3_finalize(stmt);
//       FILE_LOG(LOG_DEBUG) << "here:" << curr_ver << endl;
//       return 0;
//       // sqlite3_stmt *stmt;
//       // sqlite3_prepare_v2(db, "DELETE FROM file_segments WHERE path = ? AND version = ? AND segment = ?;", -1, &stmt, 0);
//       // sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
//       // sqlite3_bind_int(stmt, 2, ver);
//       // sqlite3_bind_int(stmt, 3, seg);
//       // sqlite3_step(stmt);
//       // sqlite3_finalize(stmt);
//     }
//     else
//     {
//       int size = sqlite3_column_bytes(stmt_main, 4);
//       length_curr += size;
//       if (length_curr < length)
//         continue;
//       flag_over = true;
//       char data[size];
//       int len_use = length - (seg * ndnfs::seg_size);
//       memmove(data, (char *)sqlite3_column_blob(stmt_main, 4), len_use);
//       sqlite3_stmt *stmt;
//       // sqlite3_prepare_v2(db, "IPDATE file_segments SET content = ? WHERE path = ? AND segment = ? and version = ?;", -1, &stmt, 0);
//       sqlite3_prepare_v2(db, "INSERT INTO file_segments (content, path, segment, version) VALUES (?, ?, ?, ?);", -1, &stmt, 0);
//       sqlite3_bind_blob(stmt, 1, data, len_use, SQLITE_STATIC);
//       sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
//       sqlite3_bind_int(stmt, 3, seg);
//       sqlite3_bind_int(stmt, 4, curr_ver);
//       sqlite3_step(stmt);
//       sqlite3_finalize(stmt);
//       // sign_segment(path, ver, seg, data, len_use);
//     }
//   }
//   if (flag_over)
//   {
//     sqlite3_stmt *stmt;
//     sqlite3_prepare_v2(db, "UPDATE file_system SET current_version = ? WHERE path = ?;", -1, &stmt, 0);
//     sqlite3_bind_int(stmt, 1, curr_ver); // set current_version to the current timestamp
//     sqlite3_bind_text(stmt, 2, path, -1, SQLITE_STATIC);
//     res = sqlite3_step(stmt);
//     if (res != SQLITE_OK && res != SQLITE_DONE)
//     {
//       FILE_LOG(LOG_ERROR) << "truncate all segment: update file_system error. " << res << endl;
//       return res;
//     }
//     sqlite3_finalize(stmt);
//     FILE_LOG(LOG_DEBUG)<< "here:"<< curr_ver<<endl;
//     return 0;
//   }
// }

int addtemp_segment(const char *path, const char *buf, size_t size, off_t offset)
{
  FILE_LOG(LOG_DEBUG) << "addtemp_segment path=" << path << endl;
  sqlite3_stmt *stmt;
  char buf_seg[ndnfs::seg_size];
  int seg_size = ndnfs::seg_size;
  int seg = offset / (seg_size); // current segment
  int offset_saved = 0;
  // Add ".segtemp" after path to indicate this is a temp version
  char temp_char[9] = ".segtemp";
  char path_temp[strlen(path) + strlen(temp_char) + 1];
  strcpy(path_temp, path);
  strcat(path_temp, temp_char);

  // Insert temp segment into db
  long long buf_size = (long long)size;
  memset(buf_seg, '\0', seg_size);
  if (offset % seg_size != 0)
  {
    // Get latest content we have inserted into db
    sqlite3_prepare_v2(db, "SELECT content FROM file_segments WHERE path = ? AND segment =  ?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, path_temp, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, seg);
    int res = sqlite3_step(stmt);

    if (res == SQLITE_ROW)
    {
      offset_saved = sqlite3_column_bytes(stmt, 0);
      int seg_remain = seg_size - offset_saved;
      memmove(buf_seg, (char *)sqlite3_column_blob(stmt, 0), offset_saved);
      char content_add[seg_remain];
      memcpy(content_add, buf, min((long long)seg_remain, buf_size));
      strcat(buf_seg, content_add);
      sqlite3_finalize(stmt);
      sqlite3_prepare_v2(db, "UPDATE file_segments SET content = ? WHERE path = ? AND segment = ? and version = 100000;", -1, &stmt, 0);
      sqlite3_bind_blob(stmt, 1, buf_seg, offset_saved + min((long long)seg_remain, buf_size), SQLITE_STATIC);
      sqlite3_bind_text(stmt, 2, path_temp, -1, SQLITE_STATIC);
      sqlite3_bind_int(stmt, 3, seg);
      res = sqlite3_step(stmt);
      sqlite3_finalize(stmt);
      offset_saved = seg_remain;
      // FILE_LOG(LOG_DEBUG) << " Write first success\n";
    }
    else
    {
      sqlite3_finalize(stmt);
    }
  }

  while ((buf_size - offset_saved) > 0)
  {
    // FILE_LOG(LOG_DEBUG) << "Wrinte a new segment seg="<< seg<< endl;
    memset(buf_seg, '\0', seg_size);
    memcpy(buf_seg, buf + offset_saved, min((long long)seg_size, buf_size - offset_saved));
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO file_segments (path,version,segment, signature, content) VALUES (?,100000,?,'NONE', ?);", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, path_temp, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, seg);
    sqlite3_bind_blob(stmt, 3, buf_seg, min((long long)seg_size, buf_size - offset_saved), SQLITE_STATIC);
    int res = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    seg++;
    offset_saved += min((long long)seg_size, buf_size - offset_saved);
    if ((buf_size - offset_saved) < 0)
    {
      break;
    }
  }
}

void copycurr_segment(const char *path, int cuur_ver)
{
  FILE_LOG(LOG_DEBUG) << "copycurr_segment path=" << path << " current version=" << cuur_ver << endl;
  char temp_char[9] = ".segtemp";
  char path_temp[strlen(path) + strlen(temp_char) + 1];
  strcpy(path_temp, path);
  strcat(path_temp, temp_char);
  sqlite3_stmt *stmt;

  // get max seg
  sqlite3_prepare_v2(db, "SELECT MAX(segment) FROM file_segments WHERE path = ? AND version = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, cuur_ver);
  int res = sqlite3_step(stmt);
  if (res != SQLITE_OK)
  {
    FILE_LOG(LOG_DEBUG) << "no segment exists" << endl;
    sqlite3_finalize(stmt);
    return;
  }
  int seg_max = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);
  for (int seg = 0; seg <= seg_max; ++seg)
  {
    sqlite3_prepare16_v2(db, "INSERT INTO file_segments (path, version, segment, signature, content) VALUES(?, 100000, ?, 'NONE', (SELECT content FROM file_segments WHERE (path = ? AND version = ? AND segment = ?)));", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, path_temp, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, seg);
    sqlite3_bind_text(stmt, 3, path, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, cuur_ver);
    sqlite3_bind_int(stmt, 5, seg);
    res = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (res != SQLITE_ROW)
      FILE_LOG(LOG_DEBUG) << "copy current segment error! path:" << path << " seg:" << seg << " cuur_ver:" << cuur_ver << endl;
    else
      FILE_LOG(LOG_DEBUG) << "copy current segment sucess!" << endl;
  }
}

// remove temp version
int removetemp_segment(const char *path, int ver)
{
  FILE_LOG(LOG_DEBUG) << "removetemp_segment path=" << path << endl;
  char temp_char[9] = ".segtemp";
  char path_temp[strlen(path) + strlen(temp_char) + 1];
  strcpy(path_temp, path);
  strcat(path_temp, temp_char);

  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "UPDATE file_segments SET path = ?, version = ? WHERE path = ?;", -1, &stmt, 0);
  sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 2, ver);
  sqlite3_bind_text(stmt, 3, path_temp, -1, SQLITE_STATIC);
  int res = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return 0;
}