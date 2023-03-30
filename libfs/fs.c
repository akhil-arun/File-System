#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define SIG_LEN 8
#define FILE_PAD 10
#define FILE_LEN 16
#define OPEN_FILES 32
#define MAX_FILES 128
#define FAT_ENTRIES 2048
#define SUPERBLOCK_PAD 4079
#define BLOCK_SIZE 4096
#define FAT_EOC 0xFFFF


struct __attribute__ ((__packed__)) superblock {
	uint8_t signature [SIG_LEN];
	uint16_t disk_blocks;
	uint16_t root_index;
	uint16_t data_start;
	uint16_t num_dataBlocks;
	uint8_t num_fat;
	uint8_t padding[SUPERBLOCK_PAD];
};
typedef struct superblock superblock_t;

struct __attribute__((__packed__)) fat{
	uint16_t *entries;
};
typedef struct fat fat_t;

struct __attribute__((__packed__)) root_entry{
	uint8_t filename[FILE_LEN];
	uint32_t file_length;
	uint16_t first_block;
	uint8_t padding[FILE_PAD];
};
typedef struct root_entry root_entry_t;

struct file_descriptor{
	int fd;
	int offset;
	root_entry_t * file;
};
typedef struct file_descriptor file_descriptor_t;

struct info_helper{
	bool is_mounted;
	int free_fat;
	int free_rootEntries;
	int open_files;
};
typedef struct info_helper info_helper_t;

superblock_t superblock;
fat_t fat;  
root_entry_t root_directory[MAX_FILES];
file_descriptor_t table[OPEN_FILES];
info_helper_t info = {.is_mounted = false};

int check_mounting_errors(void)
{
	if(superblock.disk_blocks != block_disk_count())
		return -1;

	char *signature = "ECS150FS";
	if(strncmp((char*) superblock.signature, signature, 8) != 0)
		return -1;

	int disk_expected = 2 + superblock.num_fat + superblock.num_dataBlocks;
	if(disk_expected != superblock.disk_blocks)
		return -1;

	int fat_expected = superblock.num_dataBlocks / FAT_ENTRIES;
	if (superblock.num_dataBlocks % FAT_ENTRIES > 0)
		fat_expected += 1;

	if(fat_expected != superblock.num_fat)
		return -1;
	
	if(superblock.disk_blocks < 4)
		return -1;
	
	if(superblock.num_fat + 1 != superblock.root_index)
		return -1;
	
	if(superblock.root_index + 1 != superblock.data_start)
		return -1;

	if(fat.entries[0] != FAT_EOC)
		return -1;

	return 0;
}

void init_info_helper(void)
{
	info.open_files = 0;
	info.free_fat = 0;
	info.free_rootEntries = 0;
	info.is_mounted = true;

	for(int i = 0; i < superblock.num_dataBlocks; i++){
		if(fat.entries[i] == 0)
			info.free_fat += 1;
	}

	for (int i = 0; i < MAX_FILES; i++){
		if(root_directory[i].filename[0] == 0)
			info.free_rootEntries += 1;
	}
}

int fs_mount(const char *diskname)
{
	if (info.is_mounted == true || block_disk_open(diskname) == -1)
		return -1;
	
	block_read(0, &superblock);

	fat.entries = malloc(sizeof(uint16_t) * (superblock.num_fat * FAT_ENTRIES));
	for(int i = 0; i < superblock.num_fat; i++){
		block_read(i + 1, &(fat.entries[i * FAT_ENTRIES]));
	}

	block_read(superblock.root_index, root_directory);

	if(check_mounting_errors() == -1){
		free(fat.entries);
		return -1;
	}

	for (int i = 0; i < OPEN_FILES; i++){
		table[i].fd = i;
		table[i].offset = 0;
		table[i].file = NULL;
	}

	init_info_helper();
	return 0;
}

int fs_umount(void)
{
	if(info.is_mounted == false || info.open_files != 0)
		return -1;

	for(int i = 0; i < superblock.num_fat; i++){
		block_write(i + 1, &(fat.entries[i * FAT_ENTRIES]));
	}
	
	free(fat.entries);
	block_write(superblock.root_index, root_directory);
	
	if(block_disk_close() == -1)
		return -1;

	info.is_mounted = false;
	return 0;
}

int fs_info(void)
{
	if(info.is_mounted == false)
		return -1;
	
	printf("FS Info:\n");
	printf("total_blk_count=%d\n", superblock.disk_blocks);
	printf("fat_blk_count=%d\n", superblock.num_fat);
	printf("rdir_blk=%d\n", superblock.root_index);
	printf("data_blk=%d\n", superblock.data_start);
	printf("data_blk_count=%d\n", superblock.num_dataBlocks);
	printf("fat_free_ratio=%d/%d\n", info.free_fat, superblock.num_dataBlocks);
	printf("rdir_free_ratio=%d/%d\n", info.free_rootEntries, MAX_FILES);
	return 0;
}

int fs_create(const char *filename)
{
	if(info.is_mounted == false || info.free_rootEntries == 0)
		return -1;
	
	if(filename == NULL || filename[0] == 0)
		return -1;

	int len = strlen(filename);
	if(len + 1 > FILE_LEN)
		return -1;

	for (int i = 0; i < MAX_FILES; i++){
		if(strcmp((char*) root_directory[i].filename, filename) == 0)
			return -1;
	}

	for (int i = 0; i < MAX_FILES; i++){
		if(root_directory[i].filename[0] == 0){
			strcpy((char *)root_directory[i].filename, filename);
			root_directory[i].first_block = FAT_EOC;
			root_directory[i].file_length = 0;
			info.free_rootEntries -= 1;
			break;
		}
	}

	block_write(superblock.root_index, root_directory);
	return 0;
}

int fs_delete(const char *filename)
{
	if(info.is_mounted == false || filename == NULL || filename[0] == 0)
		return -1;

	int root_location = -1;
	for (int i = 0; i < MAX_FILES; i++){
		if(strcmp((char *)root_directory[i].filename, filename) == 0){
			root_location = i;
			break;
		}	
		if(i == 127)
			return -1;
	}

	for (int i = 0; i < OPEN_FILES; i++){
		if(&root_directory[root_location] == table[i].file)
			return -1;
	}
	
	int fat_index = root_directory[root_location].first_block;
	while(fat_index != FAT_EOC){
		int next_fat = fat.entries[fat_index];
		fat.entries[fat_index] = 0;
		info.free_fat += 1;
		fat_index = next_fat;
	}

	info.free_rootEntries += 1;
	root_directory[root_location].filename[0] = 0;
	return 0;
}

int fs_ls(void)
{
	if(info.is_mounted == false)
		return -1;

	printf("FS Ls:\n");
	for (int i = 0; i < MAX_FILES; i++){
		if(root_directory[i].filename[0] != 0){
			printf("file: %s, size: %d, data_blk: %d\n", root_directory[i].filename,
				   root_directory[i].file_length, root_directory[i].first_block);
		}
	}

	return 0;
}

int fs_open(const char *filename)
{
	if(info.is_mounted == false || filename == NULL || filename[0] == 0)
		return -1;
	
	if(info.open_files >= OPEN_FILES)
		return -1;

	int root_location = -1;
	for (int i = 0; i < MAX_FILES; i++){
		if(strcmp((char *)root_directory[i].filename, filename) == 0){
			root_location = i;
			break;
		}	
		if(i == 127)
			return -1;
	}

	for (int i = 0; i < OPEN_FILES; i++){
		if(table[i].file == NULL){
			table[i].file = &root_directory[root_location];
			table[i].offset = 0;
			info.open_files += 1;
			return i;
		}
	}
	return -1;
}

int check_fd_errors(int fd)
{
	if(info.is_mounted == false)
		return -1;
	
	if(fd < 0 || fd >= OPEN_FILES)
		return -1;
	
	if(table[fd].file == NULL)
		return -1;

	return 0;
}

int fs_close(int fd)
{
	if(check_fd_errors(fd) == -1)
		return -1;

	table[fd].file = NULL;
	info.open_files -= 1;
	return 0;
}

int fs_stat(int fd)
{
	if(check_fd_errors(fd) == -1)
		return -1;

	return table[fd].file->file_length;
}

int fs_lseek(int fd, size_t offset)
{
	if(check_fd_errors(fd) == -1)
		return -1;
	
	if(offset > table[fd].file->file_length)
		return -1;

	table[fd].offset = offset;
	return 0;
}

int get_starting_block(int start, int * previous, int fd)
{
	int current = table[fd].file->first_block;
	for (int i = 0; i < start; i++){
		*previous = current;
		current = fat.entries[current];
	}
	
	return current;
}

int min(int a, int b)
{
	if (a < b)
		return a;

	return b;
}

int find_free_fat(void)
{
	for (int i = 0; i < superblock.num_dataBlocks; i++){
		if(fat.entries[i] == 0)
			return i;
	}
	return -1;
}

int get_new_block(int index)
{
	if (fat.entries[index] == FAT_EOC){
		int retval = find_free_fat();
		if(retval == -1)
			return -1;

		fat.entries[index] = retval;
		fat.entries[retval] = FAT_EOC;
		info.free_fat -= 1;
		return retval;
	}

	return fat.entries[index];
}

int fs_write(int fd, void *buf, size_t count)
{
	if (check_fd_errors(fd) == -1 || buf == NULL)
		return -1;
	
	if(count == 0)
		return 0;

	int file_len = table[fd].file->file_length;
	int offset = table[fd].offset;
	
	int prev_index = -1;
	int index = get_starting_block(offset / BLOCK_SIZE, &prev_index, fd);
	if(index == FAT_EOC){
		int retval = find_free_fat();
		if(retval == -1)
			return 0;

		if (table[fd].file->first_block == FAT_EOC)
			table[fd].file->first_block = retval;
		
		else
			fat.entries[prev_index] = retval;
		
		index = retval;
		fat.entries[index] = FAT_EOC;
		info.free_fat -= 1;
	}

	int bytes_to_write = (int) count;
	int block_offset = offset % BLOCK_SIZE;
	
	int num_blocks = ((bytes_to_write + block_offset) / BLOCK_SIZE);
	if ((bytes_to_write + block_offset) % BLOCK_SIZE > 0)
		num_blocks += 1;

	int bytes_wrote = 0;
	int data_index = superblock.data_start;
	uint8_t *bounce = malloc(BLOCK_SIZE * sizeof(uint8_t));

	for (int i = 0; i < num_blocks; i++){
		if(i > 0){
			int retval = get_new_block(index);
			if(retval == -1)
				break;
			
			index = retval;
		}
		
		block_read(data_index + index, bounce);
		if(i == 0){
			bytes_wrote = min(bytes_to_write, BLOCK_SIZE - block_offset);
			memcpy(&bounce[block_offset], buf, bytes_wrote);
			block_write(data_index + index, bounce);
		}

		else if(i + 1 == num_blocks){
			int remaining = bytes_to_write - bytes_wrote;
			memcpy(bounce, buf + bytes_wrote, remaining);
			block_write(data_index + index, bounce);
			bytes_wrote += remaining;
		}

		else{
			memcpy(bounce, buf + bytes_wrote, BLOCK_SIZE);
			block_write(data_index + index, bounce);
			bytes_wrote += BLOCK_SIZE;
		}
	}

	free(bounce);
	table[fd].offset += bytes_wrote;
	if(table[fd].offset > file_len)
		table[fd].file->file_length = table[fd].offset;

	return bytes_wrote;
}

int fs_read(int fd, void *buf, size_t count)
{
	if(check_fd_errors(fd) == -1 || buf == NULL)
		return -1;

	int file_len = table[fd].file->file_length;
	int offset = table[fd].offset;
	if (file_len == 0 || offset == file_len || count == 0)
		return 0;

	int prev_index = -1;
	int index = get_starting_block(offset / BLOCK_SIZE, &prev_index, fd);
	int bytes_to_read = min(file_len - offset, (int) count);
	int block_offset = offset % BLOCK_SIZE;
	
	int num_blocks = ((bytes_to_read + block_offset) / BLOCK_SIZE);
	if((bytes_to_read + block_offset) % BLOCK_SIZE > 0)
		num_blocks += 1;

	int bytes_read = 0;
	int data_index = superblock.data_start;
	uint8_t *bounce = malloc(BLOCK_SIZE * sizeof(uint8_t));

	for (int i = 0; i < num_blocks; i++){
		block_read(data_index + index, bounce);
		
		if(i == 0){
			bytes_read = min(file_len - block_offset, BLOCK_SIZE - block_offset);
			bytes_read = min(bytes_read, (int)count);
			memcpy(buf, &bounce[block_offset], bytes_read);
			index = fat.entries[index];
		}
		
		else if(i + 1 == num_blocks){
			int remaining = bytes_to_read - bytes_read;
			memcpy(buf + bytes_read, bounce, remaining);
			bytes_read += remaining;
		}

		else{
			memcpy(buf + bytes_read, bounce, BLOCK_SIZE);
			bytes_read += BLOCK_SIZE;
			index = fat.entries[index];
		}
	}

	free(bounce);
	table[fd].offset += bytes_to_read;
	return bytes_to_read;
}
