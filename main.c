#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>



typedef uint32_t block_t[2];
typedef uint32_t enc_key_t[4];
const uint32_t rounds_number = 32;
const uint32_t delta = 2654435769;
const uint32_t deltax32 = 3337565984;
uint32_t uint32_max = 4294967295;


void encrypt_block(block_t block, const enc_key_t key) {
    uint32_t current_delta = 0;
    for (int i = 0; i < rounds_number; ++i) {
        current_delta += delta;
        block[0] += ((block[1] << 4) + key[0]) ^ (block[1] + current_delta) ^ ((block[1] >> 5) + key[1]);
        block[1] += ((block[0] << 4) + key[2]) ^ (block[0] + current_delta) ^ ((block[0] >> 5) + key[3]);
    }
}

void decrypt_block(block_t block, const enc_key_t key) {
    uint32_t current_delta = deltax32;
    for (int i = 0; i < rounds_number; ++i) {
        block[1] -= ((block[0] << 4) + key[2]) ^ (block[0] + current_delta) ^ ((block[0] >> 5) + key[3]);
        block[0] -= ((block[1] << 4) + key[0]) ^ (block[1] + current_delta) ^ ((block[1] >> 5) + key[1]);
        current_delta -= delta;
    }
}

void fill_block(block_t* block, int first_filled) {
    char* ch_block = (char*)block;
    for (int i = first_filled; i < sizeof(block_t); ++i) {
        ch_block[i] = 1;
    }
}

void encrypt_or_decrypt_file(int fd, int new_fd ,enc_key_t key, char enc_flag) {
    block_t current_block;

    while (1) {
        int how_much_read = read(fd, &current_block, sizeof(block_t));
        if (how_much_read  == -1) {
            perror("couldn't read file");
            return;
        }
        else if (how_much_read == 0)
            break;
        else if (how_much_read < sizeof(block_t))
            fill_block(&current_block, how_much_read);

        if (enc_flag)
            encrypt_block(current_block, key);
        else
            decrypt_block(current_block, key);

        int wrote = write(new_fd, &current_block, sizeof(block_t));
        if (wrote == -1) {
            perror("couldn't write to file");
            break;
        }
    }
}

void encrypt_or_decrypt_dir(DIR* dir, int new_dir_fd, enc_key_t key, char enc_flag) {
    struct dirent* dirent = readdir(dir);

    int dir_fd = dirfd(dir);

    while(dirent != NULL) {
        if (!(strcmp(dirent->d_name, ".")) || !(strcmp(dirent->d_name, ".."))) {
            dirent = readdir(dir);
            continue;
        }

        int fd = openat(dir_fd, dirent->d_name, O_RDONLY);
        if (fd <= 0) {
            perror("couldn't open file for reading");
            dirent = readdir(dir);
            continue;
        }

        struct stat st;
        fstatat(dir_fd, dirent->d_name, &st, AT_SYMLINK_NOFOLLOW);
        int new_file_fd = openat(new_dir_fd, dirent->d_name, O_CREAT | O_WRONLY, st.st_mode);

        encrypt_or_decrypt_file(fd, new_file_fd, key, enc_flag);

        close(fd);
        close(new_file_fd);

        dirent = readdir(dir);
    }
}

void make_dir_for_act(char* path, char* new_path, char encrypt_flag) {
    memset(new_path, 0, PATH_MAX);
    if (encrypt_flag)
        sprintf(new_path, "%s_encrypted", path);
    else {
        if (strstr(path, "_encrypted")) {
            memcpy(new_path, path, strlen(path) - strlen("_encrypted"));
        }
        else {
            sprintf(new_path, "%s_decrypted", path);
        }
    }

    mkdir(new_path, 0777);
}


void get_key(const char* str, enc_key_t* key) {
    srand(strtol(str, 0, 10));

    *key[0] = rand() % uint32_max;
    *key[1] = rand() % uint32_max;
    *key[2] = rand() % uint32_max;
    *key[3] = rand() % uint32_max;
}

int main(int argc, char* argv[]) {
    // argv[1] - directory path
    // argv[2] - seed for obtaining the encryption key
    // argv[3] - "-e" for encrypting "-d" for decrypting

    char encrypt_flag = argv[3][1] == 'e';

    char new_path[PATH_MAX];
    make_dir_for_act(argv[1], new_path, encrypt_flag);
    int new_dir_fd = (dirfd(opendir(new_path)));

    enc_key_t key = {0, 0, 0, 0};
    get_key(argv[2], &key);

    DIR* dir = opendir(argv[1]);
    if (dir == NULL) {
        perror("couldn't open a directory");
        return 1;
    }

    encrypt_or_decrypt_dir(dir, new_dir_fd, key, encrypt_flag);

    close(new_dir_fd);
    closedir(dir);
    return 0;
}