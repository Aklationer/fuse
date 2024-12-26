#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
// openssl
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
char password[32];
struct file_node
{
    char name[256];
    char content[256];
    char AES_Key[32];
    char password[32];
    bool use;
    struct file_node *next;
};

struct dir_node
{
    char name[256];
    bool use;
    struct dir_node *next;
};

static struct dir_node *d_head = NULL;
static struct file_node *f_head = NULL;

bool is_dir(const char *path)
{
    path++;
    struct dir_node *temp = d_head;
    while (temp)
    {
        if (strcmp(path, temp->name) == 0 && temp->use)
            return 1;
        temp = temp->next;
    }
    return 0;
}

bool is_file(const char *path)
{
    path++;
    struct file_node *temp = f_head;
    while (temp)
    {
        if (strcmp(path, temp->name) == 0 && temp->use)
            return 1;
        temp = temp->next;
    }
    return 0;
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev)
{

    printf("do_mknod\n");

    path++; // 跳過"/"

    struct file_node *node = malloc(sizeof(struct file_node));
    strcpy(node->name, path);
    memset(node->content, 0, sizeof(node->content));
    memset(node->AES_Key, 0, sizeof(node->AES_Key));
    node->use = 1;
    node->next = f_head;
    f_head = node;

    return 0;
}

static int do_mkdir(const char *path, mode_t mode)
{

    printf("do_mkdir\n");
    path++; // 跳過"/"

    struct dir_node *node = malloc(sizeof(struct dir_node));
    strcpy(node->name, path);
    node->use = 1;
    node->next = d_head;
    d_head = node;

    return 0;
}

static int do_rmdir(const char *path)
{

    printf("do_rmdir\n");

    path++; // 跳過"/"

    struct dir_node *temp = d_head;
    while (temp)
    {
        if (strcmp(temp->name, path) == 0)
            temp->use = 0;
        temp = temp->next;
    }

    return 0;
}

static int do_getattr(const char *path, struct stat *st)
{

    /*
        path :要訪問的file path
        st : file attr 所放的data structure
    */
    memset(st, 0, sizeof(struct stat));
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = time(NULL); // 最後訪問時間
    st->st_mtime = time(NULL); // 最後修改時間

    if (strcmp(path, "/") == 0 || is_dir(path))
    {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2; // 幾乎所有file system 中 每個dir都有兩個hard link 一個是.  一個父親所指向自己的link
    }
    else if (is_file(path))
    {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = 1024;
    }
    else
    {
        return -ENOENT;
    }
    return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{

    /*
        path : 要讀取file的path
        buffer read所放space
        filler : 為FUSE的一個function pointer
        offset : start read index
   */

    printf("do_readdir\n");

    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);

    if (strcmp(path, "/") == 0)
    {

        struct file_node *temp_f = f_head;
        while (temp_f && temp_f->use)
        {
            filler(buffer, temp_f->name, NULL, 0);
            temp_f = temp_f->next;
        }

        struct dir_node *temp_d = d_head;
        while (temp_d && temp_d->use)
        {
            filler(buffer, temp_d->name, NULL, 0);
            temp_d = temp_d->next;
        }
    }

    return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{

    /*
        path : 要讀取file的path
        buffer : read所放space
        size : 要在file中讀多少data
        offset : start read index
   */
    getchar();
    printf("d%s", password);
    int len, out_len;

    printf("do_read\n");

    path++;

    struct file_node *temp = f_head;

    while (temp)
    {
        if (strcmp(path, temp->name) == 0 && temp->use)
        {

            printf("%s\n", temp->password);
            printf("Undecryption Data : ");
            for (int i = 0; i < strlen(temp->content); i++)
                printf("%02hhx ", temp->content[i]);
            printf("\n");

            EVP_CIPHER_CTX *ctx;

            ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, temp->AES_Key, NULL);
            EVP_DecryptUpdate(ctx, buffer, &len, temp->content, strlen(temp->content));
            EVP_DecryptFinal_ex(ctx, buffer + len, &out_len);
            len += out_len;
            EVP_CIPHER_CTX_free(ctx);

            printf("Decryption Data : %s", buffer);

            printf("\n");

            return strlen(buffer) - offset;
        }
        temp = temp->next;
    }
    return strlen(temp->content) - offset;
}

static int do_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info)
{

    /*
        path : 要讀取file的path
        buffer : 想寫的data
        size : buffer size
        offset : 從buffer哪開始寫
   */
    int len, out_len;

    printf("do_write\n");

    path++;

    struct file_node *temp = f_head;
    while (temp)
    {
        if (strcmp(path, temp->name) == 0 && temp->use)
        {

            EVP_CIPHER_CTX *ctx;

            RAND_bytes(temp->AES_Key, sizeof(temp->AES_Key));

            ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, temp->AES_Key, NULL);
            EVP_EncryptUpdate(ctx, temp->content, &len, buffer, strlen(buffer));
            EVP_EncryptFinal_ex(ctx, temp->content + len, &out_len);
            len += out_len;
            EVP_CIPHER_CTX_free(ctx);

            printf("Encryption Data : ");
            for (int i = 0; i < len; i++)
                printf("%02hhx ", temp->content[i]);
            printf("\n");
        }
        temp = temp->next;
    }

    return size;
}

static int do_open(const char *path, struct fuse_file_info *fi)
{
    printf("do_open\n");
    path++;
    struct file_node *temp = f_head;
    while (temp)
    {
        if (strcmp(path, temp->name) == 0 && temp->use)
        {
            if ((fi->flags & O_ACCMODE) != O_RDONLY && (fi->flags & O_ACCMODE) != O_WRONLY)
            {
                return -EACCES; // 权限错误
            }
            printf("%s\n", temp->password);
            return 0;
        }
        temp = temp->next;
    }
    return -ENOENT;
}

static int do_rm(const char *path)
{
    printf("do_rm\n");
    path++;
    struct file_node *temp = f_head;
    while (temp)
    {
        if (strcmp(temp->name, path) == 0)
        {
            printf("%d", temp->use);
            temp->use = 0;
        }
        temp = temp->next;
    }
}

static struct fuse_operations operations = {
    .getattr = do_getattr,
    .readdir = do_readdir,
    .read = do_read,
    .mkdir = do_mkdir,
    .mknod = do_mknod,
    .write = do_write,
    .rmdir = do_rmdir,
    .open = do_open,
    .unlink = do_rm};

int main(int argc, char *argv[])
{

    return fuse_main(argc, argv, &operations, NULL);
}
