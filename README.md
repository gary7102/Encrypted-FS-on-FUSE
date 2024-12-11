# Objective
This assignment aims to deepen understanding of file system operations and encryption mechanisms by building a simple in-memory file system using the FUSE (Filesystem in Userspace) framework, followed by integrating AES-256 encryption to ensure data security.

**Resources:**  
1.	[Less Simple, Yet Stupid Filesystem (Using FUSE)](https://github.com/MaaSTaaR/LSYSFS)  
2.	[In Storage Filesystem (ISFS) Using FUSE](https://github.com/yttty/isfs)

Assignment: [Link](https://github.com/gary7102/Encrypted-FS-on-FUSE/blob/main/Assignment%202.docx)

# Part 1
**Setting Up FUSE environment**  
```
sudo apt-get install fuse libfuse-dev
```

![image](https://hackmd.io/_uploads/ryLRzhBm1e.png)

![image](https://hackmd.io/_uploads/SknVNnrQJe.png)

# Part 2

Building a Basic In-Memory File System with FUSE: Using the FUSE framework, create a simple in-memory file system. This file system should support basic operations such as:
*	Create, read, and write files.
*	Open and close files.
*	Create and remove directories.
*	List directory contents.  


<font size = 4>**memfs**</font>
```
memfs/
├── Makefile           
├── main.c             # 主程式，包含Initlize 和 FUSE 的入口點
├── node.c             # 節點操作（如Create, LookUP）相關操作
├── node.h             # header file of node.c
├── encryption.c       # 與資料加密和解密相關操作
├── encryption.h       # header file of encryption.c`
├── operations.c       # FUSE 各種函數的實現（如: read, write, mkdir）
├── operations.h       # headre file of operations.c
└── memfs.h            # global header file，定義核心結構、global vaviable，root等


```



<font size = 4>**Makefile**</font>
```
CC = gcc
CFLAGS = `pkg-config fuse3 --cflags` -Wall -g
LDFLAGS = `pkg-config fuse3 --libs` -lssl -lcrypto

SOURCES = main.c node.c encryption.c operations.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = memfs.h node.h encryption.h operations.h

all: memfs

memfs: $(OBJECTS)
	$(CC) $(CFLAGS) -o memfs $(OBJECTS) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f memfs $(OBJECTS)

```
**Makefile 說明:**  
執行 `make` 時，會先找到 `all`，`all` 依賴於 `memfs`，所以去執行`memfs` ，`memfs` 依賴於 `$(OBJECTS)`，所以實際上會先去檢查所有的`.o`檔是否存在，
* 如果`.o` file 不在，就先把對應的`.c`檔編譯成`.o` file
* 如果`.o` file 存在，就直接執行 `memfs` 的生成



`pkg-config fuse3 --cflags` 及`pkg-config fuse3 --libs` 表示 provide the compiler the proper arguments to include “fuse3” library.  
`-Wall` 表示啟用所有常用的編譯器警告

編譯成功後會出現一個可執行檔 `memfs`  

![image](https://hackmd.io/_uploads/SJMST3ZV1g.png)

<font size = 4>**將`memfs` 掛載到 `/tmp/memfs`**</font>
```
./memfs -f -d /tmp/memfs
```
`-f` : 表示讓process在foreground運作。主要目的是在terminal中看到程式的输出，類似於 `dmesg` (查看kernel 內的訊息)。  

`-d` : Debug模式，可以用來查看更詳細的運作訊息，包含每個指令實際執行到的function、nodeid、pid、error message等等

結束後，在另一個terminal 中輸入:
```
cd /tmp/memfs
```
即可開始對file system進行各種操作。


---

<font size = 4>**創建新directory**</font>

```
mkdir testdir
```

在Foreground中會出現:  
![image](https://hackmd.io/_uploads/SyQfXgvmkl.png)

可以發現，`mkdir` 實際上會先去`LOOKUP /testdir`，得到 error: NO such file or directory，  
接下來會真正執行`MKDIR` 產生 `testdir` 這個目錄

---

<font size = 4>**建立新檔案**</font>
```
touch testfile
```

在Foreground中會出現:  

![image](https://hackmd.io/_uploads/ryX2ilDmye.png)


可以發現創立檔案的流程:
* `LOOKUP /testfile`
得到 error: NO such file or directory
* `CREATE /testfile`
在nodeid 為 1(root directory)下創建testfile
* `SETATTR`
對testfile設定一些屬性(如: `atimes`, `mtimes`)，
* `RELEASE`
關閉testfile，得到success。


---

<font size = 4>**寫入檔案**</font>

```
echo "Hello" > testfile
```

在Foreground中會出現:  

![image](https://hackmd.io/_uploads/r1Wu3xwXyg.png)

可以發現共寫入6個bytes，`"Hello\n"` 共6bytes。

---

<font size = 4>**讀取檔案**</font>
```
cat testfile
```
![image](https://hackmd.io/_uploads/B1FxbZwmyl.png)


在Foreground中會出現:  
![image](https://hackmd.io/_uploads/ryqyg-PQ1l.png)


---

<font size = 4>**列出directory內容**</font>
```
ls -l
```
![image](https://hackmd.io/_uploads/BkndbbvXke.png)


在Foreground中會出現:  
![image](https://hackmd.io/_uploads/Syaw-bvQye.png)


---

<font size = 4>**delete file**</font>
```
rm testfile
```

在Foreground中會出現:  
![image](https://hackmd.io/_uploads/rk7cM-wXyg.png)

---

<font size = 4>**delete directory**</font>
```
rmdir testdir
```
在Foreground中會出現:  
![image](https://hackmd.io/_uploads/rk1HMZD7kg.png)

若 directory不存在會出現:  
![image](https://hackmd.io/_uploads/HyOoPttXJe.png)


# Part 3, 4, 5
* Integrating AES-256 Encryption
* Encrypted with a different key
* Ensure all file operations (read, write, etc.) handle encrypted data correctly
* Testing and Validation

<font size = 4>**AES-256 Encryption如何運作?**</font>

* `EVP_CIPHER_CTX_new()` : returns a pointer to a newly created EVP_CIPHER_CTX for success and NULL for failure.
* `EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)`
* `EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)` 
* `EVP_EncryptFinal_ex(...)`
*  `EVP_CIPHER_CTX_free(ctx)`


Implement a mechanism for managing encryption keys, ensuring that each file can be encrypted with a <font color = orange>**different key**</font>. Design the system so that the encryption key must be supplied to open a file. 


<font size = 4>**寫入時加密:**</font>
可以在mount 上資料夾之前，先設幾個斷點，到時候方便檢查是否確實加密
* 讓 `memfs` mount 上 `/tmp/memfs`：
```
gdb --args ./memfs -f -d /tmp/memfs
```

* `gdb` 寫入斷點:
```
break memfs.c:545    // before ending memfs_write()
break memfs.c:456    // before ending memfs_read()
```

* `gdb` 執行程式: 
```
run
```

**在另一邊的terminal 打入:**
```
echo "123456789123456789" > testfile
```
可以看到自動生成的`AES key`(32-bits)及`IV`(16-bits)，  
![image](https://hackmd.io/_uploads/BkX5bd37kl.png)


停在中斷點後，在 `gdb`中打入指令，查看memory中的加密資料內容:

```
x/32bx encrypted_data
```

![image](https://hackmd.io/_uploads/Hk6GsF2Qkl.png)


和我們直接印出資料內容:
![image](https://hackmd.io/_uploads/H17ZitnXke.png)
得到一樣的內容

可以看到這串資料使用了AES-256加密演算法，且加密資料 `encrypted_data` 的內容與原始寫入資料: `123456789123456789\n` 沒有任何關係


<font size = 4>**讀取時解密:**</font>
若要查看解密資料是否正確

* 先打:
```
cat testfile
```

* 停在中斷點後，在 `gdb` 打入指令，查看memory中的解密資料內容:
```
x/32bx decrypted_data
```

![image](https://hackmd.io/_uploads/B1fzZkiXkl.png)

這次可以看到，解密的資料為正確資料，因為根據ASCII-Table:
* `1` 為 `0x31`
* `2` 為 `0x32`
* ...
* `9` 為 `0x39`
* `\n` 為 `0x0a`

可以得到結論，寫入的資料經過AES-256加密過後，在未解密的情況下讀取，確實會是一串和原始資料不相關的資料，證實有正確實現加密檔案的動作，  
而解密過後的資料`decrypted_data` 資料為: `123456789123456789\n`，確實為寫入資料，因此驗證AES-256在寫入時有正確加密，不夠的位元也有做padding，而在讀取資料時才做解密的動作，且解密資料為寫入資料正確無誤。

<font size = 4>**測試多個檔案生成不同的key**</font>
```
touch testfile_2
```
![image](https://hackmd.io/_uploads/H1qrIOnmye.png)

```
touch testfile_3
```
![image](https://hackmd.io/_uploads/HkpULdhQkl.png)




# Part 6
<font size = 4>**Testing and Validation**</font>

測試: 若給予錯誤的AES key，是否能解密資料

更改`memfs_read()` 為:
```c
// Use wrong key to decrypted data
int memfs_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi) {
    
    // ...
    
    // 定義錯誤的 AES 金鑰（與正確金鑰不同）
    unsigned char wrong_key[AES_KEY_SIZE] = "wrongkey12345678901234567890abcd";

    // 使用錯誤的金鑰進行解密
    int decrypted_size = decrypt_data((unsigned char *)node->data, node->size,
                                      wrong_key, node->aes_iv, &decrypted_data);

    
    // ...

```


這個`memfs_read()`內預設了錯誤的AES key，在讀取時會使用到錯誤的key，  
並且`return -EIO`，所以在command line 會看到 Input/output error

<font size = 4>**執行結果:**</font>

![image](https://hackmd.io/_uploads/rk_NOY27kl.png)

![image](https://hackmd.io/_uploads/ByuIOt37kx.png)

可以看到，使用錯誤的AES key讀取已經加密的資料，無法讀取






<font size = 4>**卸载file system**</font>
```
fusermount -u /tmp/memfs    
```






# Problems
