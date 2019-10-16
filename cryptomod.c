#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#include <linux/random.h>

#include <linux/moduleparam.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

//#include <openssl/sha.h>
#define  DEVICE_NAME "crypto"    ///< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "cry"        ///< The device class -- this is a character device driver
#define  MESSAGE_SIZE 256

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_DESCRIPTION("Crypto Device");  ///< The description -- see modinfo

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static char   message[MESSAGE_SIZE] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  cryptoClass  = NULL; ///< The device-driver class struct pointer
static struct device* cryptoDevice = NULL; ///< The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

struct tcrypt_result {
    struct completion completion;
    int err;
}a;

struct skcipher_def {
    struct scatterlist source;
    struct scatterlist destination;
    struct crypto_skcipher *tfm;
    struct skcipher_request *request;
    struct tcrypt_result result;
}b;

static char *key;
static char *iv;

module_param(key, charp, 0000);
module_param(iv, charp, 0000);

static int __init crypto_init(void){
   printk(KERN_INFO "CRYPTO: Initializing the CRYPTO LKM\n");

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "CRYPTO: failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "CRYPTO: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   cryptoClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(cryptoClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(cryptoClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "CRYPTO: device class registered correctly\n");

   // Register the device driver
   cryptoDevice = device_create(cryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(cryptoDevice)){               // Clean up if there is an error
      class_destroy(cryptoClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(cryptoDevice);
   }
   printk(KERN_INFO "CRYPTO: device class created correctly\n"); // Made it! device was initialized

   return 0;
}

static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
    int rc = 0;

    if (enc){
        rc = crypto_skcipher_encrypt(sk->request);
    }
    else{
        rc = crypto_skcipher_decrypt(sk->request);
    }

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:;
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n", rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

static void __exit crypto_exit(void){
   device_destroy(cryptoClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(cryptoClass);                          // unregister the device class
   class_destroy(cryptoClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number

   printk(KERN_INFO "CRYPTO: Goodbye from the LKM!\n");
}

static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "CRYPTO: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "CRYPTO: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "CRYPTO: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

static unsigned int encrypt(const char *string){

   struct skcipher_def sk;
   struct crypto_skcipher *skcipher = NULL;
   struct skcipher_request *request = NULL;
   int ret = -EFAULT;
   int i,j;
   int no_blocks = 0, modd;

   char *plaintext = NULL;
   char *chiphertext;

   char *ivdata = NULL;
   char *buf;

   skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
   if (IS_ERR(skcipher)) {
      pr_info("could not allocate skcipher handle\n");
      return PTR_ERR(skcipher);
   }
   printk(KERN_INFO "CRYPTO: skcipher alocado\n");

   request = skcipher_request_alloc(skcipher, GFP_KERNEL);
   if (!request) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        crypto_free_skcipher(skcipher);
	return ret;							
   }

   printk(KERN_INFO "CRYPTO: request alocada\n");

   if (crypto_skcipher_setkey(skcipher, key, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
	skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	return ret;
   }

   printk(KERN_INFO "CRYPTO: key setada: %s\n",key);

   ivdata = kmalloc(16, GFP_KERNEL);
   if (!ivdata ){
	pr_info("could not allocate ivdata\n");
	skcipher_request_free(request);
	crypto_free_skcipher(skcipher);
	return PTR_ERR(ivdata);
   }

   for(i = 0; i < 16; i++){
	if(i < strlen(iv))
	   ivdata[i] = iv[i];
	else
	  ivdata[i] = '0';
   };

   printk(KERN_INFO "CRYPTO: vetor de inicializacao: %s\n",iv);

   no_blocks = 0;
   no_blocks = strlen(string)/16;
   modd = strlen(string)%16;

   if(modd>0)
	no_blocks++;

   plaintext = kmalloc(no_blocks*16, GFP_KERNEL);
   if (!plaintext) {
        pr_info("could not allocate plaintext\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	return PTR_ERR(plaintext);
   }

   for(i = 0; i < no_blocks*16; i++){

	if(i < strlen(string))
	   plaintext[i] = string[i];
	else if(i == strlen(string))
	   plaintext[i] = '\0';
	else
	   plaintext[i] = '0';
   }

   printk(KERN_INFO "CRYPTO: texto original: %s\n",string);

   sk.tfm = skcipher;
   sk.request = request;

   buf = kmalloc(257,GFP_KERNEL);
   if (!buf) {
        pr_info("could not allocate plaintext\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(plaintext);
	return PTR_ERR(buf);
    }

   for(i=0,j=0;i<strlen(string);i++,j+=2){
	 sprintf((char*)buf+j,"%02X",string[i]);
   }
   buf[j] = '\0';

   printk(KERN_INFO "CRYPTO: texto em hexadecimal: %s\n",buf);

   chiphertext = kmalloc(129,GFP_KERNEL);
   if (!chiphertext) {
        pr_info("could not allocate plaintext\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(plaintext);
	kfree(buf);
	return PTR_ERR(chiphertext);
    }

    sg_set_buf(&sk.source, plaintext, 16);
    sg_set_buf(&sk.destination, chiphertext, 16);

    skcipher_request_set_crypt(request, &sk.source, &sk.destination, 16, ivdata);
    init_completion(&sk.result.completion);

    ret = test_skcipher_encdec(&sk, 1);

    if(ret){
	printk(KERN_INFO "erro ao cifrar\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(plaintext);
	kfree(buf);
	kfree(chiphertext);

	return ret;
    }
    chiphertext[16] = '\0';   

    printk(KERN_INFO "CRYPTO: Sucesso ao cifrar\n");

    for(i=0,j=0;i<strlen(chiphertext);i++,j+=2){
	sprintf((char*)buf+j,"%02hhX",chiphertext[i]);
    }
    buf[j] = '\0';

    printk(KERN_INFO "CRYPTO: texto cifrado em hexadecimal: %s\n",buf);

    sprintf(message, "%s", buf);
    size_of_message = strlen(message);

    skcipher_request_free(request);
    crypto_free_skcipher(skcipher);
    kfree(ivdata);
    kfree(plaintext);
    kfree(buf);
    kfree(chiphertext);

    return 1;
}

static unsigned int decrypt(const char *string){

   struct skcipher_def sk;
   struct crypto_skcipher *skcipher = NULL;
   struct skcipher_request *request = NULL;
   int ret = -EFAULT;
   int i,j;
   int no_blocks = 0, modd;

   char *ciphertext = NULL;
   char *plaintext = NULL;

   char *ivdata = NULL;
   char *text = NULL;

   skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
   if (IS_ERR(skcipher)) {
	pr_info("could not allocate skcipher handle\n");
	return PTR_ERR(skcipher);
   }
   printk(KERN_INFO "CRYPTO: skcipher alocado\n");

   request = skcipher_request_alloc(skcipher, GFP_KERNEL);
   if (!request) {
	pr_info("could not allocate skcipher request\n");
	ret = -ENOMEM;
	crypto_free_skcipher(skcipher);
	return ret;							
   }

   printk(KERN_INFO "CRYPTO: request alocada\n");

   if (crypto_skcipher_setkey(skcipher, key, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
	skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	return ret;
   }

   printk(KERN_INFO "CRYPTO: key setada: %s\n",key);

   ivdata = kmalloc(16, GFP_KERNEL);
   if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	return PTR_ERR(ivdata);
   }

   for(i = 0; i < 16; i++){
	if(i < strlen(iv))
	    ivdata[i] = iv[i];
	else
	    ivdata[i] = '0';
   };

   printk(KERN_INFO "CRYPTO: vetor de inicializacao: %s\n",iv);

   text = kmalloc(129,GFP_KERNEL);
   if (!text) {
        pr_info("could not allocate ivdata\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	return PTR_ERR(text);
   }

   for(i = 0, j = 0; j < strlen(string); ++i, j += 2){

	int val[1];
	char aux1[9];
	
	aux1[0] = string[j];
	aux1[1] = string[j+1];
	aux1[2] = '\0';

	sscanf(aux1,"%2x",val);
	text[i] = val[0];
   }	
   text[i] = '\0';

   no_blocks = 0;
   no_blocks = strlen(text)/16;
   modd = strlen(text)%16;

   if(modd>0)
	no_blocks++;

    ciphertext = kmalloc(16, GFP_KERNEL);
    if (!ciphertext) {
        pr_info("could not allocate ciphertext\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(text);
	return PTR_ERR(ciphertext);
    }

    for(i = 0; i < no_blocks*16; i++){

	if(i < strlen(text))
	   ciphertext[i] = text[i];
	else if(i == strlen(text))
	   ciphertext[i] = '\0';
	else
	   ciphertext[i] = '0';
    }

    sk.tfm = skcipher;
    sk.request = request;

    plaintext = kmalloc(257,GFP_KERNEL);
    if (!plaintext) {
        pr_info("could not allocate ciphertext\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(text);
	kfree(ciphertext);
	return PTR_ERR(plaintext);
    }

    printk(KERN_INFO "CRYPTO: texto cifrado: %s\n",string);

    sg_set_buf(&sk.source, ciphertext, 16);
    sg_set_buf(&sk.destination, plaintext,16);
    skcipher_request_set_crypt(request, &sk.source, &sk.destination, 16, ivdata);
    init_completion(&sk.result.completion);

    ret = test_skcipher_encdec(&sk, 0);
    if(ret){

	printk(KERN_INFO "erro ao cifrar\n");
	crypto_free_skcipher(skcipher);
	skcipher_request_free(request);
	kfree(ivdata);
	kfree(text);
	kfree(ciphertext);
	kfree(plaintext);

	return ret;
    }

    pr_info("CRYPTO: Sucesso ao decifrar\n");

    printk(KERN_INFO "CRYPTO: texto decifrado: %s\n",plaintext);

    sprintf(message, "%s", plaintext);
    size_of_message = strlen(message);

    crypto_free_skcipher(skcipher);
    skcipher_request_free(request);
    kfree(ivdata);
    kfree(text);
    kfree(ciphertext);
    kfree(plaintext);

    return 1;
}

static unsigned int sha1(const char *string){

    struct scatterlist sg;
    struct hash_desc desc;
    u8 hash_value[32];
    int i,j;

    char hex_value[64];
    char *text = kmalloc(strlen(string),GFP_KERNEL);

    if(!text){
	pr_info("Nao foi possivel alocar o texto\n");
	return PTR_ERR(text);
    }

    strcpy(text,string);

    sg_set_buf(&sg, text, strlen(text));
    printk("CRYPTO: Scatterlist linkada com texto\n");
    desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    printk("CRYPTO: Tipo de encriptacao setado para SHA1\n");

    crypto_hash_init(&desc);
    crypto_hash_update(&desc, &sg, strlen(text));
    crypto_hash_final(&desc, hash_value);

    crypto_free_hash(desc.tfm);
    kfree(text);

    for(i=0,j=0;i<strlen(hash_value);i++,j+=2){
	sprintf((char*)hex_value+j,"%02hhX",hash_value[i]);
    }
    hex_value[40] = '\0';

    printk("CRYPTO: text [%s] encriptado para [%s] utilizando SHA1\n",string,hex_value);

    sprintf(message, "%s", hex_value);
    size_of_message = strlen(message);

    return 0;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){


    if(buffer[0] == 'c')
	return encrypt(buffer+2);
    if(buffer[0] == 'd')
	return decrypt(buffer+2);
    if(buffer[0] == 'h')
	return sha1(buffer+2);

    return 0;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "CRYPTO: Device successfully closed\n");
   return 0;
}

module_init(crypto_init);
module_exit(crypto_exit);
