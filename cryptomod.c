/**
 * @file   ebbchar.c
 * @author Derek Molloy
 * @date   7 April 2015
 * @version 0.1
 * @brief   An introductory character driver to support the second article of my series on
 * Linux loadable kernel module (LKM) development. This module maps to /dev/ebbchar and
 * comes with a helper C program that can be run in Linux user space to communicate with
 * this the LKM.
 * @see http://www.derekmolloy.ie/ for a full description and follow-up descriptions.
 */

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

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
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
    struct scatterlist sg;
    struct scatterlist sf;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
}b;

static char *key;
static char *iv;

module_param(key, charp, 0644);
module_param(iv, charp, 0644);


/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
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

static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
                     int enc)
{
    int rc = 0;

    if (enc){
	pr_info("skcipher encrypt %p\n",sk->req);
        rc = crypto_skcipher_encrypt(sk->req);
    }
    else{
	pr_info("skcipher decrypt %p\n",sk->req);
        rc = crypto_skcipher_decrypt(sk->req);
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

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit crypto_exit(void){
   device_destroy(cryptoClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(cryptoClass);                          // unregister the device class
   class_destroy(cryptoClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number

    printk(KERN_INFO "CRYPTO: Goodbye from the LKM!\n");
}

/** @brief The device open function that is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "CRYPTO: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case is uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
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

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){

    struct skcipher_def sk;
    struct skcipher_def sk1;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    struct skcipher_request *req1 = NULL;
    char *buf = kmalloc(sizeof(buffer),GFP_KERNEL);
    int ret = -EFAULT;

    char *buf1 = kmalloc(MESSAGE_SIZE,GFP_KERNEL);
    char *buf2 = kmalloc(MESSAGE_SIZE,GFP_KERNEL);
    char *buf3 = kmalloc(MESSAGE_SIZE,GFP_KERNEL);
    char *buf4 = kmalloc(MESSAGE_SIZE,GFP_KERNEL);

    char *hexiv = kmalloc(MESSAGE_SIZE,GFP_KERNEL);

    int i,j;

    char *scratchpad = NULL;
    char *ivdata = NULL;
    char *originaliv = NULL;
    //unsigned char keyy[16];
   
   skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
   if (IS_ERR(skcipher)) {
      pr_info("could not allocate skcipher handle\n");
      return PTR_ERR(skcipher);
   }
   printk(KERN_INFO "CRYPTO: skcipher alocado\n");

   req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        crypto_free_skcipher(skcipher);
	return ret;							
    }

    pr_info("key:%s iv:%s\n",key,iv);

    //AES 256 with random key
    //get_random_bytes(&keyy, 16);
    if (crypto_skcipher_setkey(skcipher, key, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
	skcipher_request_free(req);
        crypto_free_skcipher(skcipher);
	return ret;
    }

    ivdata = kmalloc(16, GFP_KERNEL);
    originaliv = kmalloc(16, GFP_KERNEL);
    if (!ivdata || !originaliv) {
        pr_info("could not allocate ivdata\n");
        skcipher_request_free(req);
        crypto_free_skcipher(skcipher);
    }
    //get_random_bytes(ivdata, 16);

    *originaliv = *ivdata = *iv;

    for(i=0,j=0;i<strlen(ivdata);i++,j+=2){
	 sprintf((char*)hexiv+j,"%02X",ivdata[i]);
    }

    pr_info("1.IVDATA:%s\n",hexiv);

    for(i=0,j=0;i<strlen(originaliv);i++,j+=2){
	 sprintf((char*)hexiv+j,"%02X",originaliv[i]);
    }

    pr_info("2.ORIGINALIV:%s\n",hexiv);

    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        skcipher_request_free(req);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(originaliv);
    }
    get_random_bytes(scratchpad, 16);

    sk.tfm = skcipher;
    sk.req = req;

    //We encrypt one block
    sg_init_one(&sk.sg, scratchpad, 16);
    sg_init_one(&sk.sf, buf, 16);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sf, 16, ivdata);
    init_completion(&sk.result.completion);

    ret = test_skcipher_encdec(&sk, 1);
    if(ret){

	printk(KERN_INFO "erro ao cifrar\n");

	crypto_free_skcipher(skcipher);
    	skcipher_request_free(req);
   	kfree(ivdata);
        kfree(originaliv);
   	kfree(buf);
   	kfree(buf1);
   	kfree(buf2);
   	kfree(buf3);
   	kfree(buf4);

	return ret;
    }

    pr_info("CRYPTO: Sucesso ao cifrar\n");

    buf1 = sg_virt(&sk.sg);

    pr_info("Original:%s\n",buf1);
    for(i=0,j=0;i<strlen(buf1);i++,j+=2){
	 sprintf((char*)buf2+j,"%02X",buf1[i]);
    }

    buf2[j] = '\0';
    printk("Original hex: %s\n\n",buf2);

    pr_info("Encriptado:%s\n",buf);
    for(i=0,j=0;i<strlen(buf);i++,j+=2){
	 sprintf((char*)buf3+j,"%02X",buf[i]);
    }

    buf3[j] = '\0';
    printk("Encriptado hex: %s\n\n",buf3);



    req1 = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req1) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        crypto_free_skcipher(skcipher);
        skcipher_request_free(req);
	kfree(ivdata);
	kfree(originaliv);
	return ret;							
    }

   pr_info("Encriptado:%s\n",buf);





    sg_init_one(&sk1.sg, buf, 16);
    sg_init_one(&sk1.sf, buf1, 16);

    sk1.tfm = skcipher;
    sk1.req = req1;

    skcipher_request_set_crypt(req1, &sk1.sg, &sk1.sf, 16, originaliv);
    init_completion(&sk1.result.completion);

    ret = test_skcipher_encdec(&sk1, 0);
    if(ret){

	printk(KERN_INFO "erro ao decifrar\n");

	crypto_free_skcipher(skcipher);
    	skcipher_request_free(req);
	kfree(originaliv);
   	kfree(ivdata);
   	kfree(buf);
   	kfree(buf1);
   	kfree(buf2);
   	kfree(buf3);
   	kfree(buf4);

	return ret;
    }

    pr_info("Decryption triggered successfully\n");

    pr_info("Decriptado:%0s\n",buf1);
    for(i=0,j=0;i<strlen(buf1);i++,j+=2){
	 sprintf((char*)buf4+j,"%02X",buf1[i]);
    }

    buf4[j] = '\0';
    printk("Decriptado hex: %s\n",buf4);


    if (ret){
        skcipher_request_free(req1);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	return ret;
    }

   sprintf(message, "%s", buffer);   // appending received string with its length
   size_of_message = strlen(message);                 // store the length of the stored message

   /*sprintf(message, "%s(%zu letters)", buffer, len);   // appending received string with its length
   size_of_message = strlen(message);                 // store the length of the stored message*/
 
   crypto_free_skcipher(skcipher);
   skcipher_request_free(req);
   skcipher_request_free(req1);
   kfree(ivdata);
   kfree(buf);
   kfree(buf1);
   kfree(buf2);
   kfree(buf3);
   kfree(buf4);

   printk(KERN_INFO "CRYPTO: Received %zu characters from the user\n", len);
   return len;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "CRYPTO: Device successfully closed\n");
   return 0;
}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(crypto_init);
module_exit(crypto_exit);
