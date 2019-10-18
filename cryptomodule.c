#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/moduleparam.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>

#define  DEVICE_NAME "crypto"               // Nome do dispositivo criado em /dev 
#define  CLASS_NAME  "cry"                  // Classe do dispositivo
#define  MESSAGE_SIZE 256

MODULE_LICENSE("GPL");                      // Tipo de licença
MODULE_DESCRIPTION("Crypto Device");        // Descrição do módule

static int    majorNumber;                  // Armazena o número do dispositivo
static char   message[MESSAGE_SIZE] = {0};  // Memória para armazenar mensagem enviada ao usuário
static short  size_of_message;              // Tamanho da mensagem a ser enviada ao usuário
static int    numberOpens = 0;              // Número de vezes em que o dispositivo foi aberto
static struct class*  cryptoClass  = NULL;  // Ponteiro de classe do dispositivo
static struct device* cryptoDevice = NULL;  // Ponteiro do dispositivo
static struct mutex mtx;

// Protótipo das funções
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

static char *key; // Chave de encriptação (Recebida por parâmetro)
static char *iv;  // Vetor de inicialização (Recebido por parâmetro)

// Declaração de parâmetros
module_param(key, charp, 0000);
module_param(iv, charp, 0000);

static int __init crypto_init(void){
   printk(KERN_INFO "CRYPTO: Inicializado dispositivo de criptografia\n");

   if(strlen(key) != 16){
	printk(KERN_ALERT "Falha! O a chave criptografica deve ter 16 caracteres\n");
	return -1;
   }

   if(strlen(iv) != 16){
	printk(KERN_ALERT "Falha! O o vetor de inicializacao deve ter 16 caracteres\n");
        return -1;
   }

   // Aloca número para o dispositivo
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "CRYPTO: Falha ao registrar número de dispositivo \n");
      return majorNumber;
   }
   printk(KERN_INFO "CRYPTO: Dispositivo registrado com o número %d\n", majorNumber);

   // Resgistra a classe do dispositivo
   cryptoClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(cryptoClass)){                
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Falha ao registrar a classe do dispositivo\n");
      return PTR_ERR(cryptoClass);          
   }
   printk(KERN_INFO "CRYPTO: Classe do dispositivo registrada com sucesso\n");

   // Registra o driver de dispositivo
   cryptoDevice = device_create(cryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(cryptoDevice)){
      class_destroy(cryptoClass);
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Falha ao criar o dispositivo\n");
      return PTR_ERR(cryptoDevice);
   }

   mutex_init(&mtx);

   printk(KERN_INFO "CRYPTO: Dispositivo criado com sucesso\n");

   return 0;
}

static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
    int rc = 0;

    if (enc){
        rc = crypto_skcipher_encrypt(sk->request); // Cifra a requisição
    }
    else{
        rc = crypto_skcipher_decrypt(sk->request); // Decifra a requisição
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
        pr_info("skcipher encrypt retornou %d como resultado %d\n", rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

static void __exit crypto_exit(void){
   device_destroy(cryptoClass, MKDEV(majorNumber,0));// Remove o dispositivo
   class_unregister(cryptoClass);                    // Exclui o registro da classe
   class_destroy(cryptoClass);                       // Remove o registro da classe
   unregister_chrdev(majorNumber, DEVICE_NAME);      // Cancela o registro do número do dispositivo

   mutex_unlock(&mtx);             // Destrava mutex

   printk(KERN_INFO "CRYPTO: Dispositivo removido!\n");
}

static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "CRYPTO: O dispositivo foi aberto %d vez(es)\n", numberOpens);
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){
      printk(KERN_INFO "CRYPTO: %d caracter(es) enviado(s) para o usuario\n", size_of_message);
      mutex_unlock(&mtx);          // Destrava mutex
      return (size_of_message=0);  // Reinicia o tamanho da mensagem para zero 
   }
   else {
      printk(KERN_INFO "CRYPTO: Falha ao enviar %d caracter(es) para o usuario\n", error_count);
      mutex_unlock(&mtx);          // Destrava mutex
      return -EFAULT;              // Retorna erro
   }
}

static unsigned int encrypt(const char *string){

   struct skcipher_def sk;
   struct crypto_skcipher *skcipher = NULL;
   struct skcipher_request *request = NULL;
   int ret = -EFAULT;
   int i,j;
   int cipherlen;              // Tam da mensagem a ser cifrada (multiplo de 16)

   char *plaintext = NULL;     // Buffer para a mensagem a ser cifrada 
   char *ciphertext = NULL;    // Buffer para a mensagem cifrada

   char *ivdata = NULL;	       // Buffer para vetor de inicialização
   char *buf = NULL;	       // Buffer para receber a conversão em HEX

   mutex_lock(&mtx); // Trava mutex

   // Aloca skcipher em modo de cifragem cbc
   skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
   if (IS_ERR(skcipher)) {
	pr_info("skcipher nao pode ser alocado\n");
	return PTR_ERR(skcipher);
   }
   printk(KERN_INFO "CRYPTO: Skcipher alocado\n");

   // Aloca requisição de criptografia
   request = skcipher_request_alloc(skcipher, GFP_KERNEL);
   if (!request) {
	pr_info("skcipher request nao pode ser alocado\n");
	ret = -ENOMEM;
	crypto_free_skcipher(skcipher);
	return ret;							
   }
   printk(KERN_INFO "CRYPTO: request alocada\n");

   // Seta chave criptográfica para o skcipher em modo cbc
   if (crypto_skcipher_setkey(skcipher, key, 16)) {
	pr_info("chave criptografica nao pode ser setada\n");
	ret = -EAGAIN;
	skcipher_request_free(request);
	crypto_free_skcipher(skcipher);
	return ret;
   }
   printk(KERN_INFO "CRYPTO: Key setada: %s\n",key);

   //Aloca buffer para vetor de inicialização
   ivdata = kmalloc(16, GFP_KERNEL);
   if (!ivdata ){
	pr_info("ivdata nao pode ser alocado\n");
	skcipher_request_free(request);
	crypto_free_skcipher(skcipher);
	return PTR_ERR(ivdata);
   }

   // Copia vetor de inicialização para o buffer
   for(i = 0; i < strlen(iv); i++){
	ivdata[i] = iv[i];
   };

   cipherlen = ((strlen(string)/16 + 1)*16);

   // Aloca buffer para armazenar a mensagem original
   plaintext = kmalloc(cipherlen, GFP_KERNEL);
   if (!plaintext) {
        pr_info("plaintext nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	return PTR_ERR(plaintext);
   }
   printk(KERN_INFO "CRYPTO: Texto original: %s\n",string);

   sk.tfm = skcipher;
   sk.request = request;

   // Aloca buffer para receber a mensagem original em HEX
   buf = kmalloc(257,GFP_KERNEL);
   if (!buf) {
        pr_info("buf nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(plaintext);
	return PTR_ERR(buf);
   }

   // Converte a mensagem original para HEX
   for(i=0,j=0;i<strlen(string);i++,j+=2){
	 sprintf((char*)buf+j,"%02X",string[i]);
   }
   buf[j] = '\0';
   printk(KERN_INFO "CRYPTO: Texto em hexadecimal: %s\n",buf);

   // Aloca buffer para o resultado cifrado da mensagem
   ciphertext = kmalloc(257,GFP_KERNEL);
   if (!ciphertext) {
        pr_info("ciphertext nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(plaintext);
	kfree(buf);
	return PTR_ERR(ciphertext);
    }
   
   strcpy(plaintext,string); // Copia mensagem original para o buffer
   memset(plaintext+strlen(plaintext),0,cipherlen - strlen(plaintext)); // Realiza padding

   // Inicializa scatterlist de origem e destino da cifragem
   sg_set_buf(&sk.source, plaintext, cipherlen);
   sg_set_buf(&sk.destination, ciphertext, cipherlen);   

   // Inicializa a requisição de cifragem
   skcipher_request_set_crypt(request, &sk.source, &sk.destination, cipherlen, ivdata);
   init_completion(&sk.result.completion);

   ret = test_skcipher_encdec(&sk, 1); // Chama função de cifragem
   if(ret){
	printk(KERN_INFO "erro ao cifrar\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(plaintext);
	kfree(buf);
	kfree(ciphertext);

	return ret;
   }  
   printk(KERN_INFO "CRYPTO: Sucesso ao cifrar\n");

   // Converte mensagem cifrada para HEX
   for(i=0,j=0;i<cipherlen;i++,j+=2){
	sprintf((char*)buf+j,"%02hhX",ciphertext[i]);
   }
   buf[j] = '\0';

   printk(KERN_INFO "CRYPTO: Texto cifrado em hexadecimal: %s\n",buf);

   // Prepara mensagem para o usuário
   sprintf(message, "%s", buf);
   size_of_message = strlen(message);

   // Desaloca recursos
   skcipher_request_free(request);
   crypto_free_skcipher(skcipher);
   kfree(ivdata);
   kfree(plaintext);
   kfree(buf);
   kfree(ciphertext);

   return 1;
}

static unsigned int decrypt(const char *string){

   struct skcipher_def sk;
   struct crypto_skcipher *skcipher = NULL;
   struct skcipher_request *request = NULL;
   int ret = -EFAULT;
   int i,j;
   int cipherlen;

   char *ciphertext = NULL;	// Buffer para a mensagem cifrada
   char *plaintext = NULL;	// Buffer para a mensagem a ser decifrada

   char *ivdata = NULL;         // Buffer para vetor de inicialização
   char *text = NULL;           // Buffer para receber a conversão em HEX

   mutex_lock(&mtx); // Trava mutex
   
   // Aloca skcipher em modo de cifragem cbc
   skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
   if (IS_ERR(skcipher)) {
	pr_info("skcipher nao pode ser alocado\n");
	return PTR_ERR(skcipher);
   }
   printk(KERN_INFO "CRYPTO: Skcipher alocado\n");

   // Aloca requisição de criptografia
   request = skcipher_request_alloc(skcipher, GFP_KERNEL);
   if (!request) {
	pr_info("skcipher request nao pode ser alocado\n");
	ret = -ENOMEM;
	crypto_free_skcipher(skcipher);
	return ret;							
   }
   printk(KERN_INFO "CRYPTO: Request alocada\n");

   // Seta chave criptográfica para o skcipher em modo cbc  
   if (crypto_skcipher_setkey(skcipher, key, 16)) {
        pr_info("chave Criptografica nao pode ser setada\n");
        ret = -EAGAIN;
	skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	return ret;
   }
   printk(KERN_INFO "CRYPTO: Key setada: %s\n",key);

   //Aloca buffer para vetor de inicialização
   ivdata = kmalloc(16, GFP_KERNEL);
   if (!ivdata) {
        pr_info("ivdata nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	return PTR_ERR(ivdata);
   }

   // Copia vetor de inicialização para o buffer
   for(i = 0; i < strlen(iv); i++){
	ivdata[i] = iv[i];
   };

   // Aloca buffer para receber a conversão da mensagem de HEX para ASCII
   text = kmalloc(129,GFP_KERNEL);
   if (!text) {
        pr_info("text nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	return PTR_ERR(text);
   }

   // Converte mensagem cifrada para ASCII 
   for(i = 0, j = 0; j < strlen(string); ++i, j += 2){
	int val[1];
	char aux[9];
	
	aux[0] = string[j];
	aux[1] = string[j+1];
	aux[2] = '\0';

	sscanf(aux,"%2x",val);
	text[i] = val[0];
   }	
   text[i] = '\0';

   cipherlen = ((strlen(text)/16 + 1)*16); // Calcula tamanho da mensagem (multiplo de 16 bytes)

   //Aloca buffer a mensagem cifrada
   ciphertext = kmalloc(cipherlen, GFP_KERNEL);
   if (!ciphertext) {
        pr_info("ciphertext nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(text);
	return PTR_ERR(ciphertext);
   }

   strcpy(ciphertext,text); // Copia mensagem cifrada para o buffer
   memset(ciphertext+strlen(ciphertext),0,cipherlen - strlen(ciphertext)); // Realiza padding

   sk.tfm = skcipher;
   sk.request = request;

   // Aloca buffer para o resultado decifrado da mensagem
   plaintext = kmalloc(257,GFP_KERNEL);
   if (!plaintext) {
        pr_info("plaintext nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(ivdata);
	kfree(text);
	kfree(ciphertext);
	return PTR_ERR(plaintext);
   }
   printk(KERN_INFO "CRYPTO: Texto cifrado: %s\n",string);

   // Inicializa scatterlist de origem e destino da decifragem
   sg_set_buf(&sk.source, ciphertext, cipherlen);
   sg_set_buf(&sk.destination, plaintext,cipherlen);

   // Inicializa a requisição de decifragem
   skcipher_request_set_crypt(request, &sk.source, &sk.destination, cipherlen, ivdata);
   init_completion(&sk.result.completion);

   ret = test_skcipher_encdec(&sk, 0); //Chama função de cifragem/decifragem
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
   printk(KERN_INFO "CRYPTO: Texto decifrado: %s\n",plaintext);

   // Prepara mensagem para o usuário
   sprintf(message, "%s", plaintext);
   size_of_message = strlen(message);

   // Desaloca recursos
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
    u8 hash_value[20];
    size_t len;
    int i,j;

    char hex_value[64];
    char *text;

    mutex_lock(&mtx); // Trava mutex

    // Aloca buffer para mensagem original
    text = kmalloc(257,GFP_KERNEL); 
    if(!text){
	pr_info("Nao foi possivel alocar o texto\n");
	return PTR_ERR(text);
    }

    strcpy(text,string);	// Copia mensagem para o buffer
    len = strlen(text);		// Calcula o tamanho da mensagem

    // Inicializa scatterlist
    sg_set_buf(&sg, text, len);
    printk("CRYPTO: Scatterlist linkada com texto\n");

    // Aloca handle de criptografia hash em modo SHA1
    desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    printk("CRYPTO: Tipo de encriptacao setado para SHA1\n");

    crypto_hash_init(&desc);
    crypto_hash_update(&desc, &sg, len);
    crypto_hash_final(&desc, hash_value);

    // Desaloca recursos
    crypto_free_hash(desc.tfm);
    kfree(text);

    // Converte resultado da cifragem para HEX
    for(i=0,j=0;i<20;i++,j+=2){
	sprintf((char*)hex_value+j,"%02hhX",hash_value[i]);
    }
    hex_value[j] = '\0';

    printk("CRYPTO: Texto [%s] encriptado para [%s] utilizando SHA1\n",string,hex_value);

    // Prepara mensagem para o usuário
    sprintf(message, "%s", hex_value);
    size_of_message = strlen(message);

    return 0;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){

    // Chama a função correspondente ao primeiro caractere
    if(buffer[0] == 'c')
	return encrypt(buffer+2);
    if(buffer[0] == 'd')
	return decrypt(buffer+2);
    if(buffer[0] == 'h')
	return sha1(buffer+2);

    return 0;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "CRYPTO: Dispositivo fechado com sucesso\n");
   return 0;
}

module_init(crypto_init);
module_exit(crypto_exit);
