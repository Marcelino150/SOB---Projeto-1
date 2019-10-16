#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int cifrar(char *string);
int decifrar(char *string);
int hash(char *string);

int main(int argc,char *argv[]){

  int i = 1;
  int tam_palavra = 0;
  char operacao;
  char stringToSend[BUFFER_LENGTH] = "";

  int j;

   if(argc < 2){
	printf("Erro! Sem parametros\n");
	return 0;
   }

   operacao = argv[1][0];

   if(operacao == 'c' && argc > 2){

	char string_hex[BUFFER_LENGTH];

	while(i < argc){

	   strcat(stringToSend + tam_palavra,argv[i]);

	   if(argv[i+1] != NULL)
	   	strcat(stringToSend + tam_palavra," ");

	   tam_palavra = strlen(argv[i]) + 1;
	   i++;
	}

	//printf("%s\n",stringToSend);
	cifrar(stringToSend);
   }
   else if(operacao == 'd' && argc > 2){

	while(i < argc){

	   strcat(stringToSend + tam_palavra,argv[i]);

	   if(argv[i+1] != NULL)
	   	strcat(stringToSend + tam_palavra," ");

	   tam_palavra = strlen(argv[i]) + 1;
	   i++;
	}

	decifrar(stringToSend);
   }
   else if(operacao == 'h' && argc > 2){
	while(i < argc){

	   strcat(stringToSend + tam_palavra,argv[i]);

	   if(argv[i+1] != NULL)
	   	strcat(stringToSend + tam_palavra," ");

	   tam_palavra = strlen(argv[i]) + 1;
	   i++;
	}

	hash(stringToSend);
   }
   else{
	printf("Erro! Comando invalido!\n");
   }


   /*int ret, fd;
   char stringToSend[BUFFER_LENGTH];
   printf("Starting device test code example...\n");
   fd = open("/dev/crypto", O_RDWR);             // Open the device with read/write access
   if (fd < 0){
      perror("Failed to open the device...");
      return errno;
   }
   printf("Type in a short string to send to the kernel module:\n");
   scanf("%[^\n]%*c", stringToSend);                // Read in a string (with spaces)
   printf("Writing message to the device [%s].\n", stringToSend);
   ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
   if (ret < 0){
      perror("Failed to write the message to the device.");
      return errno;
   }

   printf("Press ENTER to read back from the device...\n");
   getchar();

   printf("Reading from the device...\n");
   ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
   if (ret < 0){
      perror("Failed to read the message from the device.");
      return errno;
   }
   printf("The received message is: [%s]\n", receive);
   printf("End of the program\n");
   return 0;*/
}

int hash(char *string){

   int ret, fd;

   printf("Iniciando dispositivo de criptografia...\n");

   fd = open("/dev/crypto", O_RDWR); // Open the device with read/write access
   if (fd < 0){
      perror("Falha ao iniciar o dispositivo...");
      return errno;
   }

   ret = write(fd, string, strlen(string)); // Send the string to the LKM
   if (ret < 0){
      perror("Falha ao encriptar a mensagem.");
      return errno;
   }

   printf("Pressione ENTER para ter o resumo criptografico...\n");
   getchar();

   printf("Lendo do dispositivo...\n");
   ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
   if (ret < 0){
      perror("Falha ao ler a mensagem do dispositivo.");
      return errno;
   }
   printf("Resumo criptografico em hexadecimal: [%s]\n", receive);
   printf("Fim do programa\n");

   return 1;

}

int cifrar(char *string){

   int ret, fd,i ,j;
   char string_hex[BUFFER_LENGTH];
   char string_aux[BUFFER_LENGTH];

   printf("Iniciando dispositivo de criptografia...\n");

   fd = open("/dev/crypto", O_RDWR); // Open the device with read/write access
   if (fd < 0){
      perror("Falha ao iniciar o dispositivo...");
      return errno;
   }

   strcpy(string_aux,string+2);

   for(i=0,j=0;i<strlen(string_aux);i++,j+=2){
     sprintf((char*)string_hex+j,"%02X",string_aux[i]);
   }
   
   printf("Encriptando mensagem [%s]:[%s].\n", string_aux,string_hex);
   ret = write(fd, string, strlen(string)); // Send the string to the LKM
   if (ret < 0){
      perror("Falha ao encriptar a mensagem.");
      return errno;
   }

   printf("Pressione ENTER para ter a mensagem criptografada...\n");
   getchar();

   printf("Lendo do dispositivo...\n");
   ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
   if (ret < 0){
      perror("Falha ao ler a mensagem do dispositivo.");
      return errno;
   }
   printf("Mensagem encriptada em hexadecimal: [%s]\n", receive);
   printf("Fim do programa\n");

   return 1;
}

int decifrar(char *string){

   int ret, fd,i ,j;

   printf("Iniciando dispositivo de criptografia...\n");

   fd = open("/dev/crypto", O_RDWR); // Open the device with read/write access
   if (fd < 0){
      perror("Falha ao iniciar o dispositivo...");
      return errno;
   }

   printf("Decifrando mensagem [%s].\n", string+2);
   ret = write(fd, string, strlen(string)); // Send the string to the LKM
   if (ret < 0){
      perror("Falha ao decifrar a mensagem.");
      return errno;
   }

   printf("Pressione ENTER para ter a mensagem decifrada...\n");
   getchar();

   printf("Lendo do dispositivo...\n");
   ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
   if (ret < 0){
      perror("Falha ao ler a mensagem do dispositivo.");
      return errno;
   }
   printf("Mensagem decifrada: [%s]\n", receive);
   printf("Fim do programa\n");

   return 1;
}
