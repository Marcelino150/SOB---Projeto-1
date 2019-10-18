#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256               // Tamanho do buffer
static char receive[BUFFER_LENGTH];     // Buffer para strings de resultado

int encrypt(char *string);
int decrypt(char *string);
int hash(char *string);
void concat(int n_arg, char *argv[], char *string);

int main(int argc,char *argv[]){

   char op;
   char stringToSend[BUFFER_LENGTH] = "";

   if(argc < 2){
	printf("Erro! Sem parametros\n");
	return 0;
   }

   op = argv[1][0]; // Pega o primeiro argumento

   // Seleciona a operação
   if(op == 'c' && argc > 2){

        concat(argc,argv,stringToSend);
	encrypt(stringToSend);  // Chama função de encriptação
   }
   else if(op == 'd' && argc > 2){

	concat(argc,argv,stringToSend);
	decrypt(stringToSend);  // Chama função de desencriptação
   }
   else if(op == 'h' && argc > 2){

	concat(argc,argv,stringToSend);
	hash(stringToSend);     // Chama função de hash (SHA1)
   }
   else{
	printf("Erro! Comando invalido!\n");
   }
}

// Transforma os argumentos a partir do terceiro em uma string continua
void concat(int n_arg, char *argv[], char *string){

   int tam = 0;
   int i = 1;

   while(i < n_arg){
	strcat(string + tam,argv[i]);

	if(argv[i+1] != NULL)
	   strcat(string + tam," ");

	tam = strlen(argv[i]) + 1;
	i++;
   }
}

int hash(char *string){

   int ret, fd;

   printf("Iniciando dispositivo de criptografia...\n");

   fd = open("/dev/crypto", O_RDWR); // Abre o dispositivo
   if (fd < 0){
      perror("Falha ao iniciar o dispositivo...");
      return errno;
   }

   ret = write(fd, string, strlen(string)); // Executa função de escrita eviando a string
   if (ret < 0){
      perror("Falha ao encriptar a mensagem.");
      return errno;
   }

   printf("Pressione ENTER para ter o resumo criptografico...\n");
   getchar();

   printf("Lendo do dispositivo...\n");
   ret = read(fd, receive, BUFFER_LENGTH); // Executa a função de leitura recebendo uma string
   if (ret < 0){
      perror("Falha ao ler a mensagem do dispositivo.");
      return errno;
   }
   printf("Resumo criptografico em hexadecimal: [%s]\n", receive);
   printf("Fim do programa\n");

   return 1;

}

int encrypt(char *string){

   int ret, fd,i ,j;
   char string_hex[BUFFER_LENGTH];
   char string_aux[BUFFER_LENGTH];

   printf("Iniciando dispositivo de criptografia...\n");

   fd = open("/dev/crypto", O_RDWR); // Executa função de escrita eviando a string
   if (fd < 0){
      perror("Falha ao iniciar o dispositivo...");
      return errno;
   }

   strcpy(string_aux,string+2);

   for(i=0,j=0;i<strlen(string_aux);i++,j+=2){
     sprintf((char*)string_hex+j,"%02X",string_aux[i]);
   }
   
   printf("Encriptando mensagem [%s]:[%s].\n", string_aux,string_hex);
   ret = write(fd, string, strlen(string)); // Executa função de escrita eviando a string
   if (ret < 0){
      perror("Falha ao encriptar a mensagem.");
      return errno;
   }

   printf("Pressione ENTER para ter a mensagem criptografada...\n");
   getchar();

   printf("Lendo do dispositivo...\n");
   ret = read(fd, receive, BUFFER_LENGTH); // Executa a função de leitura recebendo uma string
   if (ret < 0){
      perror("Falha ao ler a mensagem do dispositivo.");
      return errno;
   }
   printf("Mensagem encriptada em hexadecimal: [%s]\n", receive);
   printf("Fim do programa\n");

   return 1;
}

int decrypt(char *string){

   int ret, fd,i ,j;

   printf("Iniciando dispositivo de criptografia...\n");

   fd = open("/dev/crypto", O_RDWR); // Executa função de escrita eviando a string
   if (fd < 0){
      perror("Falha ao iniciar o dispositivo...");
      return errno;
   }

   printf("Decifrando mensagem [%s].\n", string+2);
   ret = write(fd, string, strlen(string)); // Executa função de escrita eviando a string
   if (ret < 0){
      perror("Falha ao decifrar a mensagem.");
      return errno;
   }

   printf("Pressione ENTER para ter a mensagem decifrada...\n");
   getchar();

   printf("Lendo do dispositivo...\n");
   ret = read(fd, receive, BUFFER_LENGTH);  // Executa a função de leitura recebendo uma string
   if (ret < 0){
      perror("Falha ao ler a mensagem do dispositivo.");
      return errno;
   }
   printf("Mensagem decifrada: [%s]\n", receive);
   printf("Fim do programa\n");

   return 1;
}
