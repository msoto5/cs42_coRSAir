#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>


#define TAM 1024
#define exp RSA_F4
#define bits 256

// --------------- ATAQUE WIENER ---------------
int nextConvergent (long long int *a, long long int *b, long long int *numerator, long long int *previous_numerator,long long int *denominator, long long int *previous_denominator)
{
    long long int q,r, aux_numerator, aux_denominator;
    
    if (*b == 0)
    {
        return 0;
    } 

    q = *a / *b;
    r = *a - *b * q;
    aux_numerator = *numerator;
    aux_denominator = *denominator;

    *numerator = q * (*numerator) + (*previous_numerator);
    *denominator = q * (*denominator) + (*previous_denominator);
    *previous_numerator = aux_numerator;
    *previous_denominator = aux_denominator;

    *a = *b;
    *b = r;

    return 1;
}

int prueba_ataque(long long int k, long long int d, long long int e, long long int N, long long int *phi){
    long double discriminant,raiz;
    long long int b,c,raiz_int;

    //printf("\nPruba ataque input.\n k:%lld d:%lld\ne:%lld N:%lld\nmultipliacion: %lld\n ",k,d,e,N,e*d-1);
    if (d % 2 == 0 || d == 1) return 0;

    if ((e*d-1) % k != 0) return 0;

    //printf("He pasado las dos primeras pruebas!!!\n\n");
    *phi = (e*d-1)/k;

    c = N;
    b = N - *phi + 1;
    discriminant = (long double) b * b - 4 * c;
    raiz = sqrtl(discriminant);
    raiz_int = (long long int)raiz;
    
    if (raiz_int*raiz_int != (long long int)discriminant){
        return 0;
    }

    return 1;
}

long long int ataque_wiener(long long int N, long long int e)
{
    long long int d,k,phi,k_prev,d_prev,N_copy,e_copy;

    N_copy = N;
    e_copy = e;

    k = 1;
    k_prev = 0;
    d = 0;
    d_prev = 1;

    while(nextConvergent(&e_copy,&N_copy,&k,&k_prev,&d,&d_prev) == 1){
        //printf("\n\nCONVERGENT:\na:%lld\nb:%lld\nk:%lld\nd:%lld\n",N_copy,e_copy,k,d);

        if (prueba_ataque(k,d,e,N,&phi) == 1)
        {
            return d;
        }
        
    }

    return 0;
}
// --------------- ATAQUE WIENER ---------------


// ------------ LEER CLAVE PUBLICA ------------
int leer_clave_publica(char *key_file)
{
    FILE *file = NULL;
    EVP_PKEY *evp_pubkey = NULL;
    RSA *rsa_pubkey = NULL;
    BIO *keybio = BIO_new(BIO_s_mem());    // I/O

    file = fopen(key_file, "r");
    if (!file)
    {
        printf("ERROR fopen\n");
        return 1;
    }

    // Leemos fichero. file ==> evp_pubkey (EVP_PKEY*)
    evp_pubkey = (EVP_PKEY*) PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if (!evp_pubkey)
    {
        printf("Error leyendo la clave publica\n");
        return 1;
    }

    // Cerramos el fichero
    fclose(file);
    file = NULL;

    // Obtenemos la RSA de la clave. evp_pubkey (EVP_KEY *) ==> rsa_pubkey (RSA *)
    rsa_pubkey  = EVP_PKEY_get1_RSA(evp_pubkey);
    if (!rsa_pubkey)
    {
        printf("F get1_RSA\n");
        return 1;
    }

    /*
    // Imprimir en la terminal los datos de la RSA
    RSA_print(keybio, rsa_pubkey, 0);
    char buffer [1024];
    while (BIO_read (keybio, buffer, 1024) > 0)
    {
        printf("%s", buffer);
    }
    printf("\n");
    */

    // Liberamos la BIO
    BIO_free(keybio);
    keybio = NULL;

    // Guardar en un archivo los datos de la RSA
    file = fopen("coRSAir_clavepublica.txt","w");
    if (!file)
    {
        printf("ERROR fopen\n");
        return 1;
    }
    RSA_print_fp(file, rsa_pubkey, 0);
    fclose(file);
    file = NULL;

    RSA_free(rsa_pubkey);
    rsa_pubkey = NULL;
    EVP_PKEY_free(evp_pubkey);
    evp_pubkey = NULL;
    
    return 0;
}

long long int get_from_file(char *filename, long long int *e)
{
    FILE *f = NULL;
    int i, st = 0;
    char word[1024];
    long long int n = 0, aux = 0;

    f = fopen(filename, "r");
    if (!f)
    {
        printf("ERROR fopen\n");
        return 1;
    }

    for (i = 0; fscanf(f, "%s", word) > 0 && i < 2;)
    {
        if (strcmp(word, "Modulus:") == 0)
        {
            st = fscanf(f, "%lld", &n);
            if (st == 0)
            {
                printf("ERROR leyendo numero\n");
            }
            i += 1;
        }
        else if (strcmp(word, "Exponent:") == 0)
        {
            st = fscanf(f, "%lld", e);
            if (st == 0)
            {
                printf("ERROR leyendo numero\n");
            }
            i += 1;
        }
    }

    printf("n: %lld\ne: %lld\n", n, *e);

    return n;
}

// ------------- DESCRIFRAR MENSAJE ----------------
int leer_privkey()
{
    EVP_PKEY *privkey;
    FILE *fp;
    RSA *rsakey;

    /* ---------------------------------------------------------- *
    * Next function is essential to enable openssl functions     *
    ------------------------------------------------------------ */
    OpenSSL_add_all_algorithms();

    privkey = EVP_PKEY_new();

    fp = fopen ("my_privkey.key", "r");

    PEM_read_PrivateKey(fp, &privkey, NULL, NULL);

    fclose(fp);

    rsakey = EVP_PKEY_get1_RSA(privkey);

    if(RSA_check_key(rsakey)) {
        printf("\nRSA key is valid.\n");
    }
    else {
        printf("Error validating RSA key.\n");
    }

    RSA_print_fp(stdout, rsakey, 3);

    PEM_write_PrivateKey(stdout,privkey,NULL,NULL,0,0,NULL);

    return 0;
}

// ------------- DESCRIFRAR MENSAJE ----------------
int main(int argc, char *argv[])
{
    long long int N,e,d;
    int st = 1; // 0 OK, 1 ERROR

    if (argc < 2)
    {
        printf("SyntaxError. %s <<pubkey.key>>\n", argv[0]);
        return 1;
    }

    st = leer_clave_publica(argv[1]);
    if (st)
    {
        printf("ERROR leer_clave_publica\n");
        return 1;
    }
    else
    {
        printf("Clave pública leida con exito y guardada en 'coRSAir_clavepublica.txt'\n");
    }
    
    N = get_from_file("coRSAir_clavepublica.txt", &e);

    /*
    N = 3764811703;
    e = 1368977731;
    */

    d = ataque_wiener(N,e);
    if (d == 0) printf("El ataque ha fallado\n");
    else printf("El atque ha sido un éxito. La clave es: %lld\n",d);

    leer_privkey();

    return 0;
}