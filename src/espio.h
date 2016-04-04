#define ESPIO_MAJOR 1
#define ESPIO_MINOR 0

#ifdef __cplusplus
extern "C" {
#endif

#define ESP_LEN_CORRECTOR_4M ( 8 + 1 + 1 + 4 )
#define ESP_LEN_CORRECTOR_1K ( 8 + 1 + 1 + 4 + 4 )
#define ESP_LEN_HEADER 8
#define ESP_LEN_FULL_HEADER 16

#ifndef htonl
#define htonl(A) \
    ((((unsigned)(A) & 0xff000000) >> 24) | \
    (((unsigned)(A) & 0x00ff0000) >> 8) | \
    (((unsigned)(A) & 0x0000ff00) << 8) | \
    (((unsigned)(A) & 0x000000ff) << 24))
#endif

#ifdef _WIN32
#define ESPIO_API __declspec( dllexport )
#define ESPIO_CALL __fastcall
#define ESPIO_LIBRARY "espio.dll"
#else
#define ESPIO_API __attribute__( ( visibility( "default" ) ) )
#define ESPIO_CALL
#define ESPIO_LIBRARY "libespio.so"
#endif
#define ESPIO_GET_FRAMEWORK "espio_framework"

    typedef struct ESPIO * ESPIO_HANDLE;

    typedef ESPIO_HANDLE ( ESPIO_CALL * espio_open_t )( char * key_enc, char * key_dec, int threads );
    typedef int ( ESPIO_CALL * espio_encrypt_t )( ESPIO_HANDLE eh, void * data, unsigned len );
    typedef int ( ESPIO_CALL * espio_decrypt_t )( ESPIO_HANDLE eh, void * data, unsigned len );
    typedef void ( ESPIO_CALL * espio_done_t )( ESPIO_HANDLE eh );

    typedef struct {
        int espio_major;
        int espio_minor;
        espio_open_t espio_open;
        //espio_info_t espio_info;
        espio_encrypt_t espio_encrypt;
        espio_decrypt_t espio_decrypt;
        espio_done_t espio_done;
    } ESPIO_FRAMEWORK;

    typedef ESPIO_FRAMEWORK * ( ESPIO_CALL * espio_framework_t )( );
    ESPIO_API ESPIO_FRAMEWORK * ESPIO_CALL espio_framework();

#ifdef __cplusplus
}
#endif
