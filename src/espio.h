#define ESPIO_MAJOR 1
#define ESPIO_MINOR 0

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define ESPIO_API __declspec( dllexport )
#define ESPIO_CALL __fastcall
#ifdef _M_IX86
#define ESPIO_LIBRARY "espio.dll"
#else // _M_IX86
#define ESPIO_LIBRARY "espio64.dll"
#endif // _M_IX86
#else
#define ESPIO_API __attribute__( ( visibility( "default" ) ) )
#define ESPIO_CALL
#define ESPIO_LIBRARY "libespio.so"
#endif
#define ESPIO_GET_FRAMEWORK "espio_framework"

#define ESPIO_HDRLEN 8
#define ESPIO_NXPPAD 2

    typedef enum {
        ESPIO_PASS,
        ESPIO_ERROR,
        ESPIO_ERROR_PARAM,
        ESPIO_ERROR_LENGTH,
        ESPIO_ERROR_MEMORY,
        ESPIO_ERROR_EXPIRED,
        ESPIO_ERROR_DROP,
        ESPIO_ERROR_DROP_MAC,
        ESPIO_ERROR_DROP_PROTOCOL,
        ESPIO_ERROR_FATAL
    } ESPIO_CODE;

    typedef struct {
        unsigned spi_in;
        unsigned spi_out;
        unsigned prolog;
        unsigned epilog;
        unsigned epilog_max;
        unsigned alignment;
        unsigned fixed;
        unsigned iovs;
    } ESPIO_INFO;

    typedef struct {
        void * esp;
        size_t esp_len;
        void * prolog;
        size_t prolog_len;
        void * payload;
        size_t payload_len;
        void * epilog;
        size_t epilog_len;
        unsigned seq;
        unsigned char proto;
        ESPIO_CODE code;
    } ESPIO_IOVEC;

#define ESPIO_LEN( paylen, info ) ( (info)->alignment == 1 ? \
        ( paylen + (info)->fixed ) : \
        ( paylen + (info)->fixed + ( (info)->alignment - ( paylen + ESPIO_NXPPAD ) % (info)->alignment ) % (info)->alignment ) )

    typedef struct ESPIO * ESPIO_HANDLE;

    typedef ESPIO_HANDLE( ESPIO_CALL * espio_open_t )( char * key_enc, char * key_dec, unsigned threads );
    typedef void ( ESPIO_CALL * espio_info_t )( ESPIO_HANDLE eh, ESPIO_INFO * );
    typedef ESPIO_CODE( ESPIO_CALL * espio_encrypt_t )( ESPIO_HANDLE eh, unsigned batch, ESPIO_IOVEC * iovs );
    typedef ESPIO_CODE( ESPIO_CALL * espio_decrypt_t )( ESPIO_HANDLE eh, unsigned batch, ESPIO_IOVEC * iovs );
    typedef void ( ESPIO_CALL * espio_done_t )( ESPIO_HANDLE eh );

    typedef struct {
        unsigned espio_major;
        unsigned espio_minor;
        espio_open_t espio_open;
        espio_info_t espio_info;
        espio_encrypt_t espio_encrypt;
        espio_decrypt_t espio_decrypt;
        espio_done_t espio_done;
    } ESPIO_FRAMEWORK;

    typedef ESPIO_FRAMEWORK * ( *espio_framework_t )( );
    ESPIO_API ESPIO_FRAMEWORK * espio_framework();

#ifdef __cplusplus
}
#endif

#ifndef htonl
#ifdef WORDS_BIGENDIAN
#define htonl(A) (A)
#else
#define htonl(A) ( \
    ( ( (unsigned)(A) & 0xff000000 ) >> 24 ) | \
    ( ( (unsigned)(A) & 0x00ff0000 ) >> 8 )  | \
    ( ( (unsigned)(A) & 0x0000ff00 ) << 8 )  | \
    ( ( (unsigned)(A) & 0x000000ff ) << 24 ) )
#endif
#endif

#ifndef ntohl
#define ntohl(A) htonl(A)
#endif
