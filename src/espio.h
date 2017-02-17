#ifndef ESPIO_H
#define ESPIO_H

#define ESPIO_MAJOR 0
#define ESPIO_MINOR 1

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
#define ESPIO_MAX_PROLOG 16
#define ESPIO_MAX_EPILOG 32

    typedef enum {
        ESPIO_PASS,
        ESPIO_ABSORB,
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
        uint32_t spi_in;
        uint32_t spi_out;
        uint16_t prolog;
        uint16_t epilog;
        uint16_t epilog_max;
        uint16_t alignment;
        uint16_t fixed;
        uint16_t iovs;
    } ESPIO_INFO;

    typedef struct {
        char * data;
        uint8_t prolog[ESPIO_MAX_PROLOG];
        uint8_t epilog[ESPIO_MAX_EPILOG];
        uint16_t data_len;
        uint16_t prolog_len;
        uint16_t epilog_len;
        uint16_t data_dec_shift;
        uint16_t data_dec_len;
        uint32_t seqnum;
        uint8_t protocol;
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
    ESPIO_API const ESPIO_FRAMEWORK * espio_framework();

#ifdef __cplusplus
}
#endif

#ifndef htonl
#ifdef WORDS_BIGENDIAN
#define htonl( x ) ( x )
#else // WORDS_BIGENDIAN
#ifdef _WIN32
#include <stdlib.h>
#define htonl( x ) _byteswap_ulong( x )
#else // not _WIN32
#include <byteswap.h>
#define htonl( x ) bswap_32( x )
#endif // _WIN32
#endif // WORDS_BIGENDIAN
#define ntohl( x ) htonl( x )
#endif

#ifdef ESPIO_WITH_LOADER

#ifdef _WIN32
#define LIBLOAD( name ) LoadLibraryA( name )
#define LIBFUNC( lib, name ) (UINT_PTR)GetProcAddress( lib, name )
#else
#define LIBLOAD( name ) dlopen( name, RTLD_LAZY )
#define LIBFUNC( lib, name ) dlsym( lib, name )
#endif

static const ESPIO_FRAMEWORK * eio;

static char espio_load()
{
    espio_framework_t espio_get_framework;

    void * lib = LIBLOAD( ESPIO_LIBRARY );

    if( !lib )
    {
        printf( "ERROR: \"%s\" not loaded\n", ESPIO_LIBRARY );
        return 0;
    }

    espio_get_framework = (espio_framework_t)LIBFUNC( lib, ESPIO_GET_FRAMEWORK );

    if( !espio_get_framework )
    {
        printf( "ERROR: \"%s\" not found in \"%s\"\n", ESPIO_GET_FRAMEWORK, ESPIO_LIBRARY );
        return 0;
    }

    eio = espio_get_framework();

    if( eio->espio_major != ESPIO_MAJOR )
    {
        printf( "ERROR: espio major version %d.%d != %d.%d\n", eio->espio_major, eio->espio_minor, ESPIO_MAJOR, ESPIO_MINOR );
        return 0;
    }

#if ESPIO_MINOR
    if( eio->espio_minor < ESPIO_MINOR )
    {
        printf( "WARNING: espio minor version %d.%d < %d.%d\n", eio->espio_major, eio->espio_minor, ESPIO_MAJOR, ESPIO_MINOR );
    }
#endif

    printf( "SUCCESS: %s (%d.%d) loaded\n", ESPIO_LIBRARY, eio->espio_major, eio->espio_minor );

    return 1;
}

#endif // ESPIO_WITH_LOADER

#endif // ESPIO_H
