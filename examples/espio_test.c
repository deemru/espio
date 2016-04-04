#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#endif

#include "espio.h"

#ifdef _WIN32
#define SLEEP_1_SEC Sleep( 1000 )
#define LIBLOAD( name ) LoadLibraryA( name )
#define LIBFUNC( lib, name ) (UINT_PTR)GetProcAddress( lib, name )
#else
#define SLEEP_1_SEC sleep( 1 )
#define LIBLOAD( name ) dlopen( name, RTLD_LAZY )
#define LIBFUNC( lib, name ) dlsym( lib, name )
#endif

static const ESPIO_FRAMEWORK * eio;

int espio_load()
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

    if( eio->espio_major < ESPIO_MAJOR )
    {
        printf( "ERROR: espio version %d.%d < %d.%d\n", eio->espio_major, eio->espio_minor, ESPIO_MAJOR, ESPIO_MINOR );
        return 0;
    }

    printf( "%s (%d.%d) loaded\n", ESPIO_LIBRARY, eio->espio_major, eio->espio_minor );

    return 1;
}

int main( /*int argc, char ** argv*/ )
{
    ESPIO_HANDLE eh[2];
    char pkt[256];

    if( !espio_load() )
        return 1;

    eh[0] = eio->espio_open( "output_X", "input_X", 0 );
    eh[1] = eio->espio_open( "input_X", "output_X", 0 );

    memset( pkt, 0, sizeof( pkt ) );

    if( !eio->espio_encrypt( eh[0], pkt, sizeof( pkt ) ) )
    {
        printf( "ERROR: espio_encrypt failed" );
        return 1;
    }

    if( !eio->espio_decrypt( eh[1], pkt, sizeof( pkt ) ) )
    {
        printf( "ERROR: espio_decrypt failed" );
        return 1;
    }

    memset( pkt, 10, sizeof( pkt ) );

    if( !eio->espio_encrypt( eh[0], pkt, sizeof( pkt ) ) )
    {
        printf( "ERROR: espio_encrypt failed" );
        return 1;
    }

    if( !eio->espio_decrypt( eh[1], pkt, sizeof( pkt ) ) )
    {
        printf( "ERROR: espio_decrypt failed" );
        return 1;
    }

    return 0;
}
