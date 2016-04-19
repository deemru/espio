#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#endif

#include "espio.h"

#ifdef WITH_SOQUE
#include "soque.h"
#endif

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

#ifdef WITH_SOQUE

static SOQUE_FRAMEWORK * soq;

int soque_load()
{
    soque_framework_t soque_get_framework;

    void * lib = LIBLOAD( SOQUE_LIBRARY );

    if( !lib )
    {
        printf( "ERROR: \"%s\" not loaded\n", SOQUE_LIBRARY );
        return 0;
    }

    soque_get_framework = (soque_framework_t)LIBFUNC( lib, SOQUE_GET_FRAMEWORK );

    if( !soque_get_framework )
    {
        printf( "ERROR: \"%s\" not found in \"%s\"\n", SOQUE_GET_FRAMEWORK, SOQUE_LIBRARY );
        return 0;
    }

    soq = soque_get_framework();

    if( soq->soque_major < SOQUE_MAJOR )
    {
        printf( "ERROR: soque version %d.%d < %d.%d\n", soq->soque_major, soq->soque_minor, SOQUE_MAJOR, SOQUE_MINOR );
        return 0;
    }

    printf( "%s (%d.%d) loaded\n", SOQUE_LIBRARY, soq->soque_major, soq->soque_minor );

    return 1;
}

static volatile long long g_proc_count;

typedef struct
{
    void * prologs;
    unsigned prologs_len;
    void * payloads;
    unsigned payloads_len;
    void * epilogs;
    unsigned epilogs_len;
    void * esps;
    unsigned esps_len;
    ESPIO_IOVEC * iovs;
    unsigned seq;
    char is_out;
    unsigned push;
    unsigned pop;
    unsigned size;
    ESPIO_HANDLE eh;
} ESPIO_SOQUE_ARG;

char espio_soque_init( ESPIO_SOQUE_ARG * esa, ESPIO_HANDLE eh, unsigned qsize, unsigned pktlen, ESPIO_INFO * info, char is_out )
{
    if( is_out )
    {
        esa->prologs = malloc( qsize * info->prolog );
        esa->payloads = malloc( qsize * pktlen );
        esa->epilogs = malloc( qsize * info->epilog_max );
        esa->esps = NULL;
        esa->prologs_len = info->prolog;
        esa->payloads_len = pktlen;
        esa->epilogs_len = info->epilog_max;
        esa->esps_len = 0;
    }
    else
    {
        esa->prologs = NULL;
        esa->payloads = NULL;
        esa->epilogs = NULL;
        esa->esps = malloc( qsize * ( pktlen + info->prolog + info->epilog_max ) );
        esa->prologs_len = 0;
        esa->payloads_len = 0;
        esa->epilogs_len = 0;
        esa->esps_len = pktlen + info->prolog + info->epilog_max;
    }
    esa->iovs = malloc( qsize * sizeof( ESPIO_IOVEC ) );
    esa->seq = 0;
    esa->is_out = is_out;
    esa->push = 0;
    esa->pop = 0;
    esa->size = qsize;
    esa->eh = eh;

    return 1;
}

static int SOQUE_CALL push_espio_soque_cb( void * arg, unsigned batch, char waitable )
{
    ESPIO_SOQUE_ARG * esa = ( ESPIO_SOQUE_ARG * )arg;
    unsigned n = esa->push;

    for( unsigned i = 0; i < batch; i++, n++ )
    {
        if( n == esa->size )
            n = 0;

        ESPIO_IOVEC * iov = &esa->iovs[n];
        iov->prolog = (char *)esa->prologs + n * esa->prologs_len;
        iov->prolog_len = esa->prologs_len;
        iov->payload = (char *)esa->payloads + n * esa->payloads_len;
        iov->payload_len = esa->payloads_len;
        iov->epilog = (char *)esa->epilogs + n * esa->epilogs_len;
        iov->epilog_len = esa->epilogs_len;
        iov->seq = ++esa->seq;
        iov->proto = 97;
        iov->esp = NULL;
        iov->esp_len = 0;
        iov->code = -1;
    }

    esa->push += batch;
    if( esa->push >= esa->size )
        esa->push -= esa->size;

    (void)waitable;

    return batch;
}

static void SOQUE_CALL proc_espio_soque_cb( void * arg, unsigned batch, unsigned index )
{
    ESPIO_SOQUE_ARG * esa = (ESPIO_SOQUE_ARG *)arg;
    ESPIO_IOVEC * iov = &esa->iovs[index];

    if( index + batch <= esa->size )
    {
        if( ESPIO_PASS != eio->espio_encrypt( esa->eh, batch, iov ) )
        {
            printf( "ERROR: espio_encrypt failed" );
        }
    }
    else
    {
        unsigned first_batch = esa->size - index;

        if( ESPIO_PASS != eio->espio_encrypt( esa->eh, first_batch, iov ) )
        {
            printf( "ERROR: espio_encrypt failed" );
        }

        iov = &esa->iovs[0];

        if( ESPIO_PASS != eio->espio_encrypt( esa->eh, batch - first_batch, iov ) )
        {
            printf( "ERROR: espio_encrypt failed" );
        }
    }
}

static int SOQUE_CALL pop_espio_soque_cb( void * arg, unsigned batch, char waitable )
{
    ESPIO_SOQUE_ARG * esa = (ESPIO_SOQUE_ARG *)arg;
    unsigned n = esa->pop;

    for( unsigned i = 0; i < batch; i++, n++ )
    {
        if( n == esa->size )
            n = 0;

        ESPIO_IOVEC * iov = &esa->iovs[n];
        memset( iov, 0, sizeof( ESPIO_IOVEC ) );
    }

    esa->pop += batch;
    if( esa->pop >= esa->size )
        esa->pop -= esa->size;

    g_proc_count += batch * esa->payloads_len * 8;

    (void)waitable;

    return batch;
}

static soque_push_cb push_cb = &push_espio_soque_cb;
static soque_proc_cb proc_cb = &proc_espio_soque_cb;
static soque_pop_cb pop_cb = &pop_espio_soque_cb;

#endif

#ifdef WITH_SOQUE
int main( int argc, char ** argv )
#else
int main()
#endif
{
    ESPIO_HANDLE eh[2];
    ESPIO_INFO einfo[2];

    if( !espio_load() )
        return 1;

    eh[0] = eio->espio_open( "output_X", "input_X", 0 );
    eh[1] = eio->espio_open( "input_X", "output_X", 0 );

    eio->espio_info( eh[0], &einfo[0] );
    eio->espio_info( eh[1], &einfo[1] );

#ifdef WITH_SOQUE

    ESPIO_SOQUE_ARG esa[2];

    espio_soque_init( &esa[0], eh[0], 2048, 1400, &einfo[0], 1 );
    espio_soque_init( &esa[1], eh[1], 2048, 1400, &einfo[1], 0 );

    {
        SOQUE_HANDLE * q;
        SOQUE_THREADS_HANDLE qt;
        int queue_size = 2048;
        int queue_count = 1;
        int threads_count = 4;
        char bind = 1;
        unsigned fast_batch = 64;
        unsigned help_batch = 64;

        long long speed_save;
        double speed_change;
        double speed_approx_change;
        double speed_moment = 0;
        double speed_approx = 0;
        int n = 0;
        int i;

        if( argc > 1 )
            queue_size = atoi( argv[1] );
        if( argc > 2 )
            queue_count = atoi( argv[2] );
        if( argc > 3 )
            threads_count = atoi( argv[3] );
        if( argc > 4 )
            bind = (char)atoi( argv[4] );
        if( argc > 5 )
            fast_batch = atoi( argv[5] );
        if( argc > 6 )
            help_batch = atoi( argv[6] );

        if( !soque_load() )
            return 1;

        printf( "queue_size = %d\n", queue_size );
        printf( "queue_count = %d\n", queue_count );
        printf( "threads_count = %d\n", threads_count );
        printf( "bind = %d\n", bind );
        printf( "fast_batch = %d\n", fast_batch );
        printf( "help_batch = %d\n\n", help_batch );

        q = malloc( queue_count * sizeof( void * ) );

        for( i = 0; i < queue_count; i++ )
            q[i] = soq->soque_open( queue_size, &esa[i], push_cb, proc_cb, pop_cb );

        qt = soq->soque_threads_open( threads_count, bind, q, queue_count );
        soq->soque_threads_tune( qt, fast_batch, help_batch );

        SLEEP_1_SEC; // warming

        for( ;; )
        {
            speed_save = g_proc_count;
            SLEEP_1_SEC;
            speed_change = speed_moment;
            speed_approx_change = speed_approx;
            speed_moment = (double)( g_proc_count - speed_save );
            speed_approx = ( speed_approx * n + speed_moment ) / ( n + 1 );
            printf( "Gbps:   %.03f (%s%0.03f)   ~   %.03f (%s%0.03f)\n",
                speed_moment / 1000000000,
                speed_change <= speed_moment ? "+" : "",
                ( speed_moment - speed_change ) / 1000000000,
                speed_approx / 1000000000,
                speed_approx_change <= speed_approx ? "+" : "",
                ( speed_approx - speed_approx_change ) / 1000000000 );
            n++;
        }
    }

#else // WITH_SOQUE

    char pkt[256];

    memset( pkt, 0, sizeof( pkt ) );

    ESPIO_IOVEC iov;
    unsigned seq = 0;

    iov.prolog = &pkt[0];
    iov.prolog_len = einfo[0].prolog;
    iov.payload = &pkt[iov.prolog_len];
    iov.payload_len = 200;
    iov.epilog = &pkt[iov.prolog_len + iov.payload_len];
    iov.epilog_len = einfo[0].epilog_max;
    iov.proto = 17;
    iov.seq = ++seq;

    if( ESPIO_PASS != eio->espio_encrypt( eh[0], 1, &iov ) )
    {
        printf( "ERROR: espio_encrypt failed" );
        return 1;
    }

    iov.esp = iov.prolog;
    iov.esp_len = iov.prolog_len + iov.payload_len + iov.epilog_len;

    if( ESPIO_PASS != eio->espio_decrypt( eh[1], 1, &iov ) )
    {
        printf( "ERROR: espio_decrypt failed" );
        return 1;
    }

    iov.prolog = &pkt[0];
    iov.prolog_len = einfo[0].prolog;
    iov.payload = &pkt[iov.prolog_len];
    iov.payload_len = 0;
    iov.epilog = &pkt[iov.prolog_len + iov.payload_len];
    iov.epilog_len = einfo[0].epilog_max;
    iov.seq = ++seq;

    if( ESPIO_PASS != eio->espio_encrypt( eh[0], 1, &iov ) )
    {
        printf( "ERROR: espio_encrypt failed" );
        return 1;
    }

    iov.esp = iov.prolog;
    iov.esp_len = iov.prolog_len + iov.payload_len + iov.epilog_len;

    if( ESPIO_PASS != eio->espio_decrypt( eh[1], 1, &iov ) )
    {
        printf( "ERROR: espio_decrypt failed" );
        return 1;
    }

    return 0;

#endif // WITH_SOQUE

}
