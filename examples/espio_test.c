#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#endif

#define ESPIO_WITH_LOADER
#include "espio.h"

#ifdef WITH_SOQUE

#define SOQUE_WITH_LOADER
#include "soque.h"

static volatile long long g_proc_count;

typedef struct
{
    ESPIO_IOVEC * iovs;
    char * pkts;
    unsigned seqnum;
    char is_out;
    unsigned push;
    unsigned pop;
    unsigned size;
    unsigned pktlen;
    ESPIO_HANDLE eh;
} ESPIO_SOQUE_ARG;

char espio_soque_init( ESPIO_SOQUE_ARG * esa, ESPIO_HANDLE eh, unsigned qsize, unsigned pktlen, char is_out )
{
    esa->iovs = malloc( qsize * sizeof( ESPIO_IOVEC ) );
    esa->pkts = malloc( qsize * pktlen );
    esa->seqnum = 0;
    esa->is_out = is_out;
    esa->push = 0;
    esa->pop = 0;
    esa->size = qsize;
    esa->pktlen = pktlen;
    esa->eh = eh;

    {
        unsigned i;

        for( i = 0; i < qsize; i++ )
            esa->iovs[i].data = &esa->pkts[i * pktlen];
    }

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
        iov->data_len = esa->pktlen;
        iov->seqnum = ++esa->seqnum;
        iov->protocol = 97;
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
        memset( iov->data, 0, iov->data_len );
    }

    esa->pop += batch;
    if( esa->pop >= esa->size )
        esa->pop -= esa->size;

    g_proc_count += batch * esa->pktlen * 8;

    (void)waitable;

    return batch;
}

static soque_push_cb push_cb = &push_espio_soque_cb;
static soque_proc_cb proc_cb = &proc_espio_soque_cb;
static soque_pop_cb pop_cb = &pop_espio_soque_cb;

#ifdef _WIN32
#define SLEEP_1_SEC Sleep( 1000 )
#else
#define SLEEP_1_SEC sleep( 1 )
#endif

#endif // WITH_SOQUE

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

    eh[0] = eio->espio_open( "output_X", "input_X", 8 );
    eh[1] = eio->espio_open( "input_X", "output_X", 8 );

    eio->espio_info( eh[0], &einfo[0] );
    eio->espio_info( eh[1], &einfo[1] );

#ifdef WITH_SOQUE

    ESPIO_SOQUE_ARG esa[2];

    espio_soque_init( &esa[0], eh[0], 2048, 1400, 1 );
    espio_soque_init( &esa[1], eh[1], 2048, 1400, 0 );

    {
        SOQUE_HANDLE * q;
        SOQUE_THREADS_HANDLE qt;
        int queue_size = 2048;
        int queue_count = 1;
        int threads_count = 1;
        char bind = 1;
        unsigned fast_batch = 32;
        unsigned help_batch = 32;

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
        soq->soque_threads_tune( qt, fast_batch, help_batch, 1, 50 );

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
    char pktenc[ ESPIO_MAX_PROLOG + sizeof( pkt ) + ESPIO_MAX_EPILOG ];
    unsigned pkt_enc_shift;

    ESPIO_IOVEC iov;

    // A >> B
    {
        iov.data = pkt;
        iov.data_len = sizeof( pkt );
        iov.protocol = 17;
        iov.seqnum = 1;

        memset( pkt, 0, sizeof( pkt ) );

        if( ESPIO_PASS != eio->espio_encrypt( eh[0], 1, &iov ) )
        {
            printf( "ERROR: espio_encrypt failed" );
            return 1;
        }

        memcpy( pktenc, iov.prolog, iov.prolog_len );
        pkt_enc_shift = iov.prolog_len;

        memcpy( pktenc + pkt_enc_shift, iov.data, iov.data_len );
        pkt_enc_shift += iov.data_len;

        memcpy( pktenc + pkt_enc_shift, iov.epilog, iov.epilog_len );
        pkt_enc_shift += iov.epilog_len;

        iov.data = pktenc;
        iov.data_len = pkt_enc_shift;

        if( ESPIO_PASS != eio->espio_decrypt( eh[1], 1, &iov ) )
        {
            printf( "ERROR: espio_decrypt failed" );
            return 1;
        }
    }

    // B >> A
    {
        iov.data = pkt;
        iov.data_len = sizeof( pkt );
        iov.protocol = 17;
        iov.seqnum = 1;

        memset( pkt, 0, sizeof( pkt ) );

        if( ESPIO_PASS != eio->espio_encrypt( eh[1], 1, &iov ) )
        {
            printf( "ERROR: espio_encrypt failed" );
            return 1;
        }

        memcpy( pktenc, iov.prolog, iov.prolog_len );
        pkt_enc_shift = iov.prolog_len;

        memcpy( pktenc + pkt_enc_shift, iov.data, iov.data_len );
        pkt_enc_shift += iov.data_len;

        memcpy( pktenc + pkt_enc_shift, iov.epilog, iov.epilog_len );
        pkt_enc_shift += iov.epilog_len;

        iov.data = pktenc;
        iov.data_len = pkt_enc_shift;

        if( ESPIO_PASS != eio->espio_decrypt( eh[0], 1, &iov ) )
        {
            printf( "ERROR: espio_decrypt failed" );
            return 1;
        }
    }

    return 0;

#endif // WITH_SOQUE

}
