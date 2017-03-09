#include <stdio.h>
#include <stdint.h>

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


static uint32_t SOQUE_CALL push_espio_soque_cb( void * arg, uint32_t batch, uint8_t waitable )
{
    ESPIO_SOQUE_ARG * esa = ( ESPIO_SOQUE_ARG * )arg;
    unsigned n = esa->push;
    unsigned i;

    for( i = 0; i < batch; i++, n++ )
    {
        if( n == esa->size )
            n = 0;

        ESPIO_IOVEC * iov = &esa->iovs[n];
        iov->data_len = (uint16_t)esa->pktlen;
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

static void SOQUE_CALL proc_espio_soque_cb( void * arg, SOQUE_BATCH sb )
{
    ESPIO_SOQUE_ARG * esa = (ESPIO_SOQUE_ARG *)arg;
    ESPIO_IOVEC * iov = &esa->iovs[sb.index];

    if( sb.index + sb.count <= esa->size )
    {
        if( ESPIO_PASS != eio->espio_encrypt( esa->eh, sb.count, iov ) )
        {
            printf( "ERROR: espio_encrypt failed" );
        }
    }
    else
    {
        unsigned first_batch = esa->size - sb.index;

        if( ESPIO_PASS != eio->espio_encrypt( esa->eh, first_batch, iov ) )
        {
            printf( "ERROR: espio_encrypt failed" );
        }

        iov = &esa->iovs[0];

        if( ESPIO_PASS != eio->espio_encrypt( esa->eh, sb.count - first_batch, iov ) )
        {
            printf( "ERROR: espio_encrypt failed" );
        }
    }
}

static uint32_t SOQUE_CALL pop_espio_soque_cb( void * arg, uint32_t batch, uint8_t waitable )
{
    ESPIO_SOQUE_ARG * esa = (ESPIO_SOQUE_ARG *)arg;
    unsigned n = esa->pop;
    unsigned i;

    for( i = 0; i < batch; i++, n++ )
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
static void ** cb_arg;

#ifdef _WIN32
#define SLEEP_1_SEC Sleep( 1000 )
#else
#define SLEEP_1_SEC sleep( 1 )
#endif

#endif // WITH_SOQUE


int main( int argc, char ** argv )
{

#ifdef WITH_SOQUE

    int proctsc = 1400;

    if( !espio_load() )
        return 1;

#define ESPIO_WITH_SOQUE
#include "../../soque/examples/soque_test.c"
#else // WITH_SOQUE

    ESPIO_HANDLE eh[2];
    ESPIO_INFO einfo[2];

    if( !espio_load() )
        return 1;

    eh[0] = eio->espio_open( "output_X", "input_X", 8 );
    eh[1] = eio->espio_open( "input_X", "output_X", 8 );

    eio->espio_info( eh[0], &einfo[0] );
    eio->espio_info( eh[1], &einfo[1] );

    char pkt[256];
    char pktenc[ ESPIO_MAX_PROLOG + sizeof( pkt ) + ESPIO_MAX_EPILOG ];
    uint16_t pkt_enc_shift;

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

    (void)argc;
    (void)argv;

    return 0;

#endif // WITH_SOQUE

}
