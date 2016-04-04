#include <string.h>
#include "espio.h"

#ifdef _WIN32
#pragma warning( disable:4200 ) // nonstandard extension used: zero-sized array in struct/union
#endif

#pragma pack( push, 1 )

struct espdata
{
    unsigned spi;
    unsigned seq;
    unsigned char data[0];
};

#pragma pack( pop )

struct ESPIO
{
    unsigned spi_out;
    unsigned spi_in;
    unsigned char xor_out;
    unsigned char xor_in;
    unsigned iv_len;
    unsigned mac_len;
    unsigned align_len;
};

static ESPIO_HANDLE ESPIO_CALL espio_open( char * key_enc, char * key_dec, int threads )
{
    size_t len;
    size_t i;

    ESPIO * esp = new ESPIO;
    memset( esp, 0, sizeof( ESPIO ) );

    len = strlen( key_enc );
    for( i = 0; i < len; i++ )
    {
        esp->spi_out += ( esp->spi_out << 1 ) + key_enc[i];
        esp->xor_out += ( esp->xor_out << 1 ) + key_enc[i];
    }

    len = strlen( key_dec );
    for( i = 0; i < len; i++ )
    {
        esp->spi_in += ( esp->spi_in << 1 ) + key_dec[i];
        esp->xor_in += ( esp->xor_in << 1 ) + key_dec[i];
    }

    esp->iv_len = 8;
    esp->mac_len = 6;
    (void)threads;

    return (ESPIO_HANDLE)esp;
}

static int ESPIO_CALL espio_encrypt( ESPIO_HANDLE eh, void * data, unsigned len )
{
    unsigned i;
    unsigned char xorer;
    ESPIO * esp = (ESPIO *)eh;
    espdata * ed = (espdata *)data;

    ed->spi = esp->spi_out;
    xorer = esp->xor_out + (unsigned char)ed->seq;

    memset( &ed->data[0], xorer, esp->iv_len );
    len -= sizeof( espdata );
    memset( &ed->data[len - esp->mac_len], xorer, esp->mac_len );

    for( i = 0; i < len; i++ )
        ed->data[i] ^= xorer;

    return 1;
}

static int ESPIO_CALL espio_decrypt( ESPIO_HANDLE eh, void * data, unsigned len )
{
    unsigned i;
    unsigned char xorer;
    ESPIO * esp = (ESPIO *)eh;
    espdata * ed = (espdata *)data;

    if( ed->spi != esp->spi_in )
        return 0;

    xorer = esp->xor_in + (unsigned char)ed->seq;
    len -= sizeof( espdata );

    for( i = 0; i < len; i++ )
        ed->data[i] ^= xorer;

    for( i = 0; i < esp->iv_len; i++ )
        if( ed->data[i] != xorer )
            return 0;

    for( i = len - esp->mac_len; i < len; i++ )
        if( ed->data[i] != xorer )
            return 0;

    return 1;
}

static void ESPIO_CALL espio_done( ESPIO_HANDLE eh )
{
    delete (ESPIO *)eh;
}

ESPIO_FRAMEWORK * ESPIO_CALL espio_framework()
{
    static ESPIO_FRAMEWORK esp;

    esp.espio_major = ESPIO_MAJOR;
    esp.espio_minor = ESPIO_MINOR;

    esp.espio_open = espio_open;
    esp.espio_encrypt = espio_encrypt;
    esp.espio_decrypt = espio_decrypt;
    esp.espio_done = espio_done;

    return &esp;
}
