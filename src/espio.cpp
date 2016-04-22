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
    unsigned char iv[0];
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
    ESPIO_INFO info;
};

static ESPIO_HANDLE ESPIO_CALL espio_open( char * key_enc, char * key_dec, unsigned threads )
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

    esp->info.spi_in = esp->spi_in;
    esp->info.spi_out = esp->spi_out;
    esp->info.alignment = 16;
    esp->info.prolog = ESPIO_HDRLEN + esp->iv_len;
    esp->info.epilog = ESPIO_NXPPAD + esp->mac_len;
    esp->info.epilog_max = esp->info.epilog + esp->info.alignment;
    esp->info.fixed = esp->info.prolog + esp->info.epilog;

    return (ESPIO_HANDLE)esp;
}

static ESPIO_CODE ESPIO_CALL espio_encrypt( ESPIO_HANDLE eh, unsigned batch, ESPIO_IOVEC * iovs )
{
    unsigned n;
    ESPIO * esp = (ESPIO *)eh;
    bool isError = false;

    for( n = 0; n < batch; n++ )
    {

        if( iovs[n].prolog_len != esp->info.prolog ||
            iovs[n].epilog_len < esp->info.epilog_max )
        {
            isError = true;
            iovs[n].code = ESPIO_ERROR_PARAM;
            continue;
        }

        unsigned char xorer = esp->xor_out + (unsigned char)iovs[n].seq;

        // PROLOG
        {
            espdata * ed = (espdata *)iovs[n].prolog;

            ed->spi = eh->spi_out;
            ed->seq = htonl( iovs[n].seq );
            memset( &ed->iv[0], xorer, esp->iv_len );
        }

        // PAYLOAD
        {
            unsigned char * buf = (unsigned char *)iovs[n].payload;
            unsigned len = iovs[n].payload_len;
            unsigned i;
            
            for( i = 0; i < len; i++ )
                buf[i] ^= xorer;
        }

        // EPILOG
        {
            unsigned alignment = esp->info.alignment - ( iovs[n].payload_len + ESPIO_NXPPAD ) % esp->info.alignment;
            unsigned char * buf = (unsigned char *)iovs[n].epilog;
            unsigned len = esp->info.epilog + alignment;
            unsigned i;
            
            for( i = 0; i < alignment; i++ )
                buf[i] = (unsigned char)( i + 1 ) ^ xorer;

            buf[i++] = (unsigned char)alignment ^ xorer;
            buf[i++] = iovs[n].proto ^ xorer;

            for( ; i < len; i++ )
                buf[i] = xorer;

            iovs[n].epilog_len = len;
        }

        iovs[n].code = ESPIO_PASS;
    }

    return isError ? ESPIO_ERROR : ESPIO_PASS;
}

static ESPIO_CODE ESPIO_CALL espio_decrypt( ESPIO_HANDLE eh, unsigned batch, ESPIO_IOVEC * iovs )
{
    unsigned n;
    ESPIO * esp = (ESPIO *)eh;
    bool isError = false;

    for( n = 0; n < batch; n++ )
    {
        // LENGTH CHECK
        {
            unsigned len = iovs[n].esp_len;

            if( len < esp->info.fixed ||
                ( len - esp->info.fixed + ESPIO_NXPPAD ) % esp->info.alignment )
            {
                isError = true;
                iovs[n].code = ESPIO_ERROR_LENGTH;
                continue;
            }
        }        

        unsigned char * buf = (unsigned char *)iovs[n].esp;
        unsigned char xorer;

        // SPI CHECK
        {
            espdata * ed = (espdata *)buf;

            if( ed->spi != esp->spi_in )
            {
                isError = true;
                iovs[n].code = ESPIO_ERROR_PARAM;
                continue;
            }

            xorer = esp->xor_in + (unsigned char)ntohl( ed->seq );
        }

        unsigned i = ESPIO_HDRLEN;

        // PROLOG CHECK
        {
            unsigned len = i + esp->iv_len;

            for( ; i < len; i++ )
                if( buf[i] != xorer )
                {
                    isError = true;
                    iovs[n].code = ESPIO_ERROR_DROP;
                    continue;
                }
        }

        // PAYLOAD
        {
            unsigned len = i + iovs[n].esp_len - esp->info.fixed + ESPIO_NXPPAD;

            for( ; i < len; i++ )
                buf[i] ^= xorer;
        }

        // EPILOG CHECK
        {
            unsigned len = i + esp->mac_len;

            for( ; i < len; i++ )
                if( buf[i] != xorer )
                {
                    isError = true;
                    iovs[n].code = ESPIO_ERROR_DROP_MAC;
                    continue;
                }
        }

        // PAYLOAD FIXATE
        {
            i -= esp->mac_len;

            unsigned char proto = buf[--i];
            unsigned char padlen = buf[--i];

            if( padlen > iovs[n].esp_len - esp->info.fixed )
            {
                isError = true;
                iovs[n].code = ESPIO_ERROR_DROP_PROTOCOL;
                continue;
            }

            iovs[n].esp = (unsigned char *)iovs[n].esp + esp->info.prolog;
            iovs[n].esp_len -= esp->info.fixed + padlen;
            iovs[n].proto = proto;
            iovs[n].code = ESPIO_PASS;
        }
    }

    return isError ? ESPIO_ERROR : ESPIO_PASS;
}

static void ESPIO_CALL espio_done( ESPIO_HANDLE eh )
{
    delete (ESPIO *)eh;
}

static void ESPIO_CALL espio_info( ESPIO_HANDLE eh, ESPIO_INFO * info )
{
    memcpy( info, &( (ESPIO *)eh )->info, sizeof( ESPIO_INFO ) );
}

const ESPIO_FRAMEWORK * espio_framework()
{
    static const ESPIO_FRAMEWORK eio = {
        ESPIO_MAJOR,
        ESPIO_MINOR,
        espio_open,
        espio_info,
        espio_encrypt,
        espio_decrypt,
        espio_done,
    };

    return &eio;
}
