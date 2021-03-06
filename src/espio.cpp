#include <string.h>
#include <stdint.h>
#include "espio.h"

#ifdef _WIN32
#pragma warning( disable:4200 ) // nonstandard extension used: zero-sized array in struct/union
#endif

#pragma pack( push, 1 )

struct espdata
{
    uint32_t spi;
    uint32_t seq;
    uint8_t iv[0];
};

#pragma pack( pop )

struct ESPIO
{
    uint32_t spi_out;
    uint32_t spi_in;
    uint8_t xor_out;
    uint8_t xor_in;
    uint16_t iv_len;
    uint16_t mac_len;
    uint16_t align_len;
    ESPIO_INFO info;
};

static ESPIO_HANDLE ESPIO_CALL espio_open( char * key_enc, char * key_dec, uint32_t threads )
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

static ESPIO_CODE ESPIO_CALL espio_encrypt( ESPIO_HANDLE eh, uint32_t batch, ESPIO_IOVEC * iovs )
{
    uint32_t n;
    ESPIO * esp = (ESPIO *)eh;
    bool isError = false;

    for( n = 0; n < batch; n++ )
    {
        iovs[n].prolog_len = esp->info.prolog;

        uint8_t xorer = esp->xor_out + (uint8_t)iovs[n].seqnum;

        // PROLOG
        {
            espdata * ed = (espdata *)iovs[n].prolog;

            ed->spi = eh->spi_out;
            ed->seq = htonl( iovs[n].seqnum );
            memset( &ed->iv[0], xorer, esp->iv_len );
        }

        // PAYLOAD
        {
            uint8_t * buf = (uint8_t *)iovs[n].data;
            size_t len = iovs[n].data_len;
            size_t i;
            
            for( i = 0; i < len; i++ ) buf[i] ^= xorer;
        }

        // EPILOG
        {
            uint16_t alignment = esp->info.alignment - ( iovs[n].data_len + ESPIO_NXPPAD ) % esp->info.alignment;
            uint8_t * buf = (uint8_t *)iovs[n].epilog;
            uint16_t len = esp->info.epilog + alignment;
            uint32_t i;
            
            for( i = 0; i < alignment; i++ ) buf[i] = (uint8_t)( i + 1 ) ^ xorer;

            buf[i++] = (uint8_t)alignment ^ xorer;
            buf[i++] = iovs[n].protocol ^ xorer;

            for( ; i < len; i++ ) buf[i] = xorer;

            iovs[n].epilog_len = len;
        }

        iovs[n].code = ESPIO_PASS;
    }

    return isError ? ESPIO_ERROR : ESPIO_PASS;
}

static ESPIO_CODE ESPIO_CALL espio_decrypt( ESPIO_HANDLE eh, uint32_t batch, ESPIO_IOVEC * iovs )
{
    uint32_t n;
    ESPIO * esp = (ESPIO *)eh;
    bool isError = false;

    for( n = 0; n < batch; n++ )
    {
        uint16_t esplen = iovs[n].data_len;

        // LENGTH CHECK
        {
            if( esplen < esp->info.fixed ||
                ( esplen - esp->info.fixed + ESPIO_NXPPAD ) % esp->info.alignment )
            {
                isError = true;
                iovs[n].code = ESPIO_ERROR_LENGTH;
                continue;
            }
        }        

        uint8_t * buf = (uint8_t *)iovs[n].data;
        uint8_t xorer;

        // SPI CHECK
        {
            espdata * ed = (espdata *)buf;

            if( ed->spi != esp->spi_in )
            {
                isError = true;
                iovs[n].code = ESPIO_ERROR_PARAM;
                continue;
            }

            xorer = esp->xor_in + (uint8_t)ntohl( ed->seq );
        }

        uint32_t i = ESPIO_HDRLEN;

        // PROLOG CHECK
        {
            uint32_t len = i + esp->iv_len;

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
            size_t len = i + iovs[n].data_len - esp->info.fixed + ESPIO_NXPPAD;

            for( ; i < len; i++ )
                buf[i] ^= xorer;
        }

        // EPILOG CHECK
        {
            uint32_t len = i + esp->mac_len;

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

            uint8_t proto = buf[--i];
            uint8_t padlen = buf[--i];

            if( padlen > iovs[n].data_len - esp->info.fixed )
            {
                isError = true;
                iovs[n].code = ESPIO_ERROR_DROP_PROTOCOL;
                continue;
            }

            iovs[n].data_dec_shift = esp->info.prolog;
            iovs[n].data_dec_len = esplen - esp->info.fixed - padlen;
            iovs[n].protocol = proto;
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
