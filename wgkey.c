// SPDX-License-Identifier: 0BSD

// TweetNaCL is in the public domain
// clang-format off
// begin TweetNaCL

#define FOR(i,n) for (i = 0;i < n;++i)
#define sv static void

typedef unsigned char u8;
typedef long long i64;
typedef i64 gf[16];

static const u8
  _9[32] = {9};
static const gf
  _121665 = {0xDB41,1};

sv car25519(gf o)
{
  int i;
  i64 c;
  FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

sv sel25519(gf p,gf q,int b)
{
  i64 t,i,c=~(b-1);
  FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

sv pack25519(u8 *o,const gf n)
{
  int i,j,b;
  gf m,t;
  FOR(i,16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

sv unpack25519(gf o, const u8 *n)
{
  int i;
  FOR(i,16) o[i]=n[2*i]+((i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

sv A(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]+b[i];
}

sv Z(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]-b[i];
}

sv M(gf o,const gf a,const gf b)
{
  i64 i,j,t[31];
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

sv S(gf o,const gf a)
{
  M(o,a,a);
}

sv inv25519(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

static int crypto_scalarmult(u8 *q,const u8 *n,const u8 *p)
{
  u8 z[32];
  i64 x[80],r,i;
  gf a,b,c,d,e,f;
  FOR(i,31) z[i]=n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  FOR(i,16) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for(i=254;i>=0;--i) {
    r=(z[i>>3]>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  FOR(i,16) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  inv25519(x+32,x+32);
  M(x+16,x+16,x+32);
  pack25519(q,x+16);
  return 0;
}

static int crypto_scalarmult_base(u8 *q,const u8 *n)
{
  return crypto_scalarmult(q,n,_9);
}

// end TweetNaCL
// clang-format on

// C99, except _Static_assert is C11

#if __APPLE__
// for memset_s
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if __linux__
#include <sys/random.h>
#endif

static void randombytes(void *b, size_t n) {
#if __linux__
  if (getrandom(b, n, 0) != n) {
    abort();
  }
#elif __APPLE__
  arc4random_buf(b, n);
#else
#error "unsupported platform"
#endif
}

enum { CURVE25519_KEY_SIZE = 32 };

static void generate_wg_keys(uint8_t public[static CURVE25519_KEY_SIZE],
                             uint8_t private[static CURVE25519_KEY_SIZE]) {
  randombytes(private, CURVE25519_KEY_SIZE);
  private[31] = (private[31] & 127) | 64;
  private[0] &= 248;
  (void)crypto_scalarmult_base(public, private);
}

// Encode a base64 quantum in constant time.
static void base64_encode_quantum(char enc[static 4],
                                  uint8_t const data[static 3]) {
  // Concatenate 3 8-bit input groups into 4 6-bit output groups.
  uint8_t const out[4] = {
      (data[0] >> 2) & 0x3F, ((data[0] << 4) | (data[1] >> 4)) & 0x3F,
      ((data[1] << 2) | (data[2] >> 6)) & 0x3F, data[2] & 0x3F};

  // Encode each output group.
  for (unsigned int i = 0; i < 4; ++i) {
    _Static_assert((-1) >> 8 == -1, "expected arithmetic right shift");
    enc[i] =
        // start at 'A'
        out[i] +
        'A'
        // if out >= 26, add 6 (skip from 'Z' to 'a')
        + (((25 - out[i]) >> 8) & 6)
        // if out >= 52, subtract 75 (skip from 'z' to '0')
        - (((51 - out[i]) >> 8) & 75)
        // if out >= 62, sutract 15 (skip from '9' to '+')
        - (((61 - out[i]) >> 8) & 15)
        // if out >= 63, add 3 (skip from '+' to '/')
        + (((62 - out[i]) >> 8) & 3);
  }
}

// RFC 4648 base64 encoding
static ssize_t base64_encode(char *base64_buf, size_t base64_buflen,
                             uint8_t const *data, size_t data_buflen) {
  size_t actual_encoded_data_len = 4 * ((data_buflen + 2) / 3);
  if (actual_encoded_data_len > base64_buflen) {
    return -1;
  }

  uint8_t const *in = data;
  char *out = base64_buf;
  uint8_t const *end = data + data_buflen;

  while (end - in >= 3) {
    base64_encode_quantum(out, in);
    out += 4;
    in += 3;
  }
  if (end - in == 1) {
    base64_encode_quantum(out, (uint8_t const[]){in[0], 0, 0});
    out[2] = '=';
    out[3] = '=';
  } else if (end - in == 2) {
    base64_encode_quantum(out, (uint8_t const[]){in[0], in[1], 0});
    out[3] = '=';
  }

  return actual_encoded_data_len;
}

enum { WG_KEY_LEN_BASE64 = 45 };

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "usage: wgkey private public\n");
    return 1;
  }
  FILE *private_fp = fopen(argv[1], "w");
  FILE *public_fp = fopen(argv[2], "w");
  if (private_fp == NULL || public_fp == NULL) {
    return 1;
  }
  uint8_t private[CURVE25519_KEY_SIZE];
  uint8_t public[CURVE25519_KEY_SIZE];
  generate_wg_keys(public, private);
  char private_b64[WG_KEY_LEN_BASE64];
  char public_b64[WG_KEY_LEN_BASE64];
  (void)base64_encode(private_b64, WG_KEY_LEN_BASE64, private,
                      CURVE25519_KEY_SIZE);
  (void)base64_encode(public_b64, WG_KEY_LEN_BASE64, public,
                      CURVE25519_KEY_SIZE);
  private_b64[WG_KEY_LEN_BASE64 - 1] = '\n';
  public_b64[WG_KEY_LEN_BASE64 - 1] = '\n';
  if (fwrite(private_b64, WG_KEY_LEN_BASE64, 1, private_fp) != 1) {
    return 1;
  }
  fclose(private_fp);
  if (fwrite(public_b64, WG_KEY_LEN_BASE64, 1, public_fp) != 1) {
    return 1;
  }
  fclose(public_fp);
  return 0;
}
