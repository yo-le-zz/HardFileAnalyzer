/*
 * ============================================================
 *  HARD FILE ANALYZER — core.cpp
 *  C++ Performance Core — compile en DLL Windows
 *
 *  Build (MSVC):
 *    cl /LD /O2 /MT /EHsc core.cpp /Fe:core.dll
 *    (optionnel: /arch:AVX2 pour boost SIMD)
 *
 *  Build (MinGW / g++):
 *    g++ -O3 -shared -std=c++17 -o core.dll core.cpp
 *    -pthread -lstdc++ -lm -static-libgcc -static-libstdc++
 *
 *  Python: ctypes.CDLL("core.dll")
 * ============================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* ── Thread support ──────────────────────────────────────── */
#include <process.h>   /* _beginthreadex */

#define EXPORT extern "C" __declspec(dllexport)
#define MAX_STRINGS     8192
#define MAX_STRING_LEN  512
#define CHUNK_SIZE      65536   /* entropy chunk: 64 KB */
#define THREAD_COUNT    8       /* parallélisme entropy/strings */


/* ════════════════════════════════════════════════════════════
 *  MD5
 * ════════════════════════════════════════════════════════════ */
typedef struct { uint32_t s[4]; uint8_t buf[64]; uint64_t bytes; } MD5_CTX2;

static const uint32_t MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,
    0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,
    0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,
    0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,
    0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
    0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
    0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
};
static const uint32_t MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
};
#define ROL32(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void md5_process(uint32_t s[4], const uint8_t* blk) {
    uint32_t a=s[0],b=s[1],c=s[2],d=s[3],m[16],F,g,tmp;
    for(int i=0;i<16;i++) m[i]=((uint32_t)blk[i*4])|(blk[i*4+1]<<8)|(blk[i*4+2]<<16)|(blk[i*4+3]<<24);
    for(int i=0;i<64;i++){
        if(i<16){F=(b&c)|(~b&d);g=i;}
        else if(i<32){F=(d&b)|(~d&c);g=(5*i+1)%16;}
        else if(i<48){F=b^c^d;g=(3*i+5)%16;}
        else{F=c^(b|~d);g=(7*i)%16;}
        tmp=d;d=c;c=b;b=b+ROL32(a+F+MD5_K[i]+m[g],MD5_S[i]);a=tmp;
    }
    s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=d;
}

EXPORT void md5(const uint8_t* data, size_t len, char* out_hex) {
    uint32_t s[4]={0x67452301,0xefcdab89,0x98badcfe,0x10325476};
    uint8_t buf[64]; size_t i=0,l=len;
    for(;i+64<=len;i+=64) md5_process(s,(uint8_t*)data+i);
    size_t rem=len-i;
    memcpy(buf,data+i,rem);
    buf[rem]=0x80;
    if(rem<56){memset(buf+rem+1,0,55-rem);}
    else{memset(buf+rem+1,0,63-rem);md5_process(s,buf);memset(buf,0,56);}
    uint64_t bits=(uint64_t)l*8;
    for(int j=0;j<8;j++) buf[56+j]=(bits>>(j*8))&0xff;
    md5_process(s,buf);
    sprintf(out_hex,"%08x%08x%08x%08x",
        ((s[0]>>24)&0xff)|((s[0]>>8)&0xff00)|((s[0]&0xff00)<<8)|((s[0]&0xff)<<24),
        ((s[1]>>24)&0xff)|((s[1]>>8)&0xff00)|((s[1]&0xff00)<<8)|((s[1]&0xff)<<24),
        ((s[2]>>24)&0xff)|((s[2]>>8)&0xff00)|((s[2]&0xff00)<<8)|((s[2]&0xff)<<24),
        ((s[3]>>24)&0xff)|((s[3]>>8)&0xff00)|((s[3]&0xff00)<<8)|((s[3]&0xff)<<24));
}


/* ════════════════════════════════════════════════════════════
 *  SHA-1
 * ════════════════════════════════════════════════════════════ */
#define ROL1(x,n) (((x)<<(n))|((x)>>(32-(n))))
EXPORT void sha1(const uint8_t* d, size_t len, char* hex) {
    uint32_t h[5]={0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
    uint8_t buf[128]; size_t i=0;
    for(;i+64<=len;i+=64){
        uint32_t w[80],a,b,c,dd,e,f,k,tmp;
        for(int j=0;j<16;j++) w[j]=(d[i+j*4]<<24)|(d[i+j*4+1]<<16)|(d[i+j*4+2]<<8)|d[i+j*4+3];
        for(int j=16;j<80;j++) w[j]=ROL1(w[j-3]^w[j-8]^w[j-14]^w[j-16],1);
        a=h[0];b=h[1];c=h[2];dd=h[3];e=h[4];
        for(int j=0;j<80;j++){
            if(j<20){f=(b&c)|(~b&dd);k=0x5a827999;}
            else if(j<40){f=b^c^dd;k=0x6ed9eba1;}
            else if(j<60){f=(b&c)|(b&dd)|(c&dd);k=0x8f1bbcdc;}
            else{f=b^c^dd;k=0xca62c1d6;}
            tmp=ROL1(a,5)+f+e+k+w[j];e=dd;dd=c;c=ROL1(b,30);b=a;a=tmp;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=dd;h[4]+=e;
    }
    size_t rem=len-i;
    memcpy(buf,d+i,rem);
    buf[rem]=0x80;
    if(rem<56){memset(buf+rem+1,0,55-rem);}
    else{memset(buf+rem+1,0,63-rem);}
    uint64_t bits=(uint64_t)len*8;
    for(int j=0;j<8;j++) buf[56+j]=(bits>>(56-j*8))&0xff;
    /* process last block */
    uint32_t w[80],a,b,c,dd,e,f,k,tmp;
    for(int j=0;j<16;j++) w[j]=(buf[j*4]<<24)|(buf[j*4+1]<<16)|(buf[j*4+2]<<8)|buf[j*4+3];
    for(int j=16;j<80;j++) w[j]=ROL1(w[j-3]^w[j-8]^w[j-14]^w[j-16],1);
    a=h[0];b=h[1];c=h[2];dd=h[3];e=h[4];
    for(int j=0;j<80;j++){
        if(j<20){f=(b&c)|(~b&dd);k=0x5a827999;}
        else if(j<40){f=b^c^dd;k=0x6ed9eba1;}
        else if(j<60){f=(b&c)|(b&dd)|(c&dd);k=0x8f1bbcdc;}
        else{f=b^c^dd;k=0xca62c1d6;}
        tmp=ROL1(a,5)+f+e+k+w[j];e=dd;dd=c;c=ROL1(b,30);b=a;a=tmp;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=dd;h[4]+=e;
    sprintf(hex,"%08x%08x%08x%08x%08x",h[0],h[1],h[2],h[3],h[4]);
}


/* ════════════════════════════════════════════════════════════
 *  SHA-256
 * ════════════════════════════════════════════════════════════ */
static const uint32_t K256[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) ((x&y)^(~x&z))
#define MAJ(x,y,z) ((x&y)^(x&z)^(y&z))
#define S0(x) (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define S1(x) (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define G0(x) (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define G1(x) (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_block(uint32_t h[8], const uint8_t* blk) {
    uint32_t w[64],a,b,c,d,e,f,g,hh,T1,T2;
    for(int i=0;i<16;i++) w[i]=(blk[i*4]<<24)|(blk[i*4+1]<<16)|(blk[i*4+2]<<8)|blk[i*4+3];
    for(int i=16;i<64;i++) w[i]=G1(w[i-2])+w[i-7]+G0(w[i-15])+w[i-16];
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for(int i=0;i<64;i++){
        T1=hh+S1(e)+CH(e,f,g)+K256[i]+w[i];
        T2=S0(a)+MAJ(a,b,c);
        hh=g;g=f;f=e;e=d+T1;d=c;c=b;b=a;a=T1+T2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

EXPORT void sha256(const uint8_t* data, size_t len, char* hex) {
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t i=0;
    for(;i+64<=len;i+=64) sha256_block(h,(uint8_t*)data+i);
    uint8_t buf[128]; size_t rem=len-i;
    memcpy(buf,data+i,rem);
    buf[rem]=0x80;
    if(rem<56) memset(buf+rem+1,0,55-rem);
    else{ memset(buf+rem+1,0,63-rem);sha256_block(h,buf);memset(buf,0,56);}
    uint64_t bits=(uint64_t)len*8;
    for(int j=0;j<8;j++) buf[56+j]=(bits>>(56-j*8))&0xff;
    sha256_block(h,buf);
    sprintf(hex,"%08x%08x%08x%08x%08x%08x%08x%08x",
            h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
}


/* ════════════════════════════════════════════════════════════
 *  SHANNON ENTROPY — Multithreadé
 * ════════════════════════════════════════════════════════════ */
struct EntropyChunk {
    const uint8_t* data;
    size_t         len;
    double         result;
};

static unsigned __stdcall entropy_thread(void* arg) {
    EntropyChunk* c = (EntropyChunk*)arg;
    uint64_t freq[256] = {};
    for(size_t i=0;i<c->len;i++) freq[c->data[i]]++;
    double e=0.0;
    for(int i=0;i<256;i++){
        if(freq[i]){
            double p=(double)freq[i]/c->len;
            e -= p * log2(p);
        }
    }
    c->result = e;
    return 0;
}

/* Returns overall entropy × 10000 as integer (e.g. 72345 = 7.2345) */
EXPORT int32_t entropy_mt(const uint8_t* data, size_t len) {
    if(len == 0) return 0;
    if(len <= CHUNK_SIZE){
        EntropyChunk c={data,len,0.0};
        entropy_thread(&c);
        return (int32_t)(c.result * 10000);
    }
    /* Split into THREAD_COUNT chunks */
    int n = THREAD_COUNT;
    EntropyChunk chunks[THREAD_COUNT];
    HANDLE threads[THREAD_COUNT];
    size_t chunk = len / n;
    for(int i=0;i<n;i++){
        chunks[i].data = data + i*chunk;
        chunks[i].len  = (i==n-1) ? len - i*chunk : chunk;
        chunks[i].result = 0.0;
        threads[i] = (HANDLE)_beginthreadex(NULL,0,entropy_thread,&chunks[i],0,NULL);
    }
    WaitForMultipleObjects(n,(const HANDLE*)threads,TRUE,INFINITE);
    for(int i=0;i<n;i++) CloseHandle(threads[i]);
    /* Weighted average */
    double total=0.0;
    for(int i=0;i<n;i++) total += chunks[i].result * (chunks[i].len/(double)len);
    return (int32_t)(total * 10000);
}

/* Per-region entropy scan: writes up to max_regions offsets+entropies (int32 pairs) */
EXPORT int32_t entropy_regions(const uint8_t* data, size_t len,
                                int32_t* offsets, int32_t* entropies,
                                int32_t max_regions) {
    int found=0;
    size_t step = CHUNK_SIZE;
    for(size_t i=0;i+step<=len && found<max_regions;i+=step){
        EntropyChunk c={data+i,step,0.0};
        entropy_thread(&c);
        if(c.result > 7.0){
            offsets[found]   = (int32_t)i;
            entropies[found] = (int32_t)(c.result*10000);
            found++;
        }
    }
    return found;
}


/* ════════════════════════════════════════════════════════════
 *  FAST STRING EXTRACTION
 * ════════════════════════════════════════════════════════════ */
struct StrChunk {
    const uint8_t* data;
    size_t  start, end;
    char*   out;        /* pre-allocated output buffer */
    int*    count;      /* protected by caller lock */
    int     min_len;
    int     max_strings;
    CRITICAL_SECTION* lock;
};

static uint8_t is_printable[256];

static void init_printable() {
    static int done=0;
    if(done) return;
    for(int i=0;i<256;i++) is_printable[i]=(i>=0x20 && i<0x7f)?1:0;
    done=1;
}

static unsigned __stdcall strings_thread(void* arg){
    StrChunk* sc=(StrChunk*)arg;
    char tmp[MAX_STRING_LEN+2];
    int cur=0;
    for(size_t i=sc->start;i<sc->end;i++){
        uint8_t b=sc->data[i];
        if(is_printable[b] && b!='\r' && b!='\n'){
            if(cur<MAX_STRING_LEN) tmp[cur++]=b;
        } else {
            if(cur >= sc->min_len){
                tmp[cur]='\n'; tmp[cur+1]='\0';
                EnterCriticalSection(sc->lock);
                int idx = *sc->count;
                if(idx < sc->max_strings){
                    memcpy(sc->out + (size_t)idx*(MAX_STRING_LEN+2), tmp, cur+2);
                    (*sc->count)++;
                }
                LeaveCriticalSection(sc->lock);
            }
            cur=0;
        }
    }
    return 0;
}

/*
 * Extract printable ASCII strings.
 * out: flat buffer of (max_strings × 514) bytes.
 * Returns count of strings found.
 */
EXPORT int32_t extract_strings(const uint8_t* data, size_t len,
                                char* out, int32_t max_strings, int32_t min_len) {
    init_printable();
    if(len==0||max_strings<=0) return 0;
    CRITICAL_SECTION lock;
    InitializeCriticalSection(&lock);
    int count=0;
    int n = (len > CHUNK_SIZE*2) ? THREAD_COUNT : 1;
    StrChunk chunks[THREAD_COUNT];
    HANDLE threads[THREAD_COUNT];
    size_t chunk = len / n;
    for(int i=0;i<n;i++){
        chunks[i].data       = data;
        chunks[i].start      = i*chunk;
        chunks[i].end        = (i==n-1) ? len : (i+1)*chunk;
        chunks[i].out        = out;
        chunks[i].count      = &count;
        chunks[i].min_len    = min_len;
        chunks[i].max_strings= max_strings;
        chunks[i].lock       = &lock;
        threads[i]=(HANDLE)_beginthreadex(NULL,0,strings_thread,&chunks[i],0,NULL);
    }
    WaitForMultipleObjects(n,(const HANDLE*)threads,TRUE,INFINITE);
    for(int i=0;i<n;i++) CloseHandle(threads[i]);
    DeleteCriticalSection(&lock);
    return count;
}


/* ════════════════════════════════════════════════════════════
 *  PATTERN MATCHING — Boyer-Moore-Horspool
 * ════════════════════════════════════════════════════════════ */
struct PatternResult { int32_t offset; int32_t pat_idx; };

static void build_bmt(const uint8_t* pat, int plen, int bmt[256]){
    for(int i=0;i<256;i++) bmt[i]=plen;
    for(int i=0;i<plen-1;i++) bmt[pat[i]]=plen-1-i;
}

/*
 * Scan data for multiple binary patterns simultaneously.
 * patterns:    flat array of all pattern bytes concatenated
 * pat_lens:    array of individual pattern lengths
 * pat_count:   number of patterns
 * results:     output array of PatternResult (offset, pat_idx)
 * max_results: cap
 * Returns total hits.
 */
EXPORT int32_t scan_patterns(const uint8_t* data, size_t data_len,
                              const uint8_t* patterns, const int32_t* pat_lens,
                              int32_t pat_count, PatternResult* results,
                              int32_t max_results) {
    int total=0;
    size_t pat_offset=0;
    for(int pi=0;pi<pat_count && total<max_results;pi++){
        int plen=pat_lens[pi];
        const uint8_t* pat=patterns+pat_offset;
        pat_offset+=plen;
        if((size_t)plen>data_len) continue;
        int bmtable[256];
        build_bmt(pat,plen,bmtable);
        size_t i=plen-1;
        while(i<data_len && total<max_results){
            int j=plen-1, k=i;
            while(j>=0 && data[k]==pat[j]){j--;k--;}
            if(j<0){
                results[total].offset=(int32_t)k+1;
                results[total].pat_idx=pi;
                total++;
                i+=plen;
            } else {
                int skip=bmtable[data[i]];
                i+=skip;
            }
        }
    }
    return total;
}


/* ════════════════════════════════════════════════════════════
 *  PE STRUCTURE PARSER
 * ════════════════════════════════════════════════════════════ */
#pragma pack(push,1)
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} PE_COFF;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} PE_SECTION;
#pragma pack(pop)

typedef struct {
    int32_t  valid;
    uint32_t timestamp;
    uint32_t machine;
    uint16_t num_sections;
    uint32_t entry_point;
    uint32_t image_base_lo;  /* low 32 bits */
    int32_t  has_overlay;
    int32_t  overlay_entropy_x10000;
    uint32_t characteristics;
    /* Sections: max 32 */
    int32_t  sec_count;
    char     sec_names[32][10];
    uint32_t sec_chars[32];
    int32_t  sec_entropy[32];
    /* Checksum */
    uint32_t file_checksum;
    int32_t  checksum_valid;  /* 0 unknown, 1 valid, -1 invalid */
} PEInfo;

EXPORT void parse_pe(const uint8_t* data, size_t len, PEInfo* info) {
    memset(info,0,sizeof(PEInfo));
    if(len < 64) return;
    if(data[0]!='M'||data[1]!='Z') return;
    uint32_t pe_off = *(uint32_t*)(data+0x3c);
    if(pe_off+sizeof(PE_COFF)+4 > len) return;
    if(memcmp(data+pe_off,"PE\0\0",4)!=0) return;
    info->valid = 1;
    const PE_COFF* coff = (const PE_COFF*)(data+pe_off+4);
    info->timestamp    = coff->TimeDateStamp;
    info->machine      = coff->Machine;
    info->num_sections = coff->NumberOfSections;
    info->characteristics = coff->Characteristics;

    /* Optional header: entry point + image base */
    size_t opt_off = pe_off+4+sizeof(PE_COFF);
    if(opt_off+4 <= len) {
        uint16_t magic = *(uint16_t*)(data+opt_off);
        if(magic==0x10b && opt_off+24+4 <= len) {  /* PE32 */
            info->entry_point  = *(uint32_t*)(data+opt_off+16);
            info->image_base_lo= *(uint32_t*)(data+opt_off+28);
            if(opt_off+56+4 <= len) info->file_checksum = *(uint32_t*)(data+opt_off+64);
        } else if(magic==0x20b && opt_off+24+4 <= len) { /* PE32+ */
            info->entry_point  = *(uint32_t*)(data+opt_off+16);
            info->image_base_lo= *(uint32_t*)(data+opt_off+24);
            if(opt_off+72+4 <= len) info->file_checksum = *(uint32_t*)(data+opt_off+88);
        }
    }

    /* Sections */
    size_t sec_off = opt_off + coff->SizeOfOptionalHeader;
    int nsec = coff->NumberOfSections;
    if(nsec>32) nsec=32;
    info->sec_count = nsec;
    uint32_t last_raw_end = 0;
    for(int i=0;i<nsec;i++){
        if(sec_off+sizeof(PE_SECTION) > len) break;
        const PE_SECTION* s = (const PE_SECTION*)(data+sec_off);
        memcpy(info->sec_names[i], s->Name, 8);
        info->sec_names[i][8]='\0';
        info->sec_chars[i] = s->Characteristics;
        /* Per-section entropy */
        if(s->PointerToRawData && s->SizeOfRawData &&
           s->PointerToRawData+s->SizeOfRawData <= len){
            EntropyChunk c;
            c.data=data+s->PointerToRawData;
            c.len =s->SizeOfRawData;
            c.result=0.0;
            entropy_thread(&c);
            info->sec_entropy[i]=(int32_t)(c.result*10000);
        }
        uint32_t end = s->PointerToRawData + s->SizeOfRawData;
        if(end > last_raw_end) last_raw_end = end;
        sec_off += sizeof(PE_SECTION);
    }
    /* Overlay detection */
    if(last_raw_end && last_raw_end < (uint32_t)len - 16){
        info->has_overlay = 1;
        size_t ov_len = len - last_raw_end;
        EntropyChunk c={data+last_raw_end, ov_len, 0.0};
        entropy_thread(&c);
        info->overlay_entropy_x10000 = (int32_t)(c.result*10000);
    }
}


/* ════════════════════════════════════════════════════════════
 *  UNICODE STRING EXTRACTION (UTF-16LE wide strings)
 * ════════════════════════════════════════════════════════════ */
EXPORT int32_t extract_wide_strings(const uint8_t* data, size_t len,
                                    char* out, int32_t max_strings, int32_t min_len) {
    int count=0;
    char tmp[MAX_STRING_LEN+2];
    int cur=0;
    for(size_t i=0;i+1<len && count<max_strings;i+=2){
        uint16_t wc = *(uint16_t*)(data+i);
        if(wc>=0x20 && wc<0x7f){
            if(cur<MAX_STRING_LEN) tmp[cur++]=(char)wc;
        } else {
            if(cur >= min_len){
                tmp[cur]='\n'; tmp[cur+1]='\0';
                memcpy(out+(size_t)count*(MAX_STRING_LEN+2), tmp, cur+2);
                count++;
            }
            cur=0;
        }
    }
    return count;
}


/* ════════════════════════════════════════════════════════════
 *  BYTE FREQUENCY / IMBALANCE (stego / compression detection)
 * ════════════════════════════════════════════════════════════ */
EXPORT void byte_freq(const uint8_t* data, size_t len,
                      uint32_t* freq_out, int32_t* chi_sq_x100) {
    uint64_t freq[256]={};
    for(size_t i=0;i<len;i++) freq[data[i]]++;
    double expected = (double)len / 256.0;
    double chi = 0.0;
    for(int i=0;i<256;i++){
        freq_out[i] = (uint32_t)freq[i];
        double diff = freq[i] - expected;
        chi += diff*diff / expected;
    }
    *chi_sq_x100 = (int32_t)(chi * 100);
}


BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) { (void)h;(void)reason; return TRUE; }