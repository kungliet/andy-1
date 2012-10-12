/*
 * Generates 8-byte random seed for Windows95 system.
 * 
 * Author: Kang, Eun-Seong
 * Date  : 1998. 2. 11
 */

#include <CrConfig.h>
#ifdef SWC_RANDOM_NUMBER

#include <CrSMemMgr.h>




#ifdef WIN32

#include <time.h>
#include <sys/timeb.h>
#include <stdio.h>
#include <io.h> // for _find 
#include <windows.h>
#include <process.h>
#include "CrSHA.h"

CrUINT8*	getSeed(CrUINT8 *);
/**
 *Taesung Kim Modified(2000/10/17)
 *Original Code
 *	#define SEED_LEN 8
 *Because of the seed vector difference between DES and RC5
 */
#ifdef DES_RANDOM
#define SEED_LEN		8
#elif defined(AES_RANDOM) || defined(RC5_RANDOM)
#define SEED_LEN		16
#endif
//2000.11.4 KyungIm Jung Modified
//#define CEIL4(a)	( (a%4) ? (a/4+1)*4 : (a) )
#define CEIL4(a)	( (a%4) ? (a/4)*4 : (a) )
#define NUM_WINDIR_FILES	27
static CrUINT8		SeedBuf[SEED_LEN];
static CrULONG32	Counter = 0;
CrUINT8*
getSeed(CrUINT8* sbufp )
{
	register CrINT32		i, ii;
	CrINT8	*bufp, fspec[10], winDir[MAX_PATH];
	CrLONG32	handle, slpTime;
	CrUINT32 pid;
	CrUINT8 sbuf[SHA_DIGEST_LENGTH];
	CrULONG32 rr, lp;
	struct	_finddata_t	fdata;
	struct  _timeb tmb;
	clock_t clk; // CrLONG32
	if( GetWindowsDirectory( (LPTSTR)winDir, MAX_PATH ) == 0 )
	{
		printf( "GetWindowsDirectory() failed\n" );
		exit( 1 );
	}
	if( !SetCurrentDirectory( winDir ) )
	{
		printf( "SetCurrentDirectory() failed\n" );
		exit( 1 );
	}
	_ftime( &tmb );
	strcpy( fspec, "*.ini" );
	handle = _findfirst( fspec, &fdata );
	fdata.time_write = fdata.size = 0L;
	ii = (tmb.time+tmb.millitm)%NUM_WINDIR_FILES;
	for( i = 0; i < ii && _findnext( handle, &fdata )!= -1; i++ );
	_findclose( handle );
	lp = (CrULONG32)&winDir[(tmb.time+tmb.millitm+fdata.size)%MAX_PATH];
	
	pid = getpid();
	SMemset( sbuf, 0, SHA_DIGEST_LENGTH );
	rr = tmb.time*1000 + tmb.millitm;
	SMemcpy( &sbuf[CEIL4(rr%(SHA_DIGEST_LENGTH-4))], (CrUINT8 *)&rr, sizeof(CrLONG32) );
	rr = lp ^ pid ^ (tmb.time*1000 + tmb.millitm) ^ fdata.time_write ^ fdata.size;
	SMemcpy( &sbuf[CEIL4(rr%(SHA_DIGEST_LENGTH-4))+1], (CrUINT8 *)&rr, sizeof(CrLONG32) );
	SMemcpy( &sbuf[CEIL4(rr%(SHA_DIGEST_LENGTH-4))+2], (CrUINT8 *)&Counter, sizeof(CrLONG32) );
	Counter++;
	for( i = 0; i < 3; i++ )
	{
		bufp = (CrINT8 *)SHA1( sbuf, SHA_DIGEST_LENGTH, NULL );
		
		_ftime( &tmb );
		clk = clock();
		slpTime = (clk&0xffff^(CrLONG32)&winDir[clk%MAX_PATH]&0xffff) % 10 
				+ (tmb.millitm&0xffff^(CrLONG32)&SeedBuf[i]&0xffff) % 33; 
		sbuf[0] ^= slpTime&0xff;
		for( ii = 0; ii < SHA_DIGEST_LENGTH; ii++ )
			sbuf[ii] ^= bufp[ii];
		if( slpTime < 25 ) slpTime+=25;
		Sleep( slpTime );
	} // for
	SMemcpy( SeedBuf, sbuf, SEED_LEN );
	/**
	 *	2001.07.06 Removed by Taesung Kim.
	 *	Input parameter, sbufp is NULL.
	 *	And I only need return value, "SeedBuf", so don't need to
	 *	copy SeedBuf to sbufp : SMemcpy( sbufp, SeedBuf, SEED_LEN );
	 */
	/*
	if( sbufp != NULL )
		SMemcpy( sbufp, SeedBuf, SEED_LEN );
	*/
	return( SeedBuf );
}	
#endif	//#ifdef WIN32
/*
 * Generates 8-byte random seed for PSOS system.
 * 
 * Author: Lee, Tae-Seung
 * Date  : 1998.
 */
#ifdef UNIX
#ifdef XEN
#include <xen/time.h>
extern CrULONG64 jiffies;
extern CrUINT8* SHA1( CrUINT8 *, CrINT32, CrUINT8 *);
CrUINT8*	getSeed(CrUINT8 *);
CrINT32		getRandom(CrUINT8 *, CrINT32);
/**
 *Taesung Kim Modified (2000/10/18)
 *Original Code
 *	#define SEED_LEN 8
 *Because of the seed vector difference between DES and RC5
 */
#ifdef DES_RANDOM
#define SEED_LEN 8
#elif defined(AES_RANDOM) || defined(RC5_RANDOM)
#define SEED_LEN 16
#endif
/**
 *Taesung Kim Modified (2000/11/28)
 *Original Code
 *	#define BUFSIZE 200
 *200 bytes is too many space
 *20 bytes is appropriate
 */
#define BUFSIZE 20
static CrUINT8   Seed_Buf[SEED_LEN];
/* commented by tslee for psos debug
ULONG getOSCR()
{
	return (*(volatile ULONG *)OSCR);
}
*/
CrINT32 getRandom(CrUINT8 *random, CrINT32 random_len)
{
    CrINT32 i,location;
//    CrINT32 e, i, location;
 //   CrULONG32 date, year, month, day, time, ticks;
    location =0;
    for ( i=0; i<(random_len/SEED_LEN); i++) {
        location = i*SEED_LEN;
        SMemcpy( random+location, getSeed(NULL), SEED_LEN);
    }
    SMemcpy( random+location+SEED_LEN, getSeed(NULL), 4);
    return 0;
}
/*
*Warning: 'ticks' may be used before being set
*Warning: 'time' may be used before being set
*Warning: 'oscr2' may be used before being set
*ARM 컴파일시 위와 같은 warning메시지가 뜨는 이유는 초기화를 하지 않고 
*함수에서 사용했기 때문인데, 현재와 같이 굳이 코딩을 한 이유는 garbage값을 
*고의적으로 얻기 위해서이다.
*/
CrUINT8 *getSeed(CrUINT8 *sbufp)
{
	CrUINT32 oscr, oscr2;
	CrUINT32 resource1, resource2, resource3, resource4, resource5;
	CrUINT32 times,ticks,tmp;
	CrUINT8 buf[BUFSIZE], *shabufp;
	oscr = jiffies;	
	times = jiffies;
	resource2 = ((CrUINT32)oscr) ^ times;
// get resource3 from oscr and ticks
	tmp = oscr >> 5;
	if (ticks == 0 || ticks ==1)
		resource3 = tmp * 0x3A;
	else
		resource3 = tmp * ticks;
	resource4 = oscr2;
	// get resource5 from local address;
	resource5 = (CrULONG32)&oscr;
	// operation for generating random seed
	SMemset( buf, 0x00, BUFSIZE);
	SMemcpy( buf, (CrINT8 *)&resource1, sizeof(CrULONG32));
	SMemcpy( buf+sizeof(CrULONG32), (CrINT8 *)&resource2, sizeof(CrULONG32));
	SMemcpy( buf+sizeof(CrULONG32)*2, (CrINT8 *)&resource3, sizeof(CrULONG32));
	SMemcpy( buf+sizeof(CrULONG32)*3, (CrINT8 *)&resource4, sizeof(CrULONG32));
	SMemcpy( buf+sizeof(CrULONG32)*4, (CrINT8 *)&resource5, sizeof(CrULONG32));
	shabufp = (CrUINT8 *)SHA1( buf, 20, NULL );
   	SMemcpy(Seed_Buf, shabufp, SEED_LEN);
   	return( Seed_Buf );
}
#else
#include <time.h>
extern CrUINT8* SHA1( CrUINT8 *, CrINT32, CrUINT8 *);
CrUINT8*	getSeed(CrUINT8 *);
CrINT32		getRandom(CrUINT8 *, CrINT32);
/**
 *Taesung Kim Modified (2000/10/18)
 *Original Code
 *	#define SEED_LEN 8
 *Because of the seed vector difference between DES and RC5
 */
#ifdef DES_RANDOM
#define SEED_LEN 8
#elif defined(AES_RANDOM) || defined(RC5_RANDOM)
#define SEED_LEN 16
#endif
/**
 *Taesung Kim Modified (2000/11/28)
 *Original Code
 *	#define BUFSIZE 200
 *200 bytes is too many space
 *20 bytes is appropriate
 */
#define BUFSIZE 20
static CrUINT8   Seed_Buf[SEED_LEN];
/* commented by tslee for psos debug
ULONG getOSCR()
{
	return (*(volatile ULONG *)OSCR);
}
*/
CrINT32 getRandom(CrUINT8 *random, CrINT32 random_len)
{
    CrINT32 i,location;
//    CrINT32 e, i, location;
 //   CrULONG32 date, year, month, day, time, ticks;
    location =0;
    for ( i=0; i<(random_len/SEED_LEN); i++) {
        location = i*SEED_LEN;
        SMemcpy( random+location, getSeed(NULL), SEED_LEN);
    }
    SMemcpy( random+location+SEED_LEN, getSeed(NULL), 4);
    return 0;
}
/*
*Warning: 'ticks' may be used before being set
*Warning: 'time' may be used before being set
*Warning: 'oscr2' may be used before being set
*ARM 컴파일시 위와 같은 warning메시지가 뜨는 이유는 초기화를 하지 않고 
*함수에서 사용했기 때문인데, 현재와 같이 굳이 코딩을 한 이유는 garbage값을 
*고의적으로 얻기 위해서이다.
*/
CrUINT8 *getSeed(CrUINT8 *sbufp)
{
	CrUINT32 oscr, oscr2;
	CrUINT32 resource1, resource2, resource3, resource4, resource5;
	CrUINT32 times,ticks,tmp;
	CrUINT8 buf[BUFSIZE], *shabufp;
	time(&oscr);	
	times = clock();
	resource2 = ((CrUINT32)oscr) ^ times;
// get resource3 from oscr and ticks
	tmp = oscr >> 5;
	if (ticks == 0 || ticks ==1)
		resource3 = tmp * 0x3A;
	else
		resource3 = tmp * ticks;
	resource4 = oscr2;
	// get resource5 from local address;
	resource5 = (CrULONG32)&oscr;
	// operation for generating random seed
	SMemset( buf, 0x00, BUFSIZE);
	SMemcpy( buf, (CrINT8 *)&resource1, sizeof(CrULONG32));
	SMemcpy( buf+sizeof(CrULONG32), (CrINT8 *)&resource2, sizeof(CrULONG32));
	SMemcpy( buf+sizeof(CrULONG32)*2, (CrINT8 *)&resource3, sizeof(CrULONG32));
	SMemcpy( buf+sizeof(CrULONG32)*3, (CrINT8 *)&resource4, sizeof(CrULONG32));
	SMemcpy( buf+sizeof(CrULONG32)*4, (CrINT8 *)&resource5, sizeof(CrULONG32));
	shabufp = (CrUINT8 *)SHA1( buf, 20, NULL );
   	SMemcpy(Seed_Buf, shabufp, SEED_LEN);
   	return( Seed_Buf );
}
#endif // end of #ifdef XEN
#endif //end of #ifdef UNIX
#endif // #ifdef SWC_RANDOM_NUMBER

