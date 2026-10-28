#pragma once
#include <cstdio>
#include <cstdlib>

// Optional verbose tracing for the lifting pipeline.
// Enable with NOVMP_VERBOSE=1 in the environment.
namespace vmp
{
	inline bool verbose_enabled()
	{
		static const bool enabled = []
		{
			const char* e = getenv( "NOVMP_VERBOSE" );
			return e && *e && *e != '0';
		}();
		return enabled;
	}
}

#define dprintf( ... ) \
	do { if ( vmp::verbose_enabled() ) fprintf( stderr, __VA_ARGS__ ); } while ( 0 )
