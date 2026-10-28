// Copyright (C) 2020 Can Boluk
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// novmp-run — batch supervisor for NoVmp (local patch).
//
// Runs one NoVmp worker process per vmenter entry so a hard crash or a hang
// kills exactly that entry, never the batch. Parallelism is process-level
// (workers share nothing unsafe; the image file pages are shared by the OS).
// Results are aggregated from each worker's -report JSONL line; a worker
// that dies by signal or loses its report is classified as crash/timeout.
//
// usage: novmp-run <image> <vms-file> [options]
//   -bin <path>     NoVmp worker binary (default: sibling "NoVmp" next to me)
//   -o <dir>        output directory (default: novmp-run-out)
//   -j <n>          parallel workers (default: 2)
//   -t <seconds>    per-entry wall-clock budget passed as NOVMP_TIME_LIMIT;
//                   the supervisor kills at 2x this (default: 60)
//   -profile <f>    forwarded to the worker
//   -sections <s>   forwarded to the worker (repeatable)
//   -base <b>       forwarded to the worker
//
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <map>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;

struct job_t
{
	std::string rva;
	std::string report;
	std::string log;
	pid_t pid = -1;
	time_t started = 0;
	bool done = false;
};

static std::string read_first_line( const std::string& path )
{
	FILE* f = fopen( path.c_str(), "r" );
	if ( !f ) return {};
	char line[ 1024 ] = {};
	fgets( line, sizeof( line ), f );
	fclose( f );
	return line;
}

// {"rva":"0x..","status":"ok"...} -> ok
// {"rva":"0x..","status":"error","class":"switch-case"...} -> switch-case
static std::string report_class( const std::string& line )
{
	auto at = [ & ] ( const char* key ) -> std::string
	{
		std::string k = std::string( "\"" ) + key + "\":\"";
		size_t p = line.find( k );
		if ( p == std::string::npos ) return {};
		p += k.size();
		size_t e = line.find( '"', p );
		if ( e == std::string::npos ) return {};
		return line.substr( p, e - p );
	};
	std::string status = at( "status" );
	if ( status == "ok" ) return "ok";
	std::string cls = at( "class" );
	return cls.empty() ? status : cls;
}

int main( int argc, char** argv )
{
	if ( argc < 3 )
	{
		fprintf( stderr, "usage: novmp-run <image> <vms-file> [-bin p] [-o dir] [-j n] [-t secs] [-profile f] [-sections s] [-base b]\n" );
		return 1;
	}
	// Local patch: the VTIL/lifter recursions (rtrace path enumeration, the
	// symbolic simplifier, the explorer forks) can grow far faster than the
	// wall-clock guards poll, so a default 8 MiB stack overflows (SIGSEGV
	// before the budget fires; observed ~16k nested frames). Raise the stack
	// limit before any spawn — children inherit it and map their main stack
	// from it, turning stack overflow into a catchable budget timeout.
	{
		constexpr rlim_t WANT = 512ull << 20;
		struct rlimit rl = {};
		if ( getrlimit( RLIMIT_STACK, &rl ) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < WANT )
		{
			rlim_t hard = rl.rlim_max == RLIM_INFINITY ? WANT : rl.rlim_max;
			rl.rlim_cur = hard < WANT ? hard : WANT;
			if ( setrlimit( RLIMIT_STACK, &rl ) != 0 )
				fprintf( stderr, "[novmp-run] warning: cannot raise RLIMIT_STACK: %s\n", strerror( errno ) );
		}
	}
	std::string image = argv[ 1 ];
	std::string vms_file = argv[ 2 ];

	// Worker binary: look next to this executable, covering both the build
	// tree layout (build/supervisor/novmp-run + build/NoVmp/AnimeNoVMP) and a
	// flat install (both binaries in one directory).
	std::string default_bin;
	char self[ 4096 ] = {};
	ssize_t n = readlink( "/proc/self/exe", self, sizeof( self ) - 1 );
	if ( n > 0 )
	{
		std::string dir( self );
		size_t slash = dir.rfind( '/' );
		if ( slash != std::string::npos )
		{
			for ( std::string cand : { dir.substr( 0, slash + 1 ) + "AnimeNoVMP",
									   dir.substr( 0, slash + 1 ) + "../NoVmp/AnimeNoVMP",
									   dir.substr( 0, slash + 1 ) + "NoVmp",
									   dir.substr( 0, slash + 1 ) + "../NoVmp/NoVmp" } )
			{
				if ( access( cand.c_str(), X_OK ) == 0 )
				{
					default_bin = cand;
					break;
				}
			}
		}
	}
	if ( default_bin.empty() ) default_bin = "AnimeNoVMP";

	std::string bin = default_bin;
	std::string outdir = "novmp-run-out";
	int jobs = 2;
	int tlimit = 60;
	std::vector<std::string> fwd;   // forwarded worker arguments
	for ( int i = 3; i < argc; i++ )
	{
		auto next = [ & ] () -> std::string { return i + 1 < argc ? argv[ ++i ] : ""; };
		std::string a = argv[ i ];
		if ( a == "-bin" ) bin = next();
		else if ( a == "-o" ) outdir = next();
		else if ( a == "-j" ) jobs = atoi( next().c_str() );
		else if ( a == "-t" ) tlimit = atoi( next().c_str() );
		else if ( a == "-profile" || a == "-sections" || a == "-base" )
		{
			std::string v = next();
			fwd.push_back( a );
			if ( !v.empty() ) fwd.push_back( v );
		}
		else { fprintf( stderr, "unknown option %s\n", a.c_str() ); return 1; }
	}
	if ( jobs < 1 ) jobs = 1;
	// Worker budget: override any inherited value once, before any spawn.
	setenv( "NOVMP_TIME_LIMIT", std::to_string( tlimit ).c_str(), 1 );

	mkdir( outdir.c_str(), 0755 );
	std::string logsdir = outdir + "/logs";
	mkdir( logsdir.c_str(), 0755 );

	// Read the entry list.
	//
	std::vector<job_t> queue;
	{
		FILE* f = fopen( vms_file.c_str(), "r" );
		if ( !f ) { fprintf( stderr, "cannot open %s\n", vms_file.c_str() ); return 1; }
		char line[ 256 ];
		while ( fgets( line, sizeof( line ), f ) )
		{
			char* p = line;
			while ( *p == ' ' || *p == '\t' ) p++;
			if ( *p == '\n' || *p == '\r' || *p == '#' || *p == '\0' ) continue;
			std::string rva( p );
			while ( !rva.empty() && ( rva.back() == '\n' || rva.back() == '\r' ||
									  rva.back() == ' ' || rva.back() == '\t' ) )
				rva.pop_back();
			size_t tab = rva.find( '\t' );
			if ( tab != std::string::npos ) rva.resize( tab );
			job_t j;
			j.rva = rva;
			j.report = outdir + "/" + rva + ".jsonl";
			j.log = logsdir + "/" + rva + ".log";
			unlink( j.report.c_str() );
			queue.push_back( j );
		}
		fclose( f );
	}
	fprintf( stderr, "[novmp-run] %zu entries, -j %d, -t %d, worker %s\n",
			 queue.size(), jobs, tlimit, bin.c_str() );

	size_t next_job = 0;
	std::map<pid_t, size_t> inflight;
	time_t now = time( nullptr );

	auto launch = [ & ] ( size_t idx ) -> bool
	{
		job_t& j = queue[ idx ];
		std::vector<std::string> args = { bin, image };
		for ( auto& s : fwd ) args.push_back( s );
		args.push_back( "-vms" );
		args.push_back( j.rva );
		args.push_back( "-report" );
		args.push_back( j.report );

		std::vector<char*> argv_c;
		for ( auto& s : args ) argv_c.push_back( s.data() );
		argv_c.push_back( nullptr );

		int log_fd = open( j.log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644 );
		if ( log_fd < 0 ) return false;
		posix_spawn_file_actions_t fa;
		posix_spawn_file_actions_init( &fa );
		posix_spawn_file_actions_adddup2( &fa, log_fd, 1 );
		posix_spawn_file_actions_adddup2( &fa, log_fd, 2 );
		pid_t pid = -1;
		// The budget reaches the worker through the inherited environment
		// (set once below); the rest of the environment is passed untouched.
		int rc = posix_spawn( &pid, bin.c_str(), &fa, nullptr, argv_c.data(), environ );
		posix_spawn_file_actions_destroy( &fa );
		close( log_fd );
		if ( rc != 0 ) return false;
		j.pid = pid;
		j.started = time( nullptr );
		inflight[ pid ] = idx;
		return true;
	};

	FILE* summary = fopen( ( outdir + "/summary.tsv" ).c_str(), "w" );
	fprintf( summary, "rva\tclass\n" );
	std::map<std::string, int> histogram;

	while ( next_job < queue.size() || !inflight.empty() )
	{
		// Refill slots.
		//
		now = time( nullptr );
		while ( inflight.size() < ( size_t ) jobs && next_job < queue.size() )
		{
			if ( !launch( next_job ) )
			{
				fprintf( summary, "%s\tspawn-failed\n", queue[ next_job ].rva.c_str() );
				histogram[ "spawn-failed" ]++;
				queue[ next_job ].done = true;
			}
			next_job++;
		}

		// Reap whatever finished.
		//
		int status = 0;
		pid_t pid = waitpid( -1, &status, WNOHANG );
		if ( pid > 0 )
		{
			auto it = inflight.find( pid );
			if ( it != inflight.end() )
			{
				job_t& j = queue[ it->second ];
				std::string cls = report_class( read_first_line( j.report ) );
				if ( cls.empty() )
				{
					if ( WIFSIGNALED( status ) )
						cls = std::string( "crash:" ) + strsignal( WTERMSIG( status ) );
					else if ( WIFEXITED( status ) && WEXITSTATUS( status ) != 0 )
						cls = "exit" + std::to_string( WEXITSTATUS( status ) );
					else
						cls = "no-report";
				}
				fprintf( summary, "%s\t%s\n", j.rva.c_str(), cls.c_str() );
				histogram[ cls ]++;
				j.done = true;
				inflight.erase( it );
			}
			continue;   // reap more without sleeping
		}
		if ( pid < 0 && errno == ECHILD && inflight.empty() ) break;

		// Timeout enforcement: kill at 2x the budget.
		//
		now = time( nullptr );
		for ( auto it = inflight.begin(); it != inflight.end(); ++it )
		{
			job_t& j = queue[ it->second ];
			if ( now - j.started > ( time_t ) ( tlimit * 2 + 15 ) )
			{
				kill( it->first, SIGKILL );
			}
		}
		usleep( 100000 );
	}

	fclose( summary );
	fprintf( stderr, "\n[novmp-run] results:\n" );
	for ( auto& [ cls, n ] : histogram )
		fprintf( stderr, "  %-24s %d\n", cls.c_str(), n );
	fprintf( stderr, "[novmp-run] summary: %s/summary.tsv\n", outdir.c_str() );
	return 0;
}
