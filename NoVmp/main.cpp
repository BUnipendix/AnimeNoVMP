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
#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <intrin.h>
#include "vmprotect/verbose.hpp"
#else
#include <x86intrin.h>
#endif
#include <fstream>
#include <tuple>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <future>
#include <cstdio>
#include <cstring>
#include <malloc.h>
#include <cctype>
#include <linuxpe>
#include <algorithm>
#include "vmprotect/image_desc.hpp"
#include "vmprotect/vtil_lifter.hpp"
#include "vmprotect/vm_state.hpp"
#include "vmprotect/profile.hpp"
#include "demo_compiler.hpp"

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <sys/resource.h>
#endif

// ---- per-routine JSONL report -----------------------------------------------
// With -report <file> one JSON object per line is appended for every routine
// in the batch: {"rva","status":"ok|error","class","reason","ins","blocks",
// "vtil"}. Hard crashes still kill the process (a supervisor restarts the
// remaining work; exit status separates signal deaths from clean runs).
static std::string json_escape( const std::string& s )
{
	std::string out;
	for ( char c : s )
	{
		switch ( c )
		{
			case '"':  out += "\\\""; break;
			case '\\': out += "\\\\"; break;
			case '\n': out += "\\n";  break;
			case '\r': out += "\\r";  break;
			case '\t': out += "\\t";  break;
			default:
				if ( ( uint8_t ) c < 0x20 ) out += ' ';
				else out += c;
		}
	}
	return out;
}

static std::string classify_error( const std::string& what )
{
	auto has = [ & ] ( const char* k ) { return what.find( k ) != std::string::npos; };
	if ( has( "time budget" ) )          return "budget";
	if ( has( "churn limit" ) )          return "simplify-churn";
	if ( has( "Invalid VIP" ) )          return "invalid-vip";
	if ( has( "switch case" ) )          return "switch-case";
	if ( has( "invalid virtual jump" ) ) return "invalid-vjmp";
	if ( has( "Assertion failure" ) )    return "assertion";
	if ( has( "vmenter:" ) )             return "vmenter-shape";
	if ( has( "unroll exceeded" ) )      return "unroll-bound";
	if ( has( "nesting depth" ) )        return "vm-depth";
	if ( has( "vsp-indexed" ) )          return "unhandled-vsp";
	if ( has( "left the image" ) )       return "left-image";
	if ( has( "deobfuscate" ) )          return "deobfuscate";
	return "error";
}

#ifdef _MSC_VER
#pragma comment(linker, "/STACK:34359738368")
#endif

using namespace vtil::logger;

static std::vector<uint8_t> read_raw( const std::string& file_path )
{
	// Try to open file as binary
	std::ifstream file( file_path, std::ios::binary );
	if ( !file.good() ) error( "Input file cannot be opened." );

	// Read the whole file
	std::vector<uint8_t> bytes = std::vector<uint8_t>( std::istreambuf_iterator<char>( file ), {} );
	if ( bytes.size() == 0 ) error( "Input file is empty." );
	return bytes;
}

static void write_raw( void* data, size_t size, const std::string& file_path )
{
	std::ofstream file( file_path, std::ios::binary );
	if ( !file.good() ) error( "File cannot be opened for write." );
	file.write( ( char* ) data, size );
}

static const std::string gpl3_license_header = ""
"##############################################################################\n"
"# NoVmp  Copyright (C) 2020 Can Boluk                                        #\n"
"# This program comes with absolutely no warranty, and it is free software.   #\n"
"# You are welcome to redistribute it under certain conditions--for which you #\n"
"# can refer to the GNU General Public License v3.                            #\n"
"##############################################################################\n\n";

int main( int argc, const char** argv )
{
	// Local patch: raise the stack limit to the hard ceiling before any deep
	// recursion. Deep VM re-entry chains (and the optimizer's recursion) need
	// headroom; the supervised batch driver already does this pre-spawn, this
	// covers direct one-shot runs. Silently ignored when unprivileged.
	{
		rlimit rl{};
		if ( getrlimit( RLIMIT_STACK, &rl ) == 0 && rl.rlim_cur < rl.rlim_max )
		{
			rl.rlim_cur = rl.rlim_max;
			setrlimit( RLIMIT_STACK, &rl );
		}
	}

	vtil::logger::error_hook = [ ] ( const std::string& message )
	{
		log<CON_RED>( "[*] Unexpected error: %s\n", message );
		throw std::runtime_error( message );
	};

	// Feelin' fancy.
	//
	for ( char c : gpl3_license_header )
		log( c == '#' ? CON_RED : CON_YLW, "%c", c );

	// Parse command line.
	//
	if ( argc < 2 ) error( "No input file provided." );
	std::filesystem::path image_path( argv[ 1 ] );
	std::filesystem::path working_directory = vtil::make_copy(
		image_path
	).remove_filename() / "vms";
	std::filesystem::create_directory( working_directory );
	
	// Create the basic descriptor for the image
	//
	vmp::image_desc* desc = new vmp::image_desc;
	// Local patch: prefer a private file mapping so parallel workers share the
	// image's page-cache pages instead of each holding a heap copy; writes
	// (recompilation) go through copy-on-write.
	//
	if ( !desc->raw.map( image_path.string() ) )
	{
		warning( "File mapping unavailable, falling back to an in-memory copy." );
		desc->raw.own( read_raw( image_path.string() ) );
	}
	desc->override_image_base = 0;
	desc->has_relocs = desc->get_nt_headers()->optional_header.data_directories.basereloc_directory.present();
	desc->strip_constant_obfuscation = false;

	// Warn if relocs are stripped.
	//
	if ( !desc->has_relocs )
		warning( "This image has relocations stripped, NoVmp is not 100%% compatible with this switch yet." );

	// Parse options:
	//
	bool compile = false;
	bool optimize = true;
	std::vector<uint32_t> target_vms;
	std::string profile_path;
	std::string report_path;
	std::vector<std::string> cli_sections;
	for ( int i = 2; i < argc; )
	{
		if ( !strcmp( argv[ i ], "-vms" ) )
		{
			while ( ++i < argc && argv[ i ][ 0 ] != '-' )
				target_vms.emplace_back( strtoul( argv[ i ], nullptr, 16 ) );
		}
		else if ( !strcmp( argv[ i ], "-sections" ) )
		{
			while ( ++i < argc && argv[ i ][ 0 ] != '-' )
				cli_sections.emplace_back( argv[ i ] );
		}
		else if ( !strcmp( argv[ i ], "-base" ) )
		{
			fassert( ++i < argc );
			desc->override_image_base = strtoull( argv[ i ], nullptr, 16 );
			desc->has_relocs = true;
			i++;
		}
		else if ( !strcmp( argv[ i ], "-noopt" ) )
		{
			optimize = false;
			i++;
		}
		else if ( !strcmp( argv[ i ], "-opt:constant" ) )
		{
			desc->strip_constant_obfuscation = true;
			i++;
		}
		else if ( !strcmp( argv[ i ], "-report" ) )
		{
			fassert( ++i < argc );
			report_path = argv[ i ];
			i++;
		}
		else if ( !strcmp( argv[ i ], "-profile" ) )
		{
			fassert( ++i < argc );
			profile_path = argv[ i ];
			i++;
		}
		else if ( !strcmp( argv[ i ], "-experimental:recompile" ) )
		{
			i++;
			compile = true;
		}
		else
		{
			error( "Unknown parameter: %s", argv[ i ] );
		}
	}

	// Local patch (profiles): activate an adaptation profile. Without -profile
	// the profile is auto-detected from the image's section layout (see
	// vmp::detect_profile); -profile overrides the detector. Section prefixes
	// from the profile come first; -sections entries are appended on top.
	//
	if ( !profile_path.empty() )
	{
		std::string profile_error;
		if ( !vmp::load_profile( profile_path, profile_error ) )
			error( "Failed to load profile %s: %s", profile_path.c_str(), profile_error.c_str() );
	}
	else
	{
		std::vector<std::string> section_names;
		for ( int i = 0; i < desc->get_nt_headers()->file_header.num_sections; i++ )
		{
			auto* scn = desc->get_nt_headers()->get_section( i );
			section_names.emplace_back( ( const char* ) scn->name.short_name,
										 strnlen( ( const char* ) scn->name.short_name, 8 ) );
		}
		std::string profile_error;
		if ( !vmp::detect_profile( section_names, profile_error ) )
			error( "Profile auto-detection failed: %s", profile_error.c_str() );
	}
	log<CON_CYN>( "Active profile: %s (%zu vmenter shape(s), sections:",
				  vmp::g_profile.name.c_str(), vmp::g_profile.vmenter_shapes.size() );
	for ( auto& s : vmp::g_profile.sections )
		log<CON_CYN>( " %s", s.c_str() );
	log<CON_CYN>( ")\n" );
	vmp::section_prefixes = vmp::g_profile.sections;
	for ( auto& s : cli_sections )
		vmp::section_prefixes.emplace_back( s );

	// Local patch (profiles): vmenter discovery rule. Classic images expose
	// stubs through cross-section E9/E8 references; the new generation hides
	// them, so "stub-target" discovery scans for the 68 imm32 / E8 rel32 stub
	// shape directly and keeps those whose call lands in a profile VM section.
	//
	const bool stub_target_scan = ( vmp::g_profile.discovery_scan == "stub-target" );
	auto is_vm_section = [ & ] ( const char* name ) -> bool
	{
		if ( !stub_target_scan ) return false;
		for ( auto& p : vmp::g_profile.sections )
			if ( name && strncmp( name, p.c_str(), p.size() ) == 0 ) return true;
		return false;
	};

	// Iterate each section:
	//
	uint32_t rva_high = 0;
	uint32_t raw_low = 0;
	for ( int i = 0; i < desc->get_nt_headers()->file_header.num_sections; i++ )
	{
		// Reference section and re-calculate some stats
		//
		win::section_header_t* scn = desc->get_nt_headers()->get_section( i );
		rva_high = std::max( scn->virtual_address + std::max( scn->virtual_size, scn->size_raw_data ), rva_high );
		raw_low = std::max( scn->ptr_raw_data, raw_low );

		// Skip if it cannot be executed
		//
		if ( !scn->characteristics.mem_execute ) continue;


		// Iterate each byte
		//
		uint8_t* scn_begin = desc->raw.data() + scn->ptr_raw_data;
		uint8_t* scn_end = scn_begin + std::min( scn->size_raw_data, scn->virtual_size );

		for ( uint8_t* it = scn_begin; it < ( scn_end - 10 ); it++ )
		{
			uint32_t stub_rva = 0;
			bool mid_func = false;

				if ( stub_target_scan )
				{
					// New-generation rule: the stub itself is [PUSH imm32][CALL or
					// JMP rel32] and its branch must land in a profile VM section.
					//
					if ( it[ 0 ] != 0x68 || ( it[ 5 ] != 0xE8 && it[ 5 ] != 0xE9 ) ) continue;
					stub_rva = scn->virtual_address + ( uint32_t ) ( it - scn_begin );
					uint32_t call_tgt = stub_rva + 10 + *( int32_t* ) &it[ 6 ];
					win::section_header_t* scn_call = desc->rva_to_section( call_tgt );
					if ( !scn_call || !scn_call->characteristics.mem_execute ||
						 !is_vm_section( ( const char* ) scn_call->name.short_name ) )
						continue;
				}
				else
				{
					// Classic rule: [JMP rel32] or [CALL rel32] sites jumping
					// cross-section onto a vmenter stub.
					//
					if ( it[ 0 ] == 0xE9 )
						mid_func = true;
				else if ( it[ 0 ] == 0xE8 )
					mid_func = false;
				else
					continue;
				uint32_t jmp_rva = scn->virtual_address + ( it - scn_begin ) + 5 + *( int32_t* ) &it[ 1 ];

				// Skip if JMP target is in the same section / in a non-executable section
				//
				win::section_header_t* scn_jmp = desc->rva_to_section( jmp_rva );
				if ( !scn_jmp || scn_jmp == scn || !scn_jmp->characteristics.mem_execute ) continue;

				// Skip if it's not VMENTER
				//
				uint8_t* jmp_target_bytes = desc->raw.data() + jmp_rva + scn_jmp->ptr_raw_data - scn_jmp->virtual_address;
				if ( jmp_target_bytes > &desc->raw.back() ||
					 jmp_target_bytes[ 0 ] != 0x68 ||
					 jmp_target_bytes[ 5 ] != 0xE8 ) continue;
				stub_rva = jmp_rva;
			}

			// Add to image descriptor
			//
			desc->virt_routines.push_back( vmp::virtual_routine{
				.jmp_rva = stub_rva,
				.mid_routine = mid_func
			 } );

			log<CON_YLW>( "Discovered vmenter at %p\n", desc->get_real_image_base() + stub_rva );
		}
	}

	// If VM list is given, replace discovery.
	//
	if ( !target_vms.empty() ) desc->virt_routines.clear();
	for ( uint32_t rva : target_vms )
	{
		desc->virt_routines.push_back( vmp::virtual_routine{
				.jmp_rva = rva,
		} );
	}

	// Declare the worker.
	//
	// last_stats: [ins_before, ins_after, blocks_before, blocks_after] of the
	// most recent successful lift, for the stdio reply channel.
	int64_t last_stats[ 4 ] = {};
	const auto vm_lifter = [ & ] ( int vm_index ) -> vtil::routine*
	{
		// Lift the virtual machine.
		//
		vmp::virtual_routine* vr = &desc->virt_routines[ vm_index ];
		log<CON_DEF>( "Lifting virtual-machine at %p...\n", vr->jmp_rva );
		// Local patch: the wall-clock budget applies to this routine only.
		vmp::reset_time_budget();
		vmp::reset_walk_latch();
		vmp::vm_state state = { desc, vr->jmp_rva };
		vtil::routine* rtn = lift_il( &state );
		dprintf( "[dbg] lift_il returned\n" );
		if ( !rtn ) return nullptr;

		// Save unoptimized routine.
		//
		vtil::save_routine( 
			rtn, 
			( working_directory / vtil::format::str( "%p.premature.vtil", vr->jmp_rva ) ).string()
		);

		// If noopt set, return.
		//
		if ( !optimize ) return rtn;

		// Apply optimizations.
		//
		int64_t ins = rtn->num_instructions();
		int64_t blks = rtn->num_blocks();
		dprintf( "[dbg] opt start\n" );
		// Local patch: a single optimizer pass can diverge on giant lifted
		// routines (observed: mov_propagation churn on 15k-handler walks)
		// and used to fail the whole entry after the lift itself succeeded.
		// Optimization is optional refinement — accept the partially
		// optimized routine when the budget fires mid-pass instead.
		//
		try
		{
			vtil::optimizer::apply_all_profiled( rtn );
		}
		catch ( std::runtime_error& e )
		{
			if ( !strstr( e.what(), "time budget" ) ) throw;
			log( "[!] optimizer hit the time budget at %p — keeping partially optimized routine\n",
				  vr->jmp_rva );
		}
		dprintf( "[dbg] opt done\n" );
			int64_t oins = rtn->num_instructions();
			int64_t oblks = rtn->num_blocks();
			last_stats[ 0 ] = ins; last_stats[ 1 ] = oins;
			last_stats[ 2 ] = blks; last_stats[ 3 ] = oblks;

		// Write routine and optimization information.
		//
		{
			std::lock_guard _g{ logger_state };
			log<CON_GRN>( "\nLifted & optimized virtual-machine at %p\n", vr->jmp_rva );

			log<CON_YLW>( "Optimizer stats:\n" );
			log<CON_CYN>( " - Block count:       %-5d => %-5d (%.2f%%).\n", blks, oblks, 100.0f * float( float( oblks - blks ) / blks ) );
			log<CON_CYN>( " - Instruction count: %-5d => %-5d (%.2f%%).\n", ins, oins, 100.0f * float( float( oins - ins ) / ins ) );

			std::vector<uint8_t> bytes;
			for ( auto& [_, block] : rtn->explored_blocks )
			{
				for ( auto& ins : *block )
				{
					if ( ins.base->name == "vemit" )
					{
						uint8_t* bs = ( uint8_t* ) &ins.operands[ 0 ].imm().u64;
						bytes.insert( bytes.end(), bs, bs + ins.operands[ 0 ].size() );
					}
				}
			}

			if ( bytes.size() )
			{
				log<CON_YLW>( "Special instructions:\n" );

				size_t n = 0;
				auto dasm = vtil::amd64::disasm( bytes.data(), 0, bytes.size() );
				for ( auto& ins : dasm )
				{
					n++;
					log<CON_PRP>( " - %s\n", ins );
					if ( n > 10 )
					{
						log<CON_PRP>( " - ...\n" );
						break;
					}
				}
			}
		}

		// Save optimized routine.
		//
		vtil::save_routine(
			rtn,
			( working_directory / vtil::format::str( "%p.optimized.vtil", vr->jmp_rva ) ).string()
		);
		return rtn;
	};

	// Lift every routine and wait for completion.
	//
	std::vector<std::pair<size_t, std::future<vtil::routine*>>> worker_pool;
	for ( int i = 0; i < desc->virt_routines.size(); i++ )
		worker_pool.emplace_back( i, std::async( /*std::launch::async*/ std::launch::deferred, vm_lifter, i ) );

	// Local patch: per-routine JSONL report (-report <file>) plus batch
	// hygiene — free each routine and the deobfuscation cache between
	// routines so long -vms lists stay memory-bounded. Routines are only kept
	// when recompiling afterwards.
	//
	FILE* report_file = nullptr;
	if ( !report_path.empty() )
	{
		report_file = fopen( report_path.c_str(), "a" );
		if ( !report_file )
			error( "Cannot open report file %s", report_path.c_str() );
	}
	auto report = [ & ] ( uint32_t rva, const char* status, const char* cls,
						  const char* reason, bool with_stats )
	{
		if ( !report_file ) return;
		if ( with_stats )
			fprintf( report_file, "{\"rva\":\"%#x\",\"status\":\"%s\",\"ins\":[%lld,%lld],\"blocks\":[%lld,%lld]}\n",
					 rva, status,
					 ( long long ) last_stats[ 0 ], ( long long ) last_stats[ 1 ],
					 ( long long ) last_stats[ 2 ], ( long long ) last_stats[ 3 ] );
		else
			fprintf( report_file, "{\"rva\":\"%#x\",\"status\":\"%s\",\"class\":\"%s\",\"reason\":\"%s\"}\n",
					 rva, status, cls, reason );
		fflush( report_file );
	};

	for ( auto& [idx, rtn] : worker_pool )
	{
		uint32_t rva = desc->virt_routines[ idx ].jmp_rva;
		try
		{
			desc->virt_routines[ idx ].routine = rtn.get();
			if ( desc->virt_routines[ idx ].routine )
				report( rva, "ok", nullptr, nullptr, true );
			else
				report( rva, "error", "null-lift", "", false );
		}
		catch ( const std::exception& ex )
		{
			log<CON_RED>( "Error: %s\n", ex.what() );
			report( rva, "error", classify_error( ex.what() ).c_str(), json_escape( ex.what() ).c_str(), false );
		}
		catch ( ... )
		{
			report( rva, "error", "unknown", "", false );
		}
		if ( !compile && desc->virt_routines[ idx ].routine )
		{
			delete desc->virt_routines[ idx ].routine;
			desc->virt_routines[ idx ].routine = nullptr;
		}
		vmp::flush_deobfuscate_cache();
#if defined( __GLIBC__ )
		malloc_trim( 0 );  // return freed arenas to the OS between routines
#endif
	}
	if ( report_file ) fclose( report_file );

	// Return if recompilation is not requested.
	//
	if ( !compile )
	{

		return 0;
	}

	uint32_t rva_sec = ( rva_high + 0xFFF ) & ~0xFFF;
	std::vector<uint8_t> byte_stream;
	for ( auto& vr : desc->virt_routines )
	{
		// Page align rva high and calculate where we place the next section
		//
		uint32_t rva_routine = rva_sec + byte_stream.size();
		std::vector substream = vtil::compile( vr.routine, rva_routine );

		// Write jump to new routine.
		//
		if ( vr.jmp_rva )
		{
			uint8_t* jmp_rel32 = desc->rva_to_ptr<uint8_t>( vr.jmp_rva );
			fassert( jmp_rel32 != nullptr );
			*jmp_rel32 = 0xE9;
			*( int32_t* ) ( jmp_rel32 + 1 ) = rva_routine - ( vr.jmp_rva + 5 );
		}

		// Append to stream.
		//
		byte_stream.insert( byte_stream.end(), substream.begin(), substream.end() );
	}

	// Page align the section
	//
	size_t scn_original_size = byte_stream.size();
	byte_stream.resize( ( scn_original_size + 0xFFF ) & ~0xFFF );
	memset( byte_stream.data() + scn_original_size, 0xCC, byte_stream.size() - scn_original_size );

	// Create a new section in the image
	//
	fassert( raw_low > ( sizeof( win::section_header_t ) + desc->get_nt_headers()->optional_header.size_headers ) );
	size_t img_original_size = desc->raw.size();
	desc->raw.resize( img_original_size + byte_stream.size() );
	win::image_x64_t* img = ( win::image_x64_t* ) desc->raw.data();

	win::nt_headers_x64_t* nt_hdrs = img->get_nt_headers();
	nt_hdrs->optional_header.size_code += byte_stream.size();
	nt_hdrs->optional_header.size_image += byte_stream.size();
	nt_hdrs->optional_header.size_headers += sizeof( win::section_header_t );

	win::section_header_t* scn = nt_hdrs->get_section( nt_hdrs->file_header.num_sections++ );
	memset( scn, 0, sizeof( win::section_header_t ) );
	strcpy( &scn->name.short_name[ 0 ], ".novmp" );
	scn->characteristics.cnt_code = 1;
	scn->characteristics.mem_execute = 1;
	scn->characteristics.mem_read = 1;
	scn->virtual_address = rva_sec;
	scn->ptr_raw_data = img_original_size;
	scn->size_raw_data = byte_stream.size();
	scn->virtual_size = byte_stream.size();

	memcpy( desc->raw.data() + img_original_size,
			byte_stream.data(),
			byte_stream.size() );

	// Write the recompiled image.
	//
	image_path.replace_extension( "devirt" + image_path.extension().string() );
	write_raw(
		desc->raw.data(),
		desc->raw.size(),
		image_path.string()
	);
	return 0;
}
