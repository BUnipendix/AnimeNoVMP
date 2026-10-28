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
// Local patch: profile loading (TOML subset parser). See profile.hpp.
//
#include "profile.hpp"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cctype>
#include <cstdio>

namespace vmp
{
	namespace
	{
		std::string trim( const std::string& s )
		{
			size_t a = 0, b = s.size();
			while ( a < b && isspace( ( unsigned char ) s[ a ] ) ) a++;
			while ( b > a && isspace( ( unsigned char ) s[ b - 1 ] ) ) b--;
			return s.substr( a, b - a );
		}

		bool parse_int( const std::string& v, int64_t& out )
		{
			try
			{
				size_t pos = 0;
				out = std::stoll( v, &pos, 0 );
				return pos == v.size();
			}
			catch ( ... ) { return false; }
		}

		// Strips surrounding quotes; handles \" and \\ escapes minimally.
		bool parse_string( const std::string& v, std::string& out )
		{
			if ( v.size() < 2 || v.front() != '"' || v.back() != '"' ) return false;
			out.clear();
			for ( size_t i = 1; i + 1 < v.size(); i++ )
			{
				if ( v[ i ] == '\\' && i + 2 < v.size() )
				{
					char c = v[ ++i ];
					if ( c == '"' ) out += '"';
					else if ( c == '\\' ) out += '\\';
					else return false;
				}
				else
					out += v[ i ];
			}
			return true;
		}

		// ["a", "b", ...]
		bool parse_string_array( const std::string& v, std::vector<std::string>& out )
		{
			if ( v.size() < 2 || v.front() != '[' || v.back() != ']' ) return false;
			std::string body = v.substr( 1, v.size() - 2 );
			if ( trim( body ).empty() ) return true;
			size_t pos = 0;
			while ( pos < body.size() )
			{
				size_t comma = body.find( ',', pos );
				if ( comma == std::string::npos ) comma = body.size();
				std::string item = trim( body.substr( pos, comma - pos ) );
				std::string s;
				if ( !parse_string( item, s ) ) return false;
				out.push_back( s );
				pos = comma + 1;
			}
			return true;
		}

		std::string strip_comment( std::string line )
		{
			bool in_str = false;
			for ( size_t i = 0; i < line.size(); i++ )
			{
				if ( line[ i ] == '"' ) in_str = !in_str;
				else if ( line[ i ] == '#' && !in_str ) return line.substr( 0, i );
			}
			return line;
		}
	}

	bool load_profile( const std::string& path, std::string& error )
	{
		std::ifstream in( path );
		if ( !in.good() )
		{
			error = "cannot open profile file";
			return false;
		}

		profile_t p;
		std::vector<vmenter_shape> shapes;
		std::string line, section;
		int lineno = 0;

		auto fail = [ & ] ( const std::string& why )
		{
			error = "line " + std::to_string( lineno ) + ": " + why;
			return false;
		};

		while ( std::getline( in, line ) )
		{
			lineno++;
			line = trim( strip_comment( line ) );
			if ( line.empty() ) continue;

			// Section headers
			if ( line.front() == '[' )
			{
				bool array_of = line.rfind( "[[", 0 ) == 0;
				std::string close = array_of ? "]]" : "]";
				if ( line.back() != ']' || line.size() < ( array_of ? 4 : 3 ) )
					return fail( "malformed section header" );
				section = line.substr( array_of ? 2 : 1,
									   line.size() - ( array_of ? 4 : 2 ) );
				section = trim( section );
				if ( array_of )
				{
					if ( section != "vmenter.shapes" )
						return fail( "unknown array-of-tables section '" + section + "'" );
					shapes.push_back( {} );
				}
				continue;
			}

			// key = value
			size_t eq = line.find( '=' );
			if ( eq == std::string::npos ) return fail( "expected 'key = value'" );
			std::string key = trim( line.substr( 0, eq ) );
			std::string val = trim( line.substr( eq + 1 ) );
			if ( key.empty() || val.empty() ) return fail( "empty key or value" );

			if ( section == "profile" )
			{
				if ( key == "schema" )
				{
					int64_t v;
					if ( !parse_int( val, v ) ) return fail( "schema must be an integer" );
					if ( v != 1 ) return fail( "unsupported profile schema " + val + " (this build reads schema 1)" );
				}
				else if ( key == "name" )
				{
					if ( !parse_string( val, p.name ) ) return fail( "name must be a string" );
				}
				else return fail( "unknown key '" + key + "' in [profile]" );
			}
			else if ( section == "discovery" )
			{
				if ( key == "sections" )
				{
					p.sections.clear();
					if ( !parse_string_array( val, p.sections ) || p.sections.empty() )
						return fail( "sections must be a non-empty string array" );
				}
				else if ( key == "scan" )
				{
					if ( !parse_string( val, p.discovery_scan ) ) return fail( "scan must be a string" );
					if ( p.discovery_scan != "cross-branch" && p.discovery_scan != "stub-target" )
						return fail( "scan must be \"cross-branch\" or \"stub-target\"" );
				}
				else return fail( "unknown key '" + key + "' in [discovery]" );
			}
			else if ( section == "vmenter" )
			{
				if ( key == "shape" )
				{
					std::string s;
					if ( !parse_string( val, s ) ) return fail( "shape must be a string" );
					if ( s != "multi" )
					{
						// Single-shorthand: shape = "<id>"
						p.vmenter_shapes.clear();
						p.vmenter_shapes.push_back( { s } );
					}
					// "multi" keeps [[vmenter.shapes]] entries (and the
					// classic default only when no shapes table follows).
				}
				else return fail( "unknown key '" + key + "' in [vmenter]" );
			}
			else if ( section == "vmenter.shapes" )
			{
				if ( shapes.empty() ) return fail( "[[vmenter.shapes]] without shape = \"multi\"" );
				if ( key == "id" )
				{
					if ( !parse_string( val, shapes.back().id ) ) return fail( "id must be a string" );
					if ( shapes.back().id.empty() ) return fail( "empty shape id" );
				}
				else return fail( "unknown key '" + key + "' in [[vmenter.shapes]]" );
			}
			else if ( section == "mutation" )
			{
				if ( key == "demutate" )
				{
					if ( val == "true" ) p.mutation_demutate = true;
					else if ( val == "false" ) p.mutation_demutate = false;
					else return fail( "demutate must be true or false" );
				}
				else return fail( "unknown key '" + key + "' in [mutation]" );
			}
			else if ( section == "jump_table" )
			{
				int64_t v;
				if ( key == "entry_size" )
				{
					if ( !parse_int( val, v ) || ( v != 1 && v != 2 && v != 4 && v != 8 ) )
						return fail( "entry_size must be 1, 2, 4 or 8" );
					p.jt_entry_size = ( int ) v;
				}
				else if ( key == "signed" )
				{
					if ( val == "true" ) p.jt_signed = true;
					else if ( val == "false" ) p.jt_signed = false;
					else return fail( "signed must be true or false" );
				}
				else if ( key == "min_targets" )
				{
					if ( !parse_int( val, v ) || v < 1 ) return fail( "min_targets must be >= 1" );
					p.jt_min_targets = ( int ) v;
				}
				else if ( key == "max_entries" )
				{
					if ( !parse_int( val, v ) || v < 1 ) return fail( "max_entries must be >= 1" );
					p.jt_max_entries = ( int ) v;
				}
				else return fail( "unknown key '" + key + "' in [jump_table]" );
			}
			else return fail( "key outside of any section" );
		}

		if ( !shapes.empty() )
		{
			for ( auto& s : shapes )
				if ( s.id.empty() ) return fail( "[[vmenter.shapes]] entry without id" );
			p.vmenter_shapes = shapes;
		}

		// Validate shape ids against what this build knows; unknown ids are a
		// profile error rather than a silent skip.
		for ( auto& s : p.vmenter_shapes )
		{
			if ( s.id != "push-movabs" )
			{
				error = "unknown vmenter shape id '" + s.id + "'";
				return false;
			}
		}
		if ( p.vmenter_shapes.empty() )
		{
			error = "profile selects no vmenter shape";
			return false;
		}

		g_profile = p;
		return true;
	}

	// Local patch: automatic profile selection. See profile.hpp for the
	// decision table; layouts are mutually exclusive so this never guesses.
	//
	bool detect_profile( const std::vector<std::string>& section_names, std::string& error )
	{
		auto has = [ & ] ( const char* name )
		{
			for ( auto& s : section_names )
				if ( s == name )
					return true;
			return false;
		};

		profile_t p;
		if ( has( ".vmp" ) )
		{
			// Classic VMProtect 3.x stock layout — the engine defaults.
			// (leave every field at its default)
		}
		else if ( has( ".upx0" ) && has( ".upx1" ) )
		{
			// Dual-shell era: small launcher image, two packer sections; the
			// stubs are not directly referenced cross-section, so discovery
			// scans the stub shape directly and accepts call targets landing
			// in either shell.
			p.name = "dual-shell";
			p.discovery_scan = "stub-target";
			p.sections = { ".upx0", ".upx1" };
		}
		else if ( has( ".upx0" ) )
		{
			// Merged single-shell era: one packer section holding the whole
			// engine; stubs are reached through ordinary cross-section
			// branches, so the classic discovery works unchanged.
			p.name = "single-shell";
			p.sections = { ".upx0" };
		}
		else
		{
			std::string list;
			for ( auto& s : section_names )
			{
				if ( !list.empty() ) list += ", ";
				list += s;
			}
			error = "unrecognized section layout [" + list +
					"] — no automatic profile matches; pass an explicit -profile";
			return false;
		}
		g_profile = p;
		return true;
	}
}
