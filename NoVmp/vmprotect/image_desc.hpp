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
#pragma once
#include <vector>
#include <linuxpe>
#include <algorithm>
#include <vtil/arch>
#if defined( _WIN32 )
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

namespace vmp
{
	// Local patch: image byte storage that prefers a private (copy-on-write)
	// file mapping over an in-memory copy. Parallel workers lifting from the
	// same image then share the file's page-cache pages instead of each
	// holding a private heap copy (hundreds of MB per process for modern
	// images). Writes go through copy-on-write; growing the buffer
	// (recompilation) migrates it to an owned vector first.
	//
	struct image_buffer
	{
		std::vector<uint8_t> owned;
		uint8_t* mapped = nullptr;
		size_t mapped_size = 0;

		image_buffer() = default;
		image_buffer( const image_buffer& ) = delete;
		image_buffer& operator=( const image_buffer& ) = delete;
		image_buffer( image_buffer&& o ) noexcept { take( std::move( o ) ); }
		image_buffer& operator=( image_buffer&& o ) noexcept
		{
			release();
			take( std::move( o ) );
			return *this;
		}
		~image_buffer() { release(); }

		void take( image_buffer&& o ) noexcept
		{
			owned = std::move( o.owned );
			mapped = o.mapped;
			mapped_size = o.mapped_size;
			o.mapped = nullptr;
			o.mapped_size = 0;
		}
		void release() noexcept
		{
#if defined( _WIN32 )
			if ( mapped ) UnmapViewOfFile( mapped );
#else
			if ( mapped ) munmap( mapped, mapped_size );
#endif
			mapped = nullptr;
			mapped_size = 0;
			owned.clear();
			owned.shrink_to_fit();
		}

		// Maps the file privately (copy-on-write). Returns false when the
		// file cannot be mapped; callers may fall back to an in-memory copy.
		//
		bool map( const std::string& path )
		{
#if defined( _WIN32 )
			HANDLE fh = CreateFileA( path.c_str(), GENERIC_READ, FILE_SHARE_READ,
									 nullptr, OPEN_EXISTING, 0, nullptr );
			if ( fh == INVALID_HANDLE_VALUE ) return false;
			LARGE_INTEGER sz{};
			if ( !GetFileSizeEx( fh, &sz ) || sz.QuadPart <= 0 ) { CloseHandle( fh ); return false; }
			HANDLE fm = CreateFileMappingA( fh, nullptr, PAGE_WRITECOPY, 0, 0, nullptr );
			CloseHandle( fh );
			if ( !fm ) return false;
			void* p = MapViewOfFile( fm, FILE_MAP_COPY, 0, 0, 0 );
			CloseHandle( fm );
			if ( !p ) return false;
			mapped = ( uint8_t* ) p;
			mapped_size = ( size_t ) sz.QuadPart;
			return true;
#else
			int fd = open( path.c_str(), O_RDONLY );
			if ( fd < 0 ) return false;
			struct stat st{};
			if ( fstat( fd, &st ) != 0 || st.st_size <= 0 ) { close( fd ); return false; }
			void* p = mmap( nullptr, ( size_t ) st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0 );
			close( fd );
			if ( p == MAP_FAILED ) return false;
			mapped = ( uint8_t* ) p;
			mapped_size = ( size_t ) st.st_size;
			return true;
#endif
		}
		void own( std::vector<uint8_t>&& bytes )
		{
			release();
			owned = std::move( bytes );
		}

		bool is_mapped() const { return mapped != nullptr; }
		size_t size() const { return mapped ? mapped_size : owned.size(); }
		uint8_t* data() { return mapped ? mapped : owned.data(); }
		const uint8_t* data() const { return mapped ? mapped : owned.data(); }
		uint8_t& back() { return data()[ size() - 1 ]; }

		// Growing is only needed when recompiling; migrate to an owned buffer
		// so the mapping can be released first.
		//
		void resize( size_t new_size )
		{
			if ( mapped )
			{
				std::vector<uint8_t> copy( mapped, mapped + mapped_size );
				release();
				owned = std::move( copy );
			}
			owned.resize( new_size );
		}
	};

	struct virtual_routine
	{
		uint32_t jmp_rva;
		bool mid_routine;
		vtil::routine* routine = nullptr;
	};

	struct image_desc
	{
		// Basic PE image & details
		//
		image_buffer raw;
		uint64_t override_image_base = 0;

		win::image_x64_t* get_pe_header() { return ( win::image_x64_t* ) raw.data(); }
		win::nt_headers_x64_t* get_nt_headers() { return get_pe_header()->get_nt_headers(); }
		uint64_t get_mapped_image_base() { return get_nt_headers()->optional_header.image_base; }
		uint64_t get_real_image_base() { return override_image_base ? override_image_base : get_mapped_image_base(); }

		template<typename T = void>
		T* rva_to_ptr( uint32_t rva ) { return get_pe_header()->rva_to_ptr<T>( rva ); }
		win::section_header_t* rva_to_section( uint32_t rva ) { return get_pe_header()->rva_to_section( rva ); }

		// List of virtualized routines
		//
		std::vector<virtual_routine> virt_routines;

		// VMProtect specific options.
		//
		bool has_relocs = false;
		bool strip_constant_obfuscation = false;
	};
};