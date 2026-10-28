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
#include <functional>
#include <stdexcept> // local patch
#include <map>
#include <set>      // local patch: demutate rules
#include <algorithm>
#include <linuxpe>
#include <vtil/amd64>
#include "image_desc.hpp"
#include "profile.hpp" // local patch: [mutation] demutate

namespace vmp
{
	using namespace vtil::logger;

	using fn_instruction_filter = std::function<bool( const vtil::amd64::instruction& )>;

	struct instruction_stream
	{
		std::vector<std::pair<int, vtil::amd64::instruction>> stream = {};
		instruction_stream() {};

		// std::vector wrappers, stripping the index
		//
		auto& operator[]( size_t n ) const { return stream[ n ].second; }
		size_t size() const { return stream.size(); }

		// Dumps all of the instructions in the stream to a byte array
		//
		std::vector<uint8_t> to_raw()
		{
			// Normalize the stream
			//
			normalize();

			// Linearly decode into a byte array and return
			//
			std::vector<uint8_t> raw_stream;
			for ( auto& p : stream )
				raw_stream.insert( raw_stream.end(), p.second.bytes.begin(), p.second.bytes.end() );
			return raw_stream;
		}
		std::vector<uint8_t> to_raw() const
		{
			return instruction_stream( *this ).to_raw();
		}

		// Merges two instruction streams together
		//
		instruction_stream operator+( const instruction_stream& i2 ) const
		{
			// Merge both instruction streams, remove duplicates.
			//
			instruction_stream out;
			std::map<int, bool> pushed;
			for ( auto& is : { stream, i2.stream } )
			{
				for ( auto& pair : is )
				{
					if ( !pushed[ pair.first ] )
					{
						pushed[ pair.first ] = true;
						out.stream.push_back( pair );
					}
				}
			}

			// Return after sorting by instruction index into the stream
			//
			return out.normalize();
		}

		// Normalizes the instruction stream
		//
		instruction_stream& normalize()
		{
			// Sort according to the original order
			std::sort( stream.begin(), stream.end(), [ ] ( auto& p1, auto& p2 )
			{
				return p1.first <= p2.first;
			} );
			return *this;
		}

		// Traces the register's usage history throughout the instruction stream
		//
		template<bool dump = false>
		std::pair<instruction_stream, std::vector<x86_reg>> trace( x86_reg ireg, int end, int begin = 0 ) const
		{
			std::map<x86_reg, bool> dependencies;
			instruction_stream substream;

			// Trace the instruction upto the beginning of the control flow
			//
			for ( int i = end; i >= begin; i-- )
			{
				auto& ins = stream[ i ].second;

				// Check whether the register is read / written to by this instruction
				//
				uint64_t read = false;
				uint64_t write = false;
				std::vector<x86_reg> access_list;

				for ( int j = 0; j < ins.operands.size(); j++ )
				{
					if ( ins.operands[ j ].type == X86_OP_REG )
					{
						auto reg = ins.operands[ j ].reg;
						if ( vtil::amd64::registers.extend( reg ) != vtil::amd64::registers.extend( ireg ) )
						{
							access_list.push_back( reg );
							continue;
						}
						read |= ins.operands[ j ].access & CS_AC_READ;
						write |= ins.operands[ j ].access & CS_AC_WRITE;
					}
					else if ( ins.operands[ j ].type == X86_OP_MEM )
					{
						for ( auto reg : {
								ins.operands[ j ].mem.base,
								ins.operands[ j ].mem.index } )
						{
							if ( vtil::amd64::registers.extend( reg ) != vtil::amd64::registers.extend( ireg ) )
							{
								access_list.push_back( reg );
								continue;
							}
							read |= ins.operands[ j ].access & CS_AC_READ;
							// Can't read as its writing to memory if WRITE is marked
						}
					}
				}

				// If this instruction writes to this register, log it
				//
				if ( write )
				{
					for ( auto reg : access_list ) dependencies[ reg ] = true;
					substream.stream.push_back( stream[ i ] );

					if constexpr ( dump )
					{
						log<CON_RED>( " %c%c   [[ %p: %s\t%s\n",
										  read ? 'R' : ' ',
										  write ? 'W' : ' ',
										  ins.address, ins.mnemonic.data(), ins.operand_string.data() );
					}
				}

				// If the instruction writes to this register WITHOUT reading it
				// no need to trace any further, return.
				if ( write && !read ) break;
			}

			// Convert to std::vector<>
			std::vector<x86_reg> dependencies_r;
			for ( auto& p : dependencies )
				if ( p.first != X86_REG_INVALID )
					dependencies_r.push_back( p.first );

			// Print dependencies
			if constexpr ( dump )
			{
				log<CON_PRP>( " Depends on: [ " );
				for ( auto reg : dependencies_r )
					log<CON_PRP>( "%s ", vtil::amd64::name( reg ) );
				log<CON_PRP>( "]\n" );
			}

			return { substream.normalize(), dependencies_r };
		}

		// Finds the next/prev matching instruction
		//
		int next( uint32_t instruction_id,
				  const std::vector<x86_op_type>& operands,
				  int from = 0 ) const
		{
			for ( int i = from; i < stream.size(); i++ )
				if ( stream[ i ].second.is( instruction_id, operands ) ) return i;
			return -1;
		}

		int next( const fn_instruction_filter& filter,
				  int from = 0 ) const
		{
			for ( int i = from; i < stream.size(); i++ )
				if ( filter( stream[ i ].second ) ) return i;
			return -1;
		}

		int next( uint32_t instruction_id,
				  const std::vector<x86_op_type>& operands,
				  const fn_instruction_filter& filter,
				  int from = 0 ) const
		{
			for ( int i = from; i < stream.size(); i++ )
				if ( stream[ i ].second.is( instruction_id, operands ) && filter( stream[ i ].second ) ) return i;
			return -1;
		}

		int prev( uint32_t instruction_id, const std::vector<x86_op_type>& operands, int from = -1 ) const
		{
			if ( from == -1 ) from = stream.size() - 1;

			for ( int i = from; i >= 0; i-- )
				if ( stream[ i ].second.is( instruction_id, operands ) ) return i;
			return -1;
		}

		int prev( const fn_instruction_filter& filter,
				  int from = -1 ) const
		{
			if ( from == -1 ) from = stream.size() - 1;

			for ( int i = from; i >= 0; i-- )
				if ( filter( stream[ i ].second ) ) return i;
			return -1;
		}

		int prev( uint32_t instruction_id,
				  const std::vector<x86_op_type>& operands,
				  const fn_instruction_filter& filter,
				  int from = -1 ) const
		{
			if ( from == -1 ) from = stream.size() - 1;

			for ( int i = from; i >= 0; i-- )
				if ( stream[ i ].second.is( instruction_id, operands ) && filter( stream[ i ].second ) ) return i;
			return -1;
		}

		// Deletes first N instructions
		//
		void erase( int n )
		{
			while ( n-- > 0 && !stream.empty() ) stream.erase( stream.begin() );
		}

		// Dumps the given instruction sequence
		//
		std::string to_string() const
		{
			std::string out;
			for ( auto& p : stream )
				out += p.second.to_string() + "\n";
			return out;
		}
	};

	// Local patch: the deobfuscation cache used to live as function-local
	// statics inside deobfuscate(); persistent (stdio) workers reuse the
	// process across many vmenters and the cache would grow without bound.
	// It now lives at namespace scope with an explicit flush hook that the
	// stdio job loop calls between jobs.
	//
	inline std::mutex& deobfuscate_cache_mutex()
	{
		static std::mutex m;
		return m;
	}
	inline std::map<uint32_t, instruction_stream>& deobfuscate_cache()
	{
		static std::map<uint32_t, instruction_stream> cache;
		return cache;
	}
	inline void flush_deobfuscate_cache()
	{
		std::lock_guard g( deobfuscate_cache_mutex() );
		deobfuscate_cache().clear();
	}

	// Local patch (profiles): mutation-layer junk removal, ported from the
	// offline demutate tooling. Four rule families (see [mutation] in the
	// profiles): pure flag noise; paired PUSHFQ/POPFQ saves and the
	// push-R64/xor-[rsp]/pop-R64 sandwich; full-register writes between a
	// matching PUSH R64 ... POP R64 window; full-width stores overwritten by
	// a later full write without an intervening read. Only enabled when the
	// active profile sets [mutation] demutate.
	//
	inline void demutate_stream( instruction_stream& is )
	{
		using ins_t = vtil::amd64::instruction;
		auto& s = is.stream;
		const size_t n = s.size();
		std::vector<bool> keep( n, true );

		static const std::set<uint32_t> pure_flag = {
			X86_INS_CMC, X86_INS_CLC, X86_INS_STC, X86_INS_CLD,
			X86_INS_STD, X86_INS_WAIT, X86_INS_SAHF };
		static const std::set<uint32_t> pure_write = {
			X86_INS_MOV, X86_INS_MOVZX, X86_INS_MOVSX, X86_INS_MOVSXD,
			X86_INS_LEA, X86_INS_POP, X86_INS_MOVABS, X86_INS_CDQE, X86_INS_CWDE,
			X86_INS_SETAE, X86_INS_SETA, X86_INS_SETB, X86_INS_SETBE,
			X86_INS_SETE, X86_INS_SETG, X86_INS_SETGE, X86_INS_SETL,
			X86_INS_SETLE, X86_INS_SETNE, X86_INS_SETNO, X86_INS_SETNS,
			X86_INS_SETO, X86_INS_SETP, X86_INS_SETNP, X86_INS_SETS };
		static const std::set<uint32_t> rmw = {
			X86_INS_AND, X86_INS_OR, X86_INS_XOR, X86_INS_ADD, X86_INS_SUB,
			X86_INS_ADC, X86_INS_SBB, X86_INS_ROL, X86_INS_ROR, X86_INS_RCL,
			X86_INS_RCR, X86_INS_SHL, X86_INS_SHR, X86_INS_SAR, X86_INS_NEG,
			X86_INS_NOT, X86_INS_INC, X86_INS_DEC, X86_INS_BSWAP, X86_INS_XADD,
			X86_INS_SHLD, X86_INS_SHRD };

		// Per-instruction facts.
		struct facts_t
		{
			x86_reg written = X86_REG_INVALID;      // normalized 64-bit
			bool writes_full = false;               // full 64-bit pure write
			bool reads_written = false;             // reads the register it writes (RMW)
			bool reads( x86_reg r ) const { return read_set.count( r ); }
			std::set<x86_reg> read_set;
			bool is_push_reg = false, is_pop_reg = false;
			x86_reg pushed = X86_REG_INVALID;
			bool flow_break = false;                // jmp/cjcc/ret
		};
		std::vector<facts_t> F( n );
		for ( size_t i = 0; i < n; i++ )
		{
			auto& ins = s[ i ].second;
			auto& f = F[ i ];
			for ( auto& op : ins.operands )
			{
				if ( op.type == X86_OP_REG )
				{
					x86_reg ext = vtil::amd64::registers.extend( op.reg );
					if ( op.access & CS_AC_READ ) f.read_set.insert( ext );
					if ( op.access & CS_AC_WRITE ) f.written = ext;
				}
				else if ( op.type == X86_OP_MEM )
				{
					if ( op.mem.base ) f.read_set.insert( vtil::amd64::registers.extend( op.mem.base ) );
					if ( op.mem.index ) f.read_set.insert( vtil::amd64::registers.extend( op.mem.index ) );
				}
			}
			f.reads_written = f.reads( f.written );
			f.writes_full = f.written != X86_REG_INVALID && pure_write.count( ins.id ) &&
							ins.operands.size() && ins.operands[ 0 ].type == X86_OP_REG &&
							ins.operands[ 0 ].size == 8;
			if ( ins.id == X86_INS_PUSH && ins.operands.size() == 1 &&
				 ins.operands[ 0 ].type == X86_OP_REG )
			{
				f.is_push_reg = true;
				f.pushed = vtil::amd64::registers.extend( ins.operands[ 0 ].reg );
			}
			if ( ins.id == X86_INS_POP && ins.operands.size() == 1 &&
				 ins.operands[ 0 ].type == X86_OP_REG )
			{
				f.is_pop_reg = true;
				f.pushed = vtil::amd64::registers.extend( ins.operands[ 0 ].reg );
			}
			f.flow_break = ins.id == X86_INS_RET ||
						   ( ins.mnemonic.size() && ins.mnemonic[ 0 ] == 'j' );
		}

		// Rule 1: pure flag noise.
		for ( size_t i = 0; i < n; i++ )
			if ( pure_flag.count( s[ i ].second.id ) )
				keep[ i ] = false;

		// Rule 2: paired PUSHFQ/POPFQ (flag save/restore) and the
		// push R64; xor/qword [rsp], ..; pop R64 sandwich.
		for ( size_t i = 0; i < n; i++ )
		{
			auto& ins = s[ i ].second;
			if ( ins.id == X86_INS_PUSHFQ )
			{
				for ( size_t j = i + 1; j < n && j <= i + 16; j++ )
				{
					if ( s[ j ].second.id == X86_INS_POPFQ )
					{
						keep[ i ] = keep[ j ] = false;
						break;
					}
					if ( F[ j ].flow_break ) break;
				}
			}
			else if ( F[ i ].is_push_reg && i + 2 < n &&
					  s[ i + 1 ].second.id == X86_INS_XOR &&
					  s[ i + 1 ].second.operands.size() == 2 &&
					  s[ i + 1 ].second.operands[ 1 ].type == X86_OP_MEM &&
					  s[ i + 1 ].second.operands[ 1 ].mem.base == X86_REG_RSP &&
					  F[ i + 2 ].is_pop_reg &&
					  F[ i + 2 ].pushed == F[ i ].pushed )
			{
				keep[ i ] = keep[ i + 1 ] = keep[ i + 2 ] = false;
			}
		}

		// Rule 3: full-register writes between PUSH R64 and its matching
		// POP R64 never escape the window — the pop restores the value.
		for ( size_t i = 0; i < n; i++ )
		{
			if ( !F[ i ].is_push_reg || !keep[ i ] ) continue;
			x86_reg R = F[ i ].pushed;
			for ( size_t j = i + 1; j < n && j <= i + 12; j++ )
			{
				if ( !keep[ j ] ) continue;
				auto& fj = F[ j ];
				if ( fj.is_pop_reg && fj.pushed == R )
				{
					for ( size_t k = i + 1; k < j; k++ )
						if ( keep[ k ] && F[ k ].written != X86_REG_INVALID &&
							 s[ k ].second.id != X86_INS_XOR )
							keep[ k ] = false;
					break;
				}
				if ( fj.flow_break ) break;
			}
		}

		// Rule 4: full-width store to a register overwritten by a later full
		// write without an intervening read of the register.
		for ( size_t i = 0; i < n; i++ )
		{
			if ( !keep[ i ] || !F[ i ].writes_full ) continue;
			x86_reg R = F[ i ].written;
			int seen = 0;
			for ( size_t j = i + 1; j < n && seen < 8; j++ )
			{
				if ( !keep[ j ] ) continue;
				seen++;
				if ( F[ j ].reads( R ) ) break;
				if ( F[ j ].written == R )
				{
					if ( F[ j ].writes_full ) keep[ i ] = false;
					break;
				}
			}
		}

		// Rebuild with survivors, preserving the original unroll indices.
		instruction_stream out;
		for ( size_t i = 0; i < n; i++ )
			if ( keep[ i ] ) out.stream.push_back( s[ i ] );
		size_t removed = n - out.stream.size();
		if ( removed )
			is = std::move( out );
	}

	// Unrolls the entire instruction stream as far as possiblibly predictable statically
	//
	static instruction_stream deobfuscate( image_desc* img, uint32_t rva_rip )
	{
		auto& cache_mutex = deobfuscate_cache_mutex();
		auto& cache = deobfuscate_cache();

		std::lock_guard g( cache_mutex );
		auto& output = cache[ rva_rip ];
		if ( output.stream.size() ) return output;

		// Local patch: rva_rip walks with the control flow; keep the entry
		// point for diagnostics.
		const uint32_t rva_start = rva_rip;

		// For each instruction at the given VA:
		//
		int instruction_idx = 0;
		while ( true )
		{
			// Local patch: bound the unroll. A jmp/call cycle makes this walk forever
			// (each iteration follows the target and only pops the branch itself),
			// which used to show up as a VM that never finishes lifting.
			if ( instruction_idx > 200000 )
				throw std::runtime_error( vtil::format::str(
					"deobfuscate: unroll exceeded 200000 instructions at rva %#x", rva_rip ) );

			// Disassemble the instruction
			//
			// Local patch: a computed branch target can leave every mapped
			// section; rva_to_ptr returns null there and disasm would fault.
			// Report a classified error instead.
			//
			if ( auto* p = img->rva_to_ptr( rva_rip ); !p )
				throw std::runtime_error( vtil::format::str(
					"vmenter: deobfuscation left the image at rva %#x", rva_rip ) );
			std::vector i1 = vtil::amd64::disasm( img->rva_to_ptr( rva_rip ), rva_rip );
			// Local patch: the computed control flow can land on an undecodable
			// byte sequence (jump-into-data or a mis-tracked target). Report a
			// classified error instead of tripping an assertion.
			if ( i1.empty() )
				throw std::runtime_error( vtil::format::str(
					"deobfuscate: undecodable instruction at rva %#x (stream from rva %#x)", rva_rip, rva_start ) );
			vtil::amd64::instruction& instruction = i1[ 0 ];
			output.stream.push_back( { ++instruction_idx, instruction } );

			// Check if control flow deviates
			//
			if ( instruction.is( X86_INS_CALL, { X86_OP_IMM } ) )
				rva_rip = instruction.operands[ 0 ].imm;
			else if ( instruction.is( X86_INS_JMP, { X86_OP_IMM } ) )
				rva_rip = instruction.operands[ 0 ].imm, output.stream.pop_back();
			else if ( instruction.id == X86_INS_JMP || instruction.id == X86_INS_RET )
				break;
			else
				rva_rip += instruction.bytes.size();
		}
		if ( output.stream.empty() ) vtil::logger::error( "Failed to unroll control-flow." );

		// Local patch (profiles): strip the mutation layer's junk when the
		// active profile enables it, before the stream is cached and handed
		// to the parsers.
		//
		if ( !output.stream.empty() && vmp::g_profile.mutation_demutate )
			demutate_stream( output );
		return output;
	}
};