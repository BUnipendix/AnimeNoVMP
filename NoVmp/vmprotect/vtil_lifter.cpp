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
#include "vtil_lifter.hpp"
#include "verbose.hpp"
#include <vector>
#include <string>
#include <cstring>    // jump-table entry reads (local patch)
#include <regex>      // jump-table pattern matching (local patch)
#include <fstream>    // failure evidence dumps (local patch)
#include <filesystem> // failure evidence dumps (local patch)
#include "profile.hpp"
#include "rkey.hpp"
#include "subroutines.hpp"
#include "deobfuscator.hpp"
#include "architecture.hpp"
#include "il2vtil.hpp"
// Local patch: scoped sub-deadline for bounded symbolic refinements.
#include "../../../VTIL-Core/VTIL-Common/util/rtrace-budget.hpp"

// ---- local patch: hard wall-clock budget ------------------------------------
// NoVmp has no bound on how far it explores a VM; a handful of real-world targets
// spin until the outer [timeout] kills them. Fail fast instead so the batch
// keeps moving. Override with NOVMP_TIME_LIMIT=<seconds> (0 = unlimited).
#include <chrono>
#include <cstdlib>
namespace vmp
{
	static std::chrono::steady_clock::time_point g_deadline;
	static bool g_deadline_set = false;
	static inline void vm_check_budget()
	{
		if ( !g_deadline_set )
		{
			g_deadline_set = true;
			const char* e = getenv( "NOVMP_TIME_LIMIT" );
			uint64_t secs = e ? strtoull( e, nullptr, 10 ) : 120;
			if ( secs )
				g_deadline = std::chrono::steady_clock::now() + std::chrono::seconds( secs );
			else
				g_deadline = std::chrono::steady_clock::time_point::max();
		}
		if ( std::chrono::steady_clock::now() > g_deadline )
			throw std::runtime_error( "time budget exceeded (lifter)" );
		// Local patch: honor the scoped refinement sub-deadline too.
		if ( vtil::budget::sub_expired() )
			throw std::runtime_error( "time budget exceeded (bounded refinement)" );
	}

	// Local patch: adaptive refinement slice — never spend more than a quarter
	// of the remaining routine budget on one symbolic refinement, so a routine
	// with many divergent exits still finishes its walk with room for the
	// optimizer. Returns 0 (disarmed) when bounding is disabled or the routine
	// deadline has passed.
	//
	static int64_t refinement_slice_secs()
	{
		int64_t cfg = vtil::budget::refinement_budget_secs();
		if ( cfg <= 0 )
			return 0;
		auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
			g_deadline - std::chrono::steady_clock::now() ).count();
		if ( remaining <= 0 )
			return 0;
		int64_t slice = remaining / 4;
		if ( cfg < slice )
			slice = cfg;
		if ( slice < 1 )
			slice = 1;
		return slice;
	}

	// Local patch: walk-side optional refinements (constant-pool fixing and the
	// block-local optimizer invoked around every vjmp) embed the istack
	// reference tracer, whose forward trace forks into unbounded backward path
	// enumeration on adversarial shell graphs (observed: a certain anime game
	// 7.1.0 — one vjmp's apply_all burned the entire routine budget inside
	// rtrace_primitive while no sub-deadline was armed). Each of these passes is
	// optional — skipping one only costs output quality, never semantics — so
	// they run under the refinement slice and fall back to "keep the block as
	// emitted" on divergence. A latch disables a pass for the rest of the walk
	// once it diverges twice: routines that never diverge are byte-identical to
	// the unbounded behaviour, only pathological walks change. Reset per routine.
	//
	struct walk_latch_t
	{
		int fcp_divergences = 0;
		int opt_divergences = 0;
		int branch_divergences = 0;
		int exit_divergences = 0;
		bool fcp_disabled = false;
		bool opt_disabled = false;
		bool branch_disabled = false;
		bool exit_disabled = false;
	};
	static thread_local walk_latch_t walk_latch;

	// Runs a walk-side optional refinement under the refinement slice; returns
	// whether it ran to completion, false when skipped (latched) or diverged.
	//
	template <typename F>
	static bool bounded_optional( int& div_count, bool& disabled, const char* what, vtil::vip_t vip, F&& fn )
	{
		if ( disabled )
			return false;
		try
		{
			vtil::budget::scoped_sub_deadline sd( refinement_slice_secs() );
			fn();
			return true;
		}
		catch ( std::runtime_error& e )
		{
			if ( !strstr( e.what(), "bounded refinement" ) ) throw;
			if ( ++div_count >= 2 )
				disabled = true;
			log( "[!] %s diverged @vip %#llx — skipping (optional refinement)\n",
				 what, ( unsigned long long ) vip );
			// A pass unwound mid-rewrite may have invalidated block iterators
			// the simplifier cache still references.
			vtil::symbolic::purge_simplifier_state();
			return false;
		}
	}
	// Local patch: the deadline is per virtual routine, not per process — a
	// one-shot batch handling many -vms entries (or any long-lived caller)
	// would otherwise starve every routine after the first NOVMP_TIME_LIMIT
	// seconds of process lifetime. Call at each routine boundary.
	//
	void reset_time_budget() { g_deadline_set = false; }
	void reset_walk_latch() { walk_latch = {}; }
}
// ---- end local patch --------------------------------------------------------

#define DISCOVERY_VERBOSE_OUTPUT 0

namespace vmp
{
	vtil::basic_block* lift_il( vtil::basic_block* block, vm_state* vstate )
	{
		// Local patch: check here too - paths that hit an already-explored block return
		// before the main loop, and those were the ones that could spin forever.
		vm_check_budget();
		const auto fix_constant_pool = [ & ] ()
		{
			// Fix stack access to avoid trace cost.
			//
			vtil::optimizer::stack_pinning_pass{}( block );
			vtil::optimizer::istack_ref_substitution_pass{}( block );

			// Reloc base is always at the top of virtual stack upon block begin,
			// create the base-address offset evaluator using it.
			//
			vtil::symbolic::pointer reloc_base =
				vtil::symbolic::variable{ block->begin(), vtil::REG_SP }.to_expression();
			auto eval = [ & ] ( const vtil::symbolic::unique_identifier& uid )
				-> std::optional<uint64_t>
			{
				auto& var = uid.get<vtil::symbolic::variable>();
				if ( var.is_register() && var.reg().is_image_base() )
					return 0;
				if ( var.is_memory() && ( var.mem().base - reloc_base ) == 0 )
					return ( uint64_t ) -( int64_t ) vstate->img->get_real_image_base();
				return std::nullopt;
			};

			// For each LDD:
			//
			vtil::cached_tracer tracer{};
			for ( auto it = block->begin(); it != block->end(); it++ )
			{
				if ( it->base != &vtil::ins::ldd )
					continue;
				auto [base, off] = it->memory_location();
				if ( base.is_stack_pointer() )
					continue;
        
				// If it evaluates to constant delta from base:
				//
				if ( auto res = tracer( { it, base } )->evaluate( eval ); res.is_known() )
				{
					uint64_t rva = *res.get() + off;
					if ( !vstate->img->has_relocs ) rva -= vstate->img->get_real_image_base();

					// If in a read-only section:
					//
					if ( auto section = vstate->img->rva_to_section( rva ) )
					{
						if ( !section->characteristics.mem_write )
						{
							// Replace with MOV.
							//
							uint64_t value = 0;

							memcpy(
								&value,
								vstate->img->rva_to_ptr( rva ),
								it->access_size() / 8
							);

							( +it )->base = &vtil::ins::mov;
							( +it )->operands = { it->operands[ 0 ], vtil::operand{ value, it->access_size() } };
						}
					}
				}
			}
		};


		// If virtual instruction pointer is not set:
		//
		if ( !vstate->vip )
		{
			// Parse VMENTER:
			//
			auto [entry_stack, entry_vip] = parse_vmenter( vstate, vstate->current_handler_rva );
			auto blk_caller = block;
			entry_vip += ( vstate->dir_vip < 0 ? -1 : 0 );

			// Begin block if none passed.
			//
			if ( !block )
			{
				block = vtil::basic_block::begin( entry_vip );
			}
			// Otherwise, fork the block.
			//
			else
			{
				auto new_block = block->fork( entry_vip );
				// If returned nullptr, it's already explored, skip.
				//
				if ( !new_block )
				{
					std::lock_guard g( block->owner->mutex );
					block = block->owner->explored_blocks[ entry_vip ];
					fassert( block );
					// TODO: Trace possible exits once more ?.
					//
					return block;
				}
				block = new_block;
			}

			// Insert push instructions.
			//
			for ( auto& op : entry_stack )
				block->push( op );

			// Push relocation offset.
			//
			auto treloc = block->tmp( 64 );
			block->mov( treloc, vtil::REG_IMGBASE )
				 ->sub( treloc, vstate->img->get_real_image_base() )
				 ->push( treloc );
		}
		else
		{
			// If passed block is nullptr, it's already explored, skip.
			//
			if ( !block ) return nullptr;
		}

		bool handled_any = false;
		while ( 1 )
		{
			vm_check_budget();
			// Local patch: verbose evidence — the (vip -> handler) walk, so vip
			// drift can be located as the first handler landing outside the
			// packer sections (or an erratic delta).
			dprintf( "[walk] vip=%#llx handler=%#x dir=%d\n",
					 ( unsigned long long ) vstate->vip, vstate->current_handler_rva, ( int ) vstate->dir_vip );
			bool handler_in_vm_scn = false;
			if ( auto* hscn = vstate->img->rva_to_section( vstate->current_handler_rva ) )
			{
				for ( const auto& prefix : section_prefixes )
					if ( !memcmp( prefix.data(), &hscn->name.short_name[ 0 ], prefix.size() ) )
					{
						handler_in_vm_scn = true;
						break;
					}
			}
			if ( !handler_in_vm_scn )
			{
				// Local patch: an unresolvable next handler (vip drift through
				// a mis-parsed vmswap, or a runtime-computed dispatch) used to
				// kill the whole routine. The completed blocks are still valid
				// work, so model the hand-off as an unknown destination and
				// stop lifting this path only — the same philosophy as the
				// jump-table-out-of-VM and stack-indirect modeling. Guarded on
				// having completed at least one handler here: an entry whose
				// very first handler is garbage stays a hard failure.
				if ( handled_any || !block->prev.empty() )
				{
					log( "[!] unmapped handler %#x after vip %#llx — modeling as vexit\n",
						 vstate->current_handler_rva, ( unsigned long long ) vstate->vip );
					block->jmp( vtil::invalid_vip );
					return block;
				}
				// TODO: Whoooops.
				//
				// Local patch: the upstream debug dump indexes prev[0] without
				// checking — an entry whose very first handler lands outside
				// the VM sections reaches this path with an empty prev vector
				// (observed: running without section configuration on a
				// single-shell image) and crashes instead of reporting.
				if ( !block->prev.empty() )
					vtil::debug::dump( block->prev[ 0 ] );
				throw std::runtime_error( "Whoooops invalid virtual jump." );
			}

			try
			{
				// Unroll the stream
				//
				dprintf( "[dbg] step: unroll start\n" );
				instruction_stream is = vstate->unroll();
				dprintf( "[dbg] step: unroll done\n" );

				// Resolve self-referencing point and decryption blocks
				//
				std::optional self_ref_point = find_self_ref( vstate, is );
				std::vector rkblocks = extract_rkey_blocks( vstate, is );

				// If handler has a self referencing point (X: LEA r64, [X]), handle VM swap
				// 
				instruction_stream prefixss;
				if ( self_ref_point.has_value() )
				{
					// Parse the new VM state
					//
					rkblocks = parse_vmswap( vstate, is, prefixss );
				}

				// If instruction has no decryption blocks, handle VM exit / external call
				//
				if ( rkblocks.empty() )
				{
					const auto is_rva_in_vmp_scn = [ & ] ( uint32_t rva )
					{
						auto section = vstate->img->rva_to_section( rva );
						if ( !section ) return false;

						if ( vstate->img->rva_to_section( rva ) ==
							 vstate->img->rva_to_section( vstate->current_handler_rva ) )
							return true;

						for ( const auto& prefix : section_prefixes )
							if ( !memcmp( prefix.data(), &section->name.short_name[0], prefix.size() ) )
								return true;

						return false;
					};

					// Parse VMEXIT to resolve the order registers are popped
					//
					std::vector exit_stack = parse_vmexit( vstate, is );

					// Simulate the VPOP for each register being popped in the routine
					//
					for ( auto& op : exit_stack )
						block->pop( op );

					// Pop target from stack.
					//
					vtil::operand jmp_dest = block->tmp( 64 );
					block->pop( jmp_dest );

					// Insert vexit to the location.
					//
					block->vexit( jmp_dest );

					// Remove constant obfuscation.
					//
					if ( vstate->img->strip_constant_obfuscation )
						bounded_optional( walk_latch.fcp_divergences, walk_latch.fcp_disabled, "constant-pool fix",
										  vstate->vip, [ & ] { fix_constant_pool(); } );

					// Pass the current block through optimization.
					//
					jmp_dest = block->back().operands[ 0 ];

					// Determine current stack offset.
					//
					vtil::tracer tracer;
					// Local patch: bounded refinement rtrace. The exit-path refinements
					// below rtrace backwards through the whole block history; on giant
					// routines (observed: 15k-handler walks) the trace diverges and eats
					// the entire routine budget, discarding every already-lifted handler.
					// Each refinement is optional — on divergence the sentinel expression
					// keeps the flow on the default path, so the block keeps its symbolic
					// vexit(jmp_dest): the faithful model of a runtime-computed exit.
					//
					const auto bounded_rtrace_p = [ & ] ( const vtil::symbolic::variable& lookup, bool* diverged = nullptr )
						-> vtil::symbolic::expression::reference
					{
						// Local patch: exit-refinement latch. A routine whose exit
						// refinements diverge repeatedly is pathological — each
						// further divergence costs a full refinement slice only to
						// end at the same sentinel (observed: 22 divergent exits
						// burning ~220 s of a 300 s budget on a certain anime game
						// 4.8.0). Once latched, later exits still get a 1 s short
						// slice: resolvable exits (typically sub-second) keep
						// resolving, divergent ones cost a second instead of the
						// full slice.
						//
						const bool latched = walk_latch.exit_disabled;
						try
						{
							vtil::budget::scoped_sub_deadline sd( latched ? 1 : refinement_slice_secs() );
							return tracer.rtrace_p( lookup );
						}
						catch ( std::runtime_error& e )
						{
							if ( !strstr( e.what(), "bounded refinement" ) ) throw;
							if ( diverged ) *diverged = true;
							if ( ++walk_latch.exit_divergences >= 4 && !walk_latch.exit_disabled )
							{
								walk_latch.exit_disabled = true;
								log( "[!] exit refinements diverging repeatedly @vip %#llx — degrading to short slices\n",
									 ( unsigned long long ) vstate->vip );
							}
							log( "[!] vmexit rtrace diverged @vip %#llx — keeping symbolic vexit\n",
								 ( unsigned long long ) vstate->vip );
							// Sentinel: the image-base variable. Read-only registers are
							// valid without an iterator and cannot be resolved by joins,
							// so the sentinel never triggers a backward search.
							return vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression();
						}
					};
					auto stack_0 = vtil::symbolic::variable{ block->owner->entry_point->begin(), vtil::REG_SP }.to_expression();
					bool sp_diverged = false;
					auto stack_1 = bounded_rtrace_p( { std::prev( block->end() ), vtil::REG_SP }, &sp_diverged ) + block->sp_offset;
					// Local patch: on divergence skip every exit refinement. The
					// offset arithmetic below would otherwise join the sentinel with
					// the entry SP variable and diverge inside the simplifier's join
					// machinery — the same pathology the bounded rtrace just escaped.
					// The block keeps its symbolic vexit(jmp_dest).
					//
					if ( sp_diverged )
						break;
					auto offset = stack_1 - stack_0;
	#if DISCOVERY_VERBOSE_OUTPUT
					log( "sp offset => %s\n", offset.to_string() );
	#endif

					// If stack offset is non-const or [Offset < 0]:
					//
					if ( !offset.is_constant() || *offset.get<true>() < 0 )
					{
						// Try to read from the top of the stack.
						//
						// Local patch: the whole refinement is bounded — the inner
						// forward trace of SP diverges on giant blocks just like the
						// backward one; on divergence the sentinel keeps the flow on
						// the default symbolic-vexit path.
						//
						auto continue_from = [ & ]()
						{
							try
							{
								vtil::budget::scoped_sub_deadline sd( refinement_slice_secs() );
								return ( bounded_rtrace_p( { std::prev( block->end() ),
													   { tracer( { std::prev( block->end() ), vtil::REG_SP } ) + block->sp_offset, 64 } } ) -
													   (vstate->img->has_relocs ? vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression() : vtil::symbolic::expression{ vstate->img->get_real_image_base() })).simplify( true );
							}
							catch ( std::runtime_error& e )
							{
								if ( !strstr( e.what(), "bounded refinement" ) ) throw;
								log( "[!] vmexit continue rtrace diverged @vip %#llx — keeping symbolic vexit\n",
									 ( unsigned long long ) vstate->vip );
								return ( vtil::symbolic::expression_reference{ vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression() } -
													   (vstate->img->has_relocs ? vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression() : vtil::symbolic::expression{ vstate->img->get_real_image_base() })).simplify( true );
							}
						}( );
	#if DISCOVERY_VERBOSE_OUTPUT
						log( "continue => %s\n", continue_from.to_string() );
	#endif
						// If constant and is in VMP section:
						//
						if ( continue_from.is_constant() && is_rva_in_vmp_scn( *continue_from.get() ) )
						{
							// If return address points to a PUSH IMM32, aka VMENTER.
							//
							auto disasm = deobfuscate( vstate->img, *continue_from.get() );
							if ( disasm.size() && disasm[ 0 ].is( X86_INS_PUSH, { X86_OP_IMM } ) )
							{
								// Convert into vxcall and indicate that push is implicit by
								// shifting the stack pointer.
								//
								block->wback().base = &vtil::ins::vxcall;
								block->wback().vip = vstate->vip;
								block->shift_sp( 8, false, block->end() );

								/* TODO:
								// Check if it's alloca_probe inserted by the compiler, in which case we can ignore
								// and should be preserving RAX
								//
								if ( ret_rva )
								{
									// Try to identify ALLOCA probe
									//
									instruction_stream is = unroll_stream( vstate->img, ret_rva );
									if ( is.size() &&
										 is[ 0 ].is( X86_INS_SUB, { X86_OP_REG, X86_OP_IMM } ) &&
										 is[ 0 ].operands[ 1 ].imm == 0x10 )
									{
										// Try to evaluate EAX into a constant
										//
										mlil::symbol_map sym_rax;
										expression_old::instance exp_rax = mlf->trace( mlil::operand{ X86_REG_RAX }, &sym_rax ).value;
										std::optional<uint64_t> val_rax;
										if ( exp_rax )
										{
											if ( auto res = expression_old::simplify( exp_rax )->evaluate() )
												val_rax = res.value().u64;
										}

										// If rax does indeed evaluate to a constant value
										//
										if ( val_rax.has_value() )
										{
											// Skip the VXCALL that would be appended to the stream and go straight to the parsing of VMENTER
											//
											for ( x86_reg reg : parse_vmenter( vstate, xret_rva ) )
											{
												// Declare RAX preserved
												//
												if ( reg == X86_REG_RAX )
												{
													mlf->mov( mlil::operand{ X86_REG_RAX }, mlil::make_const( val_rax.value() ) );
													mlf->push( mlil::make_const( val_rax.value() ) );
												}
												else
												{
													mlf->push( mlil::operand( reg ) );
												}
											}

											// Continue parsing as usual
											//
											io::log<CON_RED>( "Processed vmexit-vmenter chain [_alloca_probe()]...\n" );
											continue;
										}
									}
								}
								*/

								// Continue lifting from the linked virtual machine.
								//
								vm_state state = { vstate->img, *continue_from.get() };
								lift_il( block, &state );
								break;
							}
						}
					}

					// Reached real exit, determine destination.
					//
					// Local patch: the exit-destination refinement is bounded as a
					// whole — subtracting the image base and simplifying a huge trace
					// result diverges in the join machinery just like the rtrace
					// itself. On divergence keep the symbolic vexit.
					//
					bool exit_diverged = false;
					auto exit_destination = jmp_dest.is_immediate()
						? vtil::symbolic::expression{ jmp_dest.imm().u64, jmp_dest.bit_count() }
						: [ & ] ( bool* diverged )
						  {
							// Local patch: exit-refinement latch (see bounded_rtrace_p):
							// once tripped, a 1 s short slice instead of the full one.
							//
							const bool latched = walk_latch.exit_disabled;
						try
						{
							vtil::budget::scoped_sub_deadline sd( latched ? 1 : refinement_slice_secs() );
							return ( tracer.rtrace_p( { std::prev( block->end() ), jmp_dest.reg() } ) -
									 (vstate->img->has_relocs ? vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression() : vtil::symbolic::expression{ vstate->img->get_real_image_base() })).simplify( true );
						}
						catch ( std::runtime_error& e )
						{
							if ( !strstr( e.what(), "bounded refinement" ) ) throw;
							*diverged = true;
							if ( ++walk_latch.exit_divergences >= 4 && !walk_latch.exit_disabled )
							{
								walk_latch.exit_disabled = true;
								log( "[!] exit refinements diverging repeatedly @vip %#llx — degrading to short slices\n",
									 ( unsigned long long ) vstate->vip );
							}
							log( "[!] vmexit exit rtrace diverged @vip %#llx — keeping symbolic vexit\n",
								 ( unsigned long long ) vstate->vip );
							return ( vtil::symbolic::expression_reference{ vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression() } -
									 (vstate->img->has_relocs ? vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression() : vtil::symbolic::expression{ vstate->img->get_real_image_base() })).simplify( true );
						}
						  }( &exit_diverged );
					if ( exit_diverged )
						break;
	#if DISCOVERY_VERBOSE_OUTPUT
					log( "exit => %s\n", exit_destination.to_string() );
	#endif

					// If constant and is in VMP section:
					//
					if ( exit_destination.is_constant() && is_rva_in_vmp_scn( *exit_destination.get() ) )
					{
						// Pop the VMEXIT.
						//
						block->pop_back();

						// Extract the non-virtualized chunk before VMENTER.
						//
						auto is = deobfuscate( vstate->img, *exit_destination.get() );

						instruction_stream non_virt_chunk = {};
						while ( true )
						{
							if ( is.size() <= 1 )
							{
								block->vexit( *exit_destination.get() );
								return block;
							}

							if ( is[ 0 ].is( X86_INS_PUSH, { X86_OP_IMM } ) &&
								 is[ 1 ].is( X86_INS_CALL, { X86_OP_IMM } ) )
								break;
							else
								non_virt_chunk.stream.push_back( is.stream[ 0 ] );
							is.erase( 1 );
						}

						// Insert VPINR->VEMIT->VPINW stream.
						//
						for ( auto& [id, ins] : non_virt_chunk.stream )
						{
							if ( ins.is( X86_INS_PUSHFQ, {} ) )
							{
								block->pushf();
								continue;
							}
							else if ( ins.is( X86_INS_POPFQ, {} ) )
							{
								block->popf();
								continue;
							}

							for ( auto reg_read : ins.regs_read )
							{
								vtil::operand op = x86_reg( reg_read );
								if ( reg_read == X86_REG_RSP ) op = { vtil::REG_SP };
								if ( reg_read == X86_REG_EFLAGS ) op = { vtil::REG_FLAGS };
								block->vpinr( op );
							}

							for ( uint8_t byte : ins.bytes )
								block->vemit( byte );

							for ( auto reg_write : ins.regs_write )
							{
								vtil::operand op = x86_reg( reg_write );
								fassert( reg_write != X86_REG_RSP );
								if ( reg_write == X86_REG_EFLAGS ) op = { vtil::REG_FLAGS };
								block->vpinw( op );
							}
						}

						// Insert a dummy JMP.
						//
						block->jmp( vtil::invalid_vip );

						// Continue lifting from the linked virtual machine.
						//
						vm_state state = { vstate->img, is[ 0 ].address };
						auto block_next = lift_il( block, &state );
					
						// Replace the destination of the jump.
						//
						block->wback().operands[ 0 ] = { block_next->entry_vip, 64 };
						break;
					}

					// Break out of the lifter loop.
					//
					break;
				}

				// Assert we have valid decryption blocks
				//
				fassert( !rkblocks.empty() );
				fassert( rkblocks.back().output_size == 4 );

				// Decrypt all parameters for the instruction
				//
				vtil::vip_t vip_params = vstate->vip;
				std::vector<std::pair<rkey_block*, rkey_value>> parameters;
				for ( rkey_block& rkblock : rkblocks )
					parameters.push_back( { &rkblock, vstate->decrypt_vip( rkblock ) } );

				// Reduce the instruction handler chunk, classify the IL instruction associated
				//
				dprintf( "[dbg] step: reduce start\n" );
				reduce_chunk( vstate, is, parameters );
				dprintf( "[dbg] step: reduce done\n" );
				is.stream.insert( is.stream.begin(), prefixss.stream.begin(), prefixss.stream.end() );
				dprintf( "[dbg] step: classify start\n" );
				arch::instruction il_instruction = arch::classify( vstate, is );
				dprintf( "[dbg] step: classify done\n" );

				// If there was a self-reference point in the handler
				//
				if ( self_ref_point.has_value() )
				{
					// Handle nop:
					//
					if( il_instruction.op == "VNOP" )
					{
						// Insert jump to VIP+$.
						//
						vtil::vip_t dst = vip_params + ( vstate->dir_vip < 0 ? -1 : 0 );
						block->jmp( dst );

						// Remove constant obfuscation.
						//
						if ( vstate->img->strip_constant_obfuscation )
							bounded_optional( walk_latch.fcp_divergences, walk_latch.fcp_disabled, "constant-pool fix",
											  vstate->vip, [ & ] { fix_constant_pool(); } );

						// Pass the current block through optimization.
						//
						//block->owner->local_opt_count += vtil::optimizer::apply_all( block ); // OPTIMIZER

						// Fork the current flow and parse as a seperate block.
						//
						vstate->next( rkblocks.back(), vip_params, self_ref_point.value() );
						lift_il( block->fork( dst ), vstate );
						return block;
					}
					else if ( il_instruction.op == "VJMP" )
					{
						// Pop target from stack.
						//
						auto jmp_dest = block->tmp( 64 );
						block->pop( jmp_dest );

						if ( vstate->dir_vip < 0 )
							block->sub( jmp_dest, 1 );

						// If relocs stripped, substract image base, uses absolute address.
						//
						if( !vstate->img->has_relocs )
							block->sub( jmp_dest, vstate->img->get_real_image_base() );
					
						// Insert jump to the location.
						//
						block->jmp( jmp_dest );

						// Remove constant obfuscation.
						//
						if ( vstate->img->strip_constant_obfuscation )
							bounded_optional( walk_latch.fcp_divergences, walk_latch.fcp_disabled, "constant-pool fix",
											  vstate->vip, [ & ] { fix_constant_pool(); } );

						// Pass the current block through optimization.
						//
						bounded_optional( walk_latch.opt_divergences, walk_latch.opt_disabled, "block optimization",
										  vstate->vip, [ & ] { block->owner->local_opt_count += vtil::optimizer::apply_all( block ); } );

						// Allocate an array of resolved destinations.
						//
						vtil::/*cached_*/tracer tracer = {};
						std::vector<vtil::vip_t> destination_list;
						uint64_t image_base = vstate->img->has_relocs ? 0 : vstate->img->get_real_image_base();
						// Local patch: analyze_branch forward-traces the whole block
						// through the istack tracer and diverges exactly like the
						// optimizer passes above on adversarial graphs. Bounded the
						// same way — an empty destination set leaves the symbolic
						// jump in place (the faithful runtime-dispatch model).
						//
						vtil::optimizer::aux::branch_info branch_info{};
						bounded_optional( walk_latch.branch_divergences, walk_latch.branch_disabled, "branch analysis",
										  vstate->vip, [ & ]
						{
							branch_info = vtil::optimizer::aux::analyze_branch( block, &tracer, { .pack = true } );
						} );

						// ---- local patch: VMProtect jump-table (switch) resolution ----
						// Upstream NoVmp throws "Whoooops hit switch case..." whenever a VJMP target
						// cannot be constant-folded. In VMProtect 3.x that is the classic relative
						// jump table, which VTIL's own printer renders as:
						//   ((0x<addend>+&&base)+__ucast(dword[((0x<table_rva>+&&base)+(idx<<0x2))]...))
						// i.e.  target_rva = addend + (int32)table[i]
						// We recover <addend>/<table_rva> from that string, read the table straight
						// out of the image, and fork the lift into every valid target. If anything
						// does not validate we do nothing and the original throw still happens.
						//
						const auto try_jump_table = [ & ] ( const vtil::symbolic::expression::reference& ex ) -> bool
	{
	    // VMProtect relative jump table. VTIL prints it as e.g.
	    //   (0x39118bf+(__ucast(dword[((0x64014ee+&&base)+(idx<<0x2))]...,0x40)|-0x100000000))
	    // i.e. target = addend + table[i], table at rva table_rva.
	    // The addend is not always tagged with &&base, so instead of exact-matching the
	    // shape we take every hex constant in the string as a candidate addend and keep
	    // whichever one makes ALL table entries land in executable sections.
	    // Local patch (profiles): entry width / signedness / thresholds come from the
	    // active profile; the opposite signedness is still tried as a fallback.
	    std::string es = ex->to_string();

	    const char* width_name = g_profile.jt_entry_size == 1 ? "byte"
	                           : g_profile.jt_entry_size == 2 ? "word"
	                           : g_profile.jt_entry_size == 8 ? "qword"
	                           : "dword";
	    std::smatch mt;
	    const std::regex re_tab( std::string( width_name ) + R"(\[\(\((0x[0-9a-fA-F]+))" );
	    if ( !std::regex_search( es, mt, re_tab ) ) return false;
	    uint64_t table_rva = std::stoull( mt[ 1 ].str(), nullptr, 16 );

	    auto* tscn = vstate->img->rva_to_section( ( uint32_t ) table_rva );
	    if ( !tscn ) return false;
	    uint64_t scn_off = table_rva - tscn->virtual_address;
	    if ( scn_off + g_profile.jt_entry_size > tscn->size_raw_data ) return false;
	    uint8_t* ent_base = vstate->img->rva_to_ptr<uint8_t>( ( uint32_t ) table_rva );
	    if ( !ent_base ) return false;
	    size_t max_entries = ( tscn->size_raw_data - scn_off ) / g_profile.jt_entry_size;
	    if ( max_entries > ( size_t ) g_profile.jt_max_entries ) max_entries = g_profile.jt_max_entries;

	    static const std::regex re_hex( R"(0x[0-9a-fA-F]+)" );
	    std::vector<uint64_t> cands;
	    for ( std::sregex_iterator it( es.begin(), es.end(), re_hex ), end; it != end; ++it )
	    {
	        uint64_t v = std::stoull( ( *it )[ 0 ].str(), nullptr, 16 );
	        if ( v != table_rva ) cands.push_back( v );
	    }
	    std::sort( cands.begin(), cands.end() );
	    cands.erase( std::unique( cands.begin(), cands.end() ), cands.end() );

	    uint64_t image_base = vstate->img->has_relocs ? 0 : vstate->img->get_real_image_base();
	    std::vector<vtil::vip_t> targets;
	    for ( uint64_t addend : cands )
	    {
	        // Profile signedness first, the opposite as a fallback.
	        for ( int variant = 0; variant < 2; variant++ )
	        {
	            bool as_signed = variant == 0 ? g_profile.jt_signed : !g_profile.jt_signed;
	            targets.clear();
	            for ( size_t i = 0; i < max_entries; i++ )
	            {
	                uint64_t val = 0;
	                std::memcpy( &val, ent_base + i * g_profile.jt_entry_size, g_profile.jt_entry_size );
	                if ( as_signed )
	                {
	                    if ( g_profile.jt_entry_size == 1 ) val = ( uint64_t ) ( int64_t ) ( int8_t ) val;
	                    else if ( g_profile.jt_entry_size == 2 ) val = ( uint64_t ) ( int64_t ) ( int16_t ) val;
	                    else if ( g_profile.jt_entry_size == 4 ) val = ( uint64_t ) ( int64_t ) ( int32_t ) val;
	                }
	                uint64_t tgt = addend + image_base + val;
	                auto* scn = vstate->img->rva_to_section( ( uint32_t ) tgt );
	                if ( !scn || !scn->characteristics.mem_execute ) break;
	                targets.push_back( tgt );
	            }
	            if ( targets.size() >= ( size_t ) g_profile.jt_min_targets ) break;
	        }
	        if ( targets.size() >= ( size_t ) g_profile.jt_min_targets ) break;
	    }
	    if ( targets.size() < ( size_t ) g_profile.jt_min_targets ) return false;

	    // Figure out whether these targets are VM bytecode (fork the lift) or native
	    // code (the VM is dispatching out of itself -> model it as a vexit).
	    auto* vm_scn = vstate->img->rva_to_section( ( uint32_t ) vstate->vip );
	    bool all_in_vm = vm_scn != nullptr;
	    for ( auto t : targets )
	        if ( vstate->img->rva_to_section( ( uint32_t ) t ) != vm_scn )
	            all_in_vm = false;

	    if ( !all_in_vm )
	    {
	        log( "[+] jump table @rva %#x: %zu targets, dispatching OUT of the VM -> vexit\n",
	             table_rva, targets.size() );
	                // The block already ends with a symbolic jmp to the computed table entry
	        // (emitted before analyze_branch), which faithfully models a native
	        // jump-table dispatch. There is nothing further to lift on this path.
	        return true;
	    }

	    log( "[+] jump table @rva %#x: %zu targets, forking\n", table_rva, targets.size() );
	    for ( auto t : targets ) destination_list.push_back( t );
	    return true;
	};
							// ---- local patch: shared branch-fork validation ----
							// Section of the current VIP and a probe-based validator shared
							// by the flag-bit and fixed-slot branch forks below.
							auto* vm_scn = vstate->img->rva_to_section( ( uint32_t ) vstate->vip );
							const auto peek_ok = [ & ] ( uint64_t c ) -> bool
							{
								if ( !vm_scn ) return false;
								auto* scn = vstate->img->rva_to_section( ( uint32_t ) c );
								if ( !scn || scn != vm_scn ) return false;
								if ( rkblocks.empty() || !self_ref_point.has_value() ) return true;  // nothing to probe with; keep old behavior
								try
								{
									vm_state probe = *vstate;
									uint32_t cand = ( uint32_t ) c;
									probe.next( rkblocks.back(), cand + ( vstate->dir_vip < 0 ? +1 : 0 ), self_ref_point.value() );
									auto* hscn = vstate->img->rva_to_section( probe.current_handler_rva );
									if ( !hscn ) return false;
									// The next handler must live in a VM (packer) section, not merely
									// anywhere mapped — a wrong fork VIP decrypts a garbage offset
									// that folds into native code and the walk dies far away
									// (observed: rva 0x3de1d83, native il2cpp region).
									for ( const auto& prefix : section_prefixes )
										if ( !memcmp( prefix.data(), &hscn->name.short_name[ 0 ], prefix.size() ) )
											return true;
									return false;
								}
								catch ( ... )
								{
									return false;
								}
							};
							// ---- local patch: flag-bit conditional branches ----
							// Live-sample evidence (failures/*.switch-case.txt and the
							// runtime VJMP dumps): the VM encodes two-way branches as
							//     destination = A + (COND ? K)
							// where COND is undecidable symbolically (flag-bit tests,
							// register sign tests, bit tests on stack values) but K
							// is a conditional constant in VA space and A the base in
							// RVA space — both outcomes are concrete addresses. Fork
							// both; the optimizer prunes whichever path is dead later.
							const auto try_flag_branch = [ & ] ( const vtil::symbolic::expression::reference& ex ) -> bool
	{
	    std::string es = ex->to_string();

	    // Collect every conditional constant in the expression, not just the
	    // first: the two-way encodings observed in the wild are
	    //     dst = A + (COND ? K)                    [single select]
	    //     dst = (COND1 ? K1) + (COND2 ? K2) + C   [select pair, 6.6.0+]
	    // so one branch expression can carry two distinct destinations.
	    std::vector<uint64_t> cands;
	    static const std::regex re_k( R"(\?\(?(0x[0-9a-fA-F]+)\)?\))" );
	    for ( std::sregex_iterator it( es.begin(), es.end(), re_k ), end; it != end; ++it )
	    {
	        uint64_t k = std::stoull( ( *it )[ 1 ].str(), nullptr, 16 );
	        cands.push_back( k );
	        cands.push_back( k - vstate->img->get_real_image_base() );
	    }
	    std::smatch ma;
	    static const std::regex re_lead( R"(^\((-?0x[0-9a-fA-F]+)\+)" );
	    if ( std::regex_search( es, ma, re_lead ) )
	        cands.push_back( ( uint64_t ) ( int64_t ) std::stoll( ma[ 1 ].str(), nullptr, 0 ) );

	    std::vector<vtil::vip_t> valid;    auto try_add = [ & ] ( uint64_t v )
	    {
	        if ( !peek_ok( v ) ) return;
	        vtil::vip_t t = ( vtil::vip_t ) ( uint32_t ) v;
	        if ( std::find( valid.begin(), valid.end(), t ) == valid.end() )
	            valid.push_back( t );
	    };
	    // Exact constants first; only widen to the ±1 neighbours when the exact
	    // set is not enough, so encodings without the fixup never fork a
	    // spurious third path.
	    for ( uint64_t c : cands ) try_add( c );
	    if ( valid.size() < 2 )
	        for ( uint64_t c : cands )
	            for ( uint64_t v : { c - 1, c + 1 } ) try_add( v );
	    if ( valid.empty() )
	    {
	        dprintf( "[-] flag-bit branch @vip %#llx declined: candidates=%zu valid=0 es=%s\n",
	                 ( unsigned long long ) vstate->vip, cands.size(), es.c_str() );
	        return false;
	    }
	    log( "[+] flag-bit branch @vip %#llx: %zu outcomes, forking\n",
	         ( unsigned long long ) vstate->vip, valid.size() );
	    for ( auto t : valid ) destination_list.push_back( t );
	    return true;
	};
							// ---- local patch: fixed-slot branch ----
							// Cross-version evidence (matrix4/switchcase_cluster): the
							// 5.2–6.6 family encodes the next VIP as an expression over
							// a static image slot instead of an immediate, an indexed
							// table or a ?() select, e.g.
							//    0x7bd264 + (int64)dword[0x4887a72+&&base]     [S01, 64x]
							//    0x7a4c88 + __ucast(dword[0x558131b+&&base])    [S02, 19x]
							// The slot bytes are static image data — the same source
							// try_jump_table reads jump tables from — so substitute the
							// read bytes into the expression and simplify: a constant
							// result is the branch target, peek-validated like the
							// flag-bit forks before lifting it.
							const auto try_fixed_slot = [ & ] ( vtil::symbolic::expression::reference ex ) -> bool
	{
	    using vtil::symbolic::variable;

	    // Find every memory leaf; exactly one distinct slot may be referenced
	    // (the same leaf appearing twice is fine, the sign-extension does that).
	    vtil::symbolic::expression::reference slot_ptr;
	    vtil::hash_t slot_hash = 0;
	    bitcnt_t slot_bits = 0;
	    size_t distinct = 0;
	    ex.transform( [ & ] ( vtil::symbolic::expression::delegate& d )
	    {
	        if ( !d->is_variable() ) return;
	        auto& var = d->uid.get<variable>();
	        if ( !var.is_memory() ) return;
	        if ( distinct == 0 || d->uid.hash_value != slot_hash )
	        {
	            slot_ptr = var.mem().decay();
	            slot_hash = d->uid.hash_value;
	            slot_bits = var.mem().bit_count;
	            distinct++;
	        }
	    }, false, false );
	    if ( distinct != 1 || !slot_ptr || slot_bits == 0 ) return false;
	    size_t slot_bytes = slot_bits / 8;
	    if ( slot_bytes > 8 ) return false;

	    // Resolve the slot address. The outer REG_IMGBASE replacement above cannot
	    // reach inside a memory leaf's pointer, so resolve it here: substitute the
	    // image base, simplify, and take the constant as either a VA or an RVA.
	    const vtil::symbolic::expression::reference& slot_cref = slot_ptr;
	    vtil::symbolic::expression::reference addr = slot_cref.transform( [ & ] ( vtil::symbolic::expression::delegate& d )
	    {
	        if ( !d->is_variable() ) return;
	        auto& var = d->uid.get<variable>();
	        if ( var.is_register() && var.reg() == vtil::REG_IMGBASE )
	            *+d = { vstate->img->get_real_image_base(), d->size() };
	    }, false, false );
	    addr.simplify( true );
	    if ( !addr->is_constant() ) return false;
	    uint64_t slot_rva = *addr->get<uint64_t>();
	    if ( slot_rva >= vstate->img->get_real_image_base() )
	        slot_rva -= vstate->img->get_real_image_base();

	    auto* sscn = vstate->img->rva_to_section( ( uint32_t ) slot_rva );
	    if ( !sscn ) return false;
	    uint64_t scn_off = slot_rva - sscn->virtual_address;
	    if ( scn_off + slot_bytes > sscn->size_raw_data ) return false;
	    uint8_t* ent = vstate->img->rva_to_ptr<uint8_t>( ( uint32_t ) slot_rva );
	    if ( !ent ) return false;
	    uint64_t slot_val = 0;
	    std::memcpy( &slot_val, ent, slot_bytes );

	    // Substitute the slot bytes for the memory leaf and simplify; if anything
	    // else in the expression is symbolic this declines by staying non-constant.
	    ex.transform( [ & ] ( vtil::symbolic::expression::delegate& d )
	    {
	        if ( !d->is_variable() ) return;
	        if ( d->uid.hash_value != slot_hash ) return;
	        auto& var = d->uid.get<variable>();
	        if ( !var.is_memory() ) return;
	        *+d = { slot_val, d->size() };
	    }, false, false );
	    ex.simplify( true );
	    if ( !ex->is_constant() ) return false;
	    uint64_t target = *ex->get<uint64_t>();

	    // The folded target may be in RVA or VA space depending on relocs; probe
	    // both like the flag-bit constants and keep whichever decrypts to a valid
	    // VM-section handler.
	    std::vector<vtil::vip_t> valid;
	    for ( uint64_t c : { target, target - vstate->img->get_real_image_base() } )
	    {
	        if ( !peek_ok( c ) ) continue;
	        vtil::vip_t t = ( vtil::vip_t ) ( uint32_t ) c;
	        if ( std::find( valid.begin(), valid.end(), t ) == valid.end() )
	            valid.push_back( t );
	    }
	    if ( valid.empty() )
	    {
	        dprintf( "[-] fixed-slot branch @vip %#llx declined: slot=%#llx val=%#llx target=%#llx\n",
	                 ( unsigned long long ) vstate->vip, ( unsigned long long ) slot_rva,
	                 ( unsigned long long ) slot_val, ( unsigned long long ) target );
	        return false;
	    }
	    log( "[+] fixed-slot branch @vip %#llx: slot rva %#llx -> %zu outcome(s)\n",
	         ( unsigned long long ) vstate->vip, ( unsigned long long ) slot_rva, valid.size() );
	    for ( auto t : valid ) destination_list.push_back( t );
	    return true;
	};
							// ---- local patch: stack-indirect dispatch ----
							// Live-sample evidence: destination read off the VM stack
							// (qword[($sp#.. +- off)]) — a runtime indirect target in
							// VM call/return style. Model it like the jump-table
							// out-of-VM case: the block already ends with a symbolic
							// jmp to the loaded value, which faithfully represents the
							// dispatch; stop lifting this path instead of failing the
							// whole routine.
							const auto try_stack_jmp = [ & ] ( const vtil::symbolic::expression::reference& ex ) -> bool
	{
	    std::string es = ex->to_string();
	    if ( es.find( "$sp#" ) == std::string::npos ) return false;
	    log( "[+] stack-indirect jump @vip %#llx -> modeled as vexit\n",
	         ( unsigned long long ) vstate->vip );
	    return true;
	};
							// ---- end local patch ----
	#if DISCOVERY_VERBOSE_OUTPUT
						log( "CC: %s\n", branch_info.cc );
						log( "VJMP => %s\n", branch_info.destinations );
	#endif
						bool any_destination_resolved = branch_info.destinations.empty();
						// Local patch: an arm whose backward trace diverges is a
						// runtime-computed dispatch — the block already ends with a
						// symbolic jump to the popped target, so skipping the arm
						// keeps a faithful model instead of letting the divergence
						// eat the whole routine budget.
						//
						bool arm_diverged = false;
						// Local patch: each shape probe below backward-traces the arm
						// expression without a scope; bound every probe with the
						// refinement slice so a diverging trace skips the probe
						// instead of the routine.
						//
						const auto probe = [ & ] ( auto&& fn ) -> bool
						{
							try
							{
								vtil::budget::scoped_sub_deadline sd( refinement_slice_secs() );
								return fn();
							}
							catch ( std::runtime_error& e )
							{
								if ( !strstr( e.what(), "bounded refinement" ) ) throw;
								log( "[!] shape probe diverged @vip %#llx — skipping probe\n",
									 ( unsigned long long ) vstate->vip );
								vtil::symbolic::purge_simplifier_state();
								return false;
							}
						};
						for ( auto& branch : branch_info.destinations )
						{
							// If not constant:
							//
							if ( !branch->is_constant() )
							{
								// Recursively trace the expression and remove any matches of REG_IMGBASE.
								//
								try
								{
									vtil::budget::scoped_sub_deadline sd( refinement_slice_secs() );
									branch = tracer.rtrace_pexp( *branch );
									branch.transform( [image_base] ( vtil::symbolic::expression::delegate& ex )
										{
											if ( ex->is_variable() )
											{
												auto& var = ex->uid.get<vtil::symbolic::variable>();
												if ( var.is_register() && var.reg() == vtil::REG_IMGBASE )
													*+ex = { image_base, ex->size() };
											}
										} )
										.simplify( true );
								}
								catch ( std::runtime_error& e )
								{
									if ( !strstr( e.what(), "bounded refinement" ) ) throw;
									arm_diverged = true;
									log( "[!] arm rtrace diverged @vip %#llx — modeling as runtime dispatch\n",
										 ( unsigned long long ) vstate->vip );
									continue;
								}
							}

							dprintf( "[vjmp] const=%d size=%zu pre_es=%s\n", (int) branch->is_constant(),
									 branch->size(), branch->to_string().c_str() );
							// If not constant:
							//
							if ( !branch->is_constant() )
							{
								// Local patch: VMProtect relative jump table. If resolved, the
								// destination list is filled and we leave the loop early.
								//
								if ( probe( [ & ] { return try_jump_table( tracer.rtrace_exp( *branch ) ); } ) )
								{
									any_destination_resolved = true;
									break;
								}
								// Local patch: flag-bit two-way branch (see above).
								//
								if ( probe( [ & ] { return try_flag_branch( tracer.rtrace_exp( *branch ) ); } ) )
								{
									any_destination_resolved = true;
									break;
								}
								// Local patch: fixed-slot branch (see above).
								//
								if ( probe( [ & ] { return try_fixed_slot( tracer.rtrace_exp( *branch ) ); } ) )
								{
									any_destination_resolved = true;
									break;
								}
								// Local patch: stack-indirect dispatch (see above).
								//
								if ( probe( [ & ] { return try_stack_jmp( tracer.rtrace_exp( *branch ) ); } ) )
								{
									any_destination_resolved = true;
									break;
								}

								dprintf( "[vjmp] arm unresolved: %s\n", branch->to_string().c_str() );
								// BISECT-A: unresolvable arm — skip, later arms may resolve.
								continue;

							}

							destination_list.push_back( *branch->get<vtil::vip_t>() );
							any_destination_resolved = true;
						}

						// Local patch: every fast arm failed to resolve but at least
						// one diverged — keep the symbolic dispatch instead of
						// failing the routine as a switch case.
						//
						if ( !any_destination_resolved && arm_diverged )
						{
							log( "[+] vjmp @vip %#llx: arms diverged — keeping symbolic dispatch\n",
								 ( unsigned long long ) vstate->vip );
							any_destination_resolved = true;
						}

						// BISECT-A: only fail when the entire destination set resolved to nothing.
						if ( !any_destination_resolved )
						{
							log( "VJMP =>\n" );
								for ( auto [branch, idx] : vtil::zip( branch_info.destinations, vtil::iindices ) )
								{
									log( "-- %d) %s\n", idx, branch );
									try
									{
										log( ">> %s\n", tracer.rtrace_exp( *branch ) );
									}
									catch ( std::runtime_error& e )
									{
										if ( !strstr( e.what(), "bounded refinement" ) ) throw;
										log( ">> <rtrace diverged>\n" );
									}
								}
								log( "CC: %s\n", branch_info.cc );
								// Local patch: evidence capture — record the unfolded
								// branch expressions so new switch/dispatch encodings
								// can be profiled offline and the recovery extended.
								//
								try
								{
									std::filesystem::create_directory( "failures" );
									std::ofstream out( "failures/" + std::to_string( vstate->current_handler_rva ) +
													  ".switch-case.txt", std::ios::app );
									out << vtil::format::str( "[vip %#llx] cc=%s\n",
															  ( uint64_t ) vstate->vip, branch_info.cc );
									for ( auto& b : branch_info.destinations )
									{
										try
										{
											out << "  " << tracer.rtrace_exp( *b )->to_string() << "\n";
										}
										catch ( std::runtime_error& e )
										{
											if ( !strstr( e.what(), "bounded refinement" ) ) throw;
											out << "  <rtrace diverged>\n";
										}
									}
									out << "\n";
								}
								catch ( ... ) {}
								//vtil::optimizer::aux::analyze_branch( block, &tracer, false );
								// Local patch: an entirely unresolved destination set is a
								// runtime-computed dispatch (observed: register-assembled
								// targets — constant-base | reg<<32 | flag-bit, and bswap
								// variants — see failures/*.switch-case.txt). The block
								// already ends with a symbolic jump to the popped target,
								// which is the faithful model; keep it instead of throwing
								// away the whole lifted routine. The evidence dump above
								// stays for offline shape profiling.
								//
								log( "[+] vjmp @vip %#llx: unresolved runtime dispatch — keeping symbolic jump\n",
									 ( unsigned long long ) vstate->vip );
							}

						// Declare branch helper.
						//
						const auto explorer = [ & ] ( vtil::vip_t dst )
						{
							// Local patch: never fork into a VIP that is not backed by a section.
							// Some branches fold to a value the VM only resolves at run time;
							// following them used to abort the whole lift with "Invalid VIP.".
							if ( !vstate->img->rva_to_section( ( uint32_t ) dst ) )
							{
								log( "[!] skipped branch to unmapped vip %#llx\n", ( unsigned long long ) dst );
								return;
							}
	#if DISCOVERY_VERBOSE_OUTPUT
							log<CON_GRN>( "Exploring branch => %p\n", dst );
	#endif
							vm_state vstate_dup = *vstate;
							vstate_dup.vip = dst + ( vstate->dir_vip < 0 ? +1 : 0 );
							vstate_dup.next( rkblocks.back(), vstate_dup.vip, self_ref_point.value() );
							lift_il( block->fork( dst ), &vstate_dup );
						};

						//
						// TODO: Fix me.
						// There are still some concurrency issues in this code base so 
						// not using multi-threading for now, optimization is not done here
						// so we don't lose much speed anyways.
						//
						for ( auto& l : destination_list )
							explorer( l );

						/*// Allocate a thread for each additional destination.
						//
						std::vector<std::thread> thread_pool;
						fassert( destination_list.size() >= 1 );
						for ( auto dst : vtil::make_range( destination_list.begin() + 1, destination_list.end() ) )
							thread_pool.emplace_back( explorer, dst );

						// Invoke current helper and wait for each thread, then break out of the loop.
						//
						explorer( destination_list.front() );
						for ( auto& thread : thread_pool )
							thread.join();*/
						break;
					}
					unreachable();
				}

				// Translate from VMP Arch to VTIL and continue processing
				//
				block->label_begin( vip_params );
				translate( block, il_instruction );
				block->label_end();

				// Skip to next instruction and continue parsing the flow linearly
				//
				vstate->next( parameters.back().second );
				handled_any = true;
			}
			catch ( std::runtime_error& e )
			{
				// Local patch: a backward VM stream can run its VIP off the
				// start of the section backing the bytecode (observed: 5.2.0
				// keeps the encrypted stream in .pdata and one routine walks
				// it down to the section's first byte). That is a natural
				// stream end, not an error: the handlers lifted so far stay
				// valid, so model the hand-off as a vexit with an unknown
				// destination — the same philosophy as the unmapped-handler
				// modeling above. An entry whose very first handler read
				// fails stays a hard error.
				//
				if ( strstr( e.what(), "Invalid VIP." ) && ( handled_any || !block->prev.empty() ) )
				{
					log( "[!] vip stream exhausted at %#llx — modeling as vexit\n",
						 ( unsigned long long ) vstate->vip );
					block->jmp( vtil::invalid_vip );
					return block;
				}
				throw;
			}
		}
		return block;
	}
};