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
// Local patch: data-driven adaptation profiles.
//
// A profile describes HOW a protected image is built (patterns, shapes,
// widths) — never concrete addresses. It lets the same engine lift different
// protector generations without code changes: section names, the vmenter
// entry shape, jump-table parameters. Values here only ever parameterize
// existing pattern matchers; an unknown shape id fails loudly (classified
// error + evidence dump) instead of guessing.
//
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace vmp
{
	struct vmenter_shape
	{
		// "push-movabs"       classic VMProtect 3.x: push sequence terminated
		//                     by MOVABS r64, imm64 (relocation marker).
		std::string id;
	};

	struct profile_t
	{
		int schema = 1;
		std::string name = "vmp3-classic";

		// [discovery]: how vmenter stubs are found.
		//   "cross-branch"  classic: E9/E8 sites jumping cross-section onto a
		//                   68 imm32 / E8 rel32 stub (engine default).
		//   "stub-target"  old dual-shell images (e.g. two packer sections):
		//                   stubs are not directly referenced cross-section;
		//                   scan executable sections for 68 imm32 / E8 rel32
		//                   whose call target lands in one of the profile's
		//                   VM sections instead.
		std::string discovery_scan = "cross-branch";

		// [discovery]: protected section prefixes the lifter treats as VM
		// sections (chaining / re-entry detection) and, for "stub-target"
		// discovery, the sections the stub's call must land in. The -sections
		// command line argument appends on top.
		std::vector<std::string> sections = { ".vmp" };

		// [vmenter]: accepted entry shapes, tried in order.
		std::vector<vmenter_shape> vmenter_shapes = { { "push-movabs" } };

		// [jump_table]: switch-table recovery parameters.
		int jt_entry_size = 4;      // bytes per table entry
		bool jt_signed = true;      // entries sign-extended?
		int jt_min_targets = 3;     // consecutive valid targets required
		int jt_max_entries = 4096;  // table length cap

		// [mutation]: the protector's mutation layer interleaves junk with
		// the real handlers. When demutate is set, the unrolled streams are
		// cleaned with the ported junk rules (flag noise, push/pop sandwich
		// pairs, dead writes inside push/pop windows, dead stores) before
		// parsing — mirroring the offline demutate tooling.
		bool mutation_demutate = false;

		bool shape_supported( const std::string& id ) const
		{
			for ( auto& s : vmenter_shapes )
				if ( s.id == id ) return true;
			return false;
		}
		bool has_shape( const std::string& id ) const { return shape_supported( id ); }
	};

	// The active profile; defaults describe classic VMProtect 3.x so behavior
	// without -profile is unchanged.
	//
	inline profile_t g_profile;

	// Automatic profile selection from the image's section layout. The
	// protector generations this engine targets are identified by mutually
	// exclusive section layouts, so the chooser never guesses:
	//   ".vmp" present        -> classic VMProtect 3.x stock layout (defaults)
	//   ".upx0" and ".upx1"   -> dual-shell era: stub-target discovery over
	//                            both packer sections
	//   ".upx0" only          -> merged single-shell era: cross-branch
	//                            discovery over the single packer section
	// Anything else fails loudly with the observed section list — pass an
	// explicit -profile for unrecognized layouts instead of guessing.
	// On success activates g_profile and returns true.
	//
	bool detect_profile( const std::vector<std::string>& section_names, std::string& error );

	// Parses the TOML subset used by profiles:
	//   [section] / [[array-section]] headers, key = value with string,
	//   integer, boolean and string-array values, # comments.
	// On success activates g_profile and returns true; otherwise returns
	// false with a human-readable reason in `error`.
	//
	bool load_profile( const std::string& path, std::string& error );
}
