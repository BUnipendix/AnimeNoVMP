// vtildump - render a VTIL routine (.vtil) as pseudo-assembly, and recover
// the original x86 bytes that VMProtect handlers were hiding (vemit*).
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <vtil/arch>
#include <vtil/symex>
#include <vtil/compiler>

int main( int argc, char** argv )
{
    if ( argc < 2 ) { printf( "usage: %s <file.vtil> [--asm-only]\n", argv[ 0 ] ); return 1; }
    bool asm_only = argc > 2 && std::string( argv[ 2 ] ) == "--asm-only";
    vtil::routine* rtn = nullptr;
    try { rtn = vtil::load_routine( argv[ 1 ] ); }
    catch ( const std::exception& ex ) { printf( "[!] load failed: %s\n", ex.what() ); return 2; }
    if ( !rtn ) { printf( "[!] load failed\n" ); return 2; }

    std::vector<uint8_t> bytes;
    for ( auto& [addr, block] : rtn->explored_blocks )
        for ( auto& ins : *block )
        {
            std::string nm = ins.base->name;
            if ( nm.rfind( "vemit", 0 ) == 0 && !ins.operands.empty() )
            {
                uint8_t* bs = ( uint8_t* ) &ins.operands[ 0 ].imm().u64;
                bytes.insert( bytes.end(), bs, bs + ins.operands[ 0 ].size() );
            }
        }

    printf( "; %s\n; entry=%llx  blocks=%zu  vemit_bytes=%zu\n", argv[ 1 ],
            ( unsigned long long ) rtn->entry_point, rtn->explored_blocks.size(), bytes.size() );

    if ( !asm_only )
        for ( auto& [addr, block] : rtn->explored_blocks )
        {
            printf( "\n%016llx:\n", ( unsigned long long ) addr );
            for ( auto& ins : *block )
                printf( "    %s\n", ins.to_string( true ).c_str() );
        }

    printf( "\n; ---- recovered x86 (vemit* bytes, %zu) ----\n", bytes.size() );
    if ( bytes.size() )
    {
        auto dasm = vtil::amd64::disasm( bytes.data(), 0, bytes.size() );
        for ( auto& ins : dasm )
            printf( "%08llx  %s\n", ( unsigned long long ) ins.address, ins.to_string().c_str() );
    }
    return 0;
}