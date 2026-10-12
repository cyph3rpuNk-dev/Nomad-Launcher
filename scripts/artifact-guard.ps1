# Parse PE metadata only. No executable is loaded or started by this guard.
# Layout: https://learn.microsoft.com/windows/win32/debug/pe-format
if (-not ('Nomad.ArtifactGuard' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
namespace Nomad {
    public static class ArtifactGuard {
        public static string[] Check(string path) {
            long size = new FileInfo(path).Length;
            if (size < 512 || size > 268435456) throw new InvalidDataException("Launcher PE size is invalid.");
            return new Reader(File.ReadAllBytes(path)).Check();
        }
        private sealed class Reader {
            readonly byte[] data;
            int optional, sections, sectionCount;
            uint headers;
            ulong imageBase;
            readonly List<string> imports = new List<string>();
            static readonly HashSet<string> stock = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
                "kernel32.dll", "user32.dll", "advapi32.dll", "gdi32.dll", "ole32.dll", "oleaut32.dll",
                "shell32.dll", "shlwapi.dll", "ntdll.dll", "combase.dll", "bcrypt.dll", "bcryptprimitives.dll",
                "crypt32.dll", "cryptbase.dll", "ncrypt.dll", "secur32.dll", "sspicli.dll", "ws2_32.dll",
                "winhttp.dll", "wininet.dll", "wintrust.dll", "version.dll", "dwmapi.dll", "uxtheme.dll",
                "imm32.dll", "setupapi.dll", "userenv.dll", "rpcrt4.dll", "psapi.dll", "dbghelp.dll",
                "iphlpapi.dll", "mpr.dll", "netapi32.dll", "powrprof.dll", "propsys.dll", "uiautomationcore.dll",
                "opengl32.dll", "d3d12.dll", "dxgi.dll", "d3dcompiler_47.dll", "hid.dll", "msvcrt.dll", "ucrtbase.dll"
            };
            public Reader(byte[] bytes) { data = bytes; }
            void Need(long offset, long count) {
                if (offset < 0 || count < 0 || offset > data.Length || count > data.Length - offset)
                    throw new InvalidDataException("Truncated or out-of-range PE metadata.");
            }
            ushort U16(int p) { Need(p,2); return BitConverter.ToUInt16(data,p); }
            uint U32(int p) { Need(p,4); return BitConverter.ToUInt32(data,p); }
            ulong U64(int p) { Need(p,8); return BitConverter.ToUInt64(data,p); }
            int Rva(uint rva, int count) {
                if (count <= 0) throw new InvalidDataException("Invalid RVA range.");
                int found = -1;
                if ((ulong)rva + (ulong)count <= headers) { Need(rva,count); found = (int)rva; }
                for (int i=0; i<sectionCount; i++) {
                    int s = sections + 40*i;
                    uint va = U32(s+12), rawSize=U32(s+16), raw=U32(s+20);
                    if (rva >= va && (ulong)rva-va+(ulong)count <= rawSize) {
                        long offset=(long)raw+rva-va; Need(offset,count);
                        if (found >= 0) throw new InvalidDataException("Ambiguous PE RVA mapping.");
                        found=(int)offset;
                    }
                }
                if (found < 0) throw new InvalidDataException("PE RVA has no file-backed range.");
                return found;
            }
            uint AddressRva(ulong address) {
                if (address < imageBase || address-imageBase > UInt32.MaxValue)
                    throw new InvalidDataException("Invalid guard address.");
                return (uint)(address-imageBase);
            }
            void ImportName(uint rva) {
                var name=new StringBuilder();
                bool terminated=false;
                for(int i=0; i<260; i++) {
                    if ((ulong)rva+(uint)i > UInt32.MaxValue) throw new InvalidDataException("Invalid import-name RVA.");
                    byte b=data[Rva(rva+(uint)i,1)];
                    if(b==0) { terminated=true; break; }
                    if(b>127) throw new InvalidDataException("Non-ASCII DLL import.");
                    name.Append((char)b);
                }
                string dll=name.ToString();
                if(!terminated || !Regex.IsMatch(dll,@"\A[A-Za-z0-9_.-]+\.dll\z",RegexOptions.IgnoreCase))
                    throw new InvalidDataException("Malformed DLL import name.");
                if(!stock.Contains(dll) && !Regex.IsMatch(dll,@"\A(?:api|ext)-ms-win-[a-z0-9-]+\.dll\z",RegexOptions.IgnoreCase))
                    throw new InvalidDataException("Non-stock Windows DLL import: "+dll);
                imports.Add(dll);
            }
            void Imports(int index, int stride, int nameOffset, bool delay) {
                int d=optional+112+index*8;
                uint rva=U32(d), size=U32(d+4);
                if(rva==0 && size==0) { if(!delay) throw new InvalidDataException("Missing PE import directory."); return; }
                if(rva==0 || size < stride || size > 1048576) throw new InvalidDataException("Invalid import directory.");
                int start=Rva(rva,(int)size);
                for(int i=0; i<(int)size/stride && i<4096; i++) {
                    int entry=start+i*stride;
                    bool empty=true;
                    for(int j=0;j<stride;j++) if(data[entry+j]!=0) { empty=false; break; }
                    if(empty) return;
                    if(delay && U32(entry)!=1) throw new InvalidDataException("Unsupported delay-import address format.");
                    uint name=U32(entry+nameOffset);
                    if(name==0) throw new InvalidDataException("Import descriptor has no DLL name.");
                    ImportName(name);
                }
                throw new InvalidDataException("Unterminated import descriptor directory.");
            }
            public string[] Check() {
                if(U16(0)!=0x5a4d) throw new InvalidDataException("Missing DOS header.");
                uint header=U32(0x3c); Need(header,24);
                int pe=(int)header;
                if(header<64 || U32(pe)!=0x4550 || U16(pe+4)!=0x8664)
                    throw new InvalidDataException("Launcher must be a Windows x64 PE image.");
                sectionCount=U16(pe+6);
                if(sectionCount<1 || sectionCount>96) throw new InvalidDataException("Invalid PE section count.");
                optional=pe+24; int optionalSize=U16(pe+20); Need(optional,optionalSize);
                if(optionalSize<240 || U16(optional)!=0x20b || U32(optional+108)<16)
                    throw new InvalidDataException("Invalid PE32+ optional header.");
                if(U16(optional+68)!=2) throw new InvalidDataException("Launcher must use the Windows GUI subsystem.");
                if((U16(optional+70)&0x4000)==0) throw new InvalidDataException("Launcher is missing the CFG image flag.");
                imageBase=U64(optional+24); headers=U32(optional+60);
                sections=optional+optionalSize; Need(sections,40*sectionCount);
                if(headers < sections+40*sectionCount || headers > data.Length) throw new InvalidDataException("Invalid PE header size.");
                for(int i=0;i<sectionCount;i++) Need(U32(sections+40*i+20),U32(sections+40*i+16));
                int dir=optional+112+10*8;
                uint configRva=U32(dir), configSize=U32(dir+4);
                if(configRva==0 || configSize<148 || configSize>65536) throw new InvalidDataException("Missing CFG load configuration.");
                int config=Rva(configRva,(int)configSize);
                uint recordedSize=U32(config);
                if(recordedSize<148 || recordedSize>configSize) throw new InvalidDataException("Invalid load configuration size.");
                if(U16(config+78)!=0x800) throw new InvalidDataException("DLL imports must use System32-only search (0x800).");
                // PE32+ includes SEHandlerTable/Count before GuardCF fields (even on x64).
                if((U32(config+144)&0x500)!=0x500 || U64(config+136)==0 || U64(config+136)>1048576)
                    throw new InvalidDataException("Missing CFG instrumentation/function table metadata.");
                Rva(AddressRva(U64(config+112)),8);
                int stride=4+(int)(U32(config+144)>>28);
                Rva(AddressRva(U64(config+128)),checked((int)U64(config+136)*stride));
                Imports(1,20,12,false); Imports(13,32,4,true);
                if(imports.Count==0) throw new InvalidDataException("Launcher imports are empty.");
                return imports.ToArray();
            }
        }
    }
}
"@
}
function Assert-NomadArtifact {
    param([Parameter(Mandatory=$true)][string]$LiteralPath)
    $null = [Nomad.ArtifactGuard]::Check($LiteralPath)
}
