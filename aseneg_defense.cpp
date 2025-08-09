// Author: 0mniscius
// Co-Author: Ar1st0
// License: Apache-2.0

// aseneg_defense.cpp  
// ASENEG (Defense Edition) 
// New (replacing earlier):
//   - Hybrid ARM/Thumb Merging Disassembly per function (auto-select best mode per function)
//   - Platform-specific API profiles (Windows/Linux/Android/iOS) for risk-weighted RCE scoring
//   - Keeps: Lightweight function recovery (prologs/epilogs), per-function CFG export, multi-arch,
//            PE imports, ELF API-surface, optional HF tokenizers, parallel ONNX & Z3, detailed reports.
// Defense-only. No payload/exploit generation.
//
// Build (Linux):
//   sudo apt install -y libcapstone-dev libz3-dev onnxruntime-dev
//   g++ -std=c++17 -O2 -pthread aseneg_defense.cpp -lcapstone -lz3 -lonnxruntime -o aseneg_defense
//
// Optional (HF Tokenizers C++):
//   g++ -std=c++17 -O2 -pthread aseneg_defense.cpp -DHAVE_HF_TOKENIZERS \
//     -I/path/to/tokenizers/include -L/path/to/tokenizers/lib -ltokenizers_c \
//     -lcapstone -lz3 -lonnxruntime -o aseneg_defense
//
// Usage:
//   ./aseneg_defense --file target.bin --onnx-model onnx/codebert.onnx [--outdir output] [--strict-rce] [--no-graphs]
//   ./aseneg_defense help
//
// Strictly defensive use. No payload/exploit generation.

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <chrono>
#include <filesystem>
#include <cstdint>
#include <iomanip>
#include <algorithm>
#include <array>
#include <cmath>
#include <thread>
#include <future>
#include <mutex>
#include <atomic>
#include <unordered_map>

#include <capstone/capstone.h>
#include <z3++.h>
#include <onnxruntime_cxx_api.h>

#ifndef _WIN32
 #include <elf.h>
#endif

#ifdef HAVE_HF_TOKENIZERS
#include <tokenizers_c/tokenizers.h>
#endif

using namespace std;
namespace fs = std::filesystem;

// ----------------------------- Pretty console -----------------------------
namespace ui {
    const string RESET = "\033[0m";
    const string BOLD  = "\033[1m";
    const string DIM   = "\033[2m";
    const string GREEN = "\033[32m";
    const string YELLOW= "\033[33m";
    const string RED   = "\033[31m";
    const string BLUE  = "\033[34m";

    void info(const string& s){ cout<<BLUE<<"[*] "<<RESET<<s<<"\n"; }
    void ok(const string& s){ cout<<GREEN<<"[+] "<<RESET<<s<<"\n"; }
    void warn(const string& s){ cout<<YELLOW<<"[!] "<<RESET<<s<<"\n"; }
    void err(const string& s){ cerr<<RED<<"[-] "<<RESET<<s<<"\n"; }
    void headline(const string& s){ cout<<BOLD<<s<<RESET<<"\n"; }
    void help(){
        headline("ASENEG Defense Edition v10 – Help");
        cout<<"Usage:\n";
        cout<<"  aseneg_defense --file <binary> --onnx-model <codebert.onnx> [--outdir <dir>] [--strict-rce] [--no-graphs]\n\n";
        cout<<"Options (optimized defaults; minimal flags):\n";
        cout<<"  --file <path>         Input binary (.elf/.exe/.pe)\n";
        cout<<"  --onnx-model <path>   Local ONNX model (CodeBERT fine-tuned)\n";
        cout<<"  --outdir <dir>        Output directory for reports (default: ./output)\n";
        cout<<"  --strict-rce          Stricter CE/RCE classification (higher thresholds, larger windows, longer Z3)\n";
        cout<<"  --no-graphs           Skip CFG export (DOT/JSON)\n\n";
        cout<<"Notes:\n";
        cout<<"  * Defense-only: no payload/exploit generation.\n";
        cout<<"  * Architectures: x86-32/x86-64/ARM/ARM64.\n";
        cout<<"  * v10 adds: Hybrid ARM/Thumb per function + Platform-specific API profiles.\n";
    }
}

// ----------------------------- Options -----------------------------
struct Options{
    string file;
    string onnxModel;
    string outdir="output";
    bool strictRCE=false;
    bool exportGraphs=true;
    // Tuned defaults
    int maxGadgets=256;
    int maxWindow=12;
    int timeoutMs=5000;
    float catThreshold=0.70f;
    int onnxShardThreads = max(2u, thread::hardware_concurrency()/2);
    int z3Threads = max(2u, thread::hardware_concurrency()/2);
};
bool parse_cli(int argc, char** argv, Options& o){
    if(argc==2 && (string(argv[1])=="help" || string(argv[1])=="--help" || string(argv[1])=="-h")){
        ui::help();
        return false;
    }
    for(int i=1;i<argc;i++){
        string a=argv[i];
        if(a=="--file" && i+1<argc) o.file=argv[++i];
        else if(a=="--onnx-model" && i+1<argc) o.onnxModel=argv[++i];
        else if(a=="--outdir" && i+1<argc) o.outdir=argv[++i];
        else if(a=="--strict-rce") o.strictRCE=true;
        else if(a=="--no-graphs") o.exportGraphs=false;
        else if(a=="help" || a=="--help" || a=="-h"){ ui::help(); return false; }
        else { ui::warn("Unknown arg: "+a+" (ignored; using optimized defaults)"); }
    }
    if(o.file.empty()||o.onnxModel.empty()){
        ui::err("Usage: aseneg_defense --file <binary> --onnx-model <codebert.onnx> [--outdir out] [--strict-rce] [--no-graphs]");
        ui::warn("Tip: run `aseneg_defense help` for details.");
        return false;
    }
    if(o.strictRCE){
        o.catThreshold = 0.76f;
        o.timeoutMs = 6000;
        o.maxWindow = 14;
    }
    return true;
}

// ----------------------------- File utils -----------------------------
vector<uint8_t> read_all(const string& path){
    ifstream f(path, ios::binary);
    if(!f) return {};
    return vector<uint8_t>((istreambuf_iterator<char>(f)), {});
}
bool write_text(const fs::path& p, const string& content){
    fs::create_directories(p.parent_path());
    ofstream f(p);
    if(!f) return false;
    f<<content;
    return true;
}
string hex64(uint64_t v){ stringstream ss; ss<<"0x"<<hex<<uppercase<<v; return ss.str(); }

// ----------------------------- Binary detection & arch -----------------------------
enum BinType {BIN_UNKNOWN, BIN_ELF, BIN_PE};
enum Arch {ARCH_X86_64, ARCH_X86_32, ARCH_ARM, ARCH_ARM64};
struct BinMeta { BinType bt=BIN_UNKNOWN; Arch arch=ARCH_X86_64; bool thumb=false; };

// forward decls for disassembly
struct DisasConfig { cs_arch arch; cs_mode mode; };
DisasConfig make_disas_config(enum Arch a, bool thumb);

BinMeta detect_meta(const vector<uint8_t>& buf){
    BinMeta m;
    if(buf.size()>=4 && buf[0]==0x7f && buf[1]=='E'&&buf[2]=='L'&&buf[3]=='F'){
        m.bt=BIN_ELF;
        if(buf.size()>=sizeof(Elf64_Ehdr)){
            const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(buf.data());
            switch(eh->e_machine){
                case EM_X86_64: m.arch=ARCH_X86_64; break;
                case EM_386:    m.arch=ARCH_X86_32; break;
                case EM_AARCH64:m.arch=ARCH_ARM64;  break;
                case EM_ARM:    m.arch=ARCH_ARM;    break;
                default: m.arch=ARCH_X86_64; break;
            }
            if(m.arch==ARCH_ARM){
                bool thumb=false;
                const Elf64_Shdr* sh_table = reinterpret_cast<const Elf64_Shdr*>(buf.data()+eh->e_shoff);
                const Elf64_Shdr& sh_strtab = sh_table[eh->e_shstrndx];
                const char* sh_strs = reinterpret_cast<const char*>(buf.data()+sh_strtab.sh_offset);
                for(int i=0;i<eh->e_shnum;i++){
                    string name = string(sh_strs + sh_table[i].sh_name);
                    if(name.find(".thumb")!=string::npos){ thumb=true; break; }
                }
                m.thumb=thumb;
            }
        }
    } else if(buf.size()>=2 && buf[0]==0x4D && buf[1]==0x5A){
        m.bt=BIN_PE;
        if(buf.size()>=0x40){
            int32_t lfanew = *reinterpret_cast<const int32_t*>(&buf[0x3C]);
            if(lfanew>0 && (size_t)lfanew+6 < buf.size()){
                uint32_t sig = *reinterpret_cast<const uint32_t*>(&buf[lfanew]);
                if(sig==0x00004550){
                    uint16_t machine = *reinterpret_cast<const uint16_t*>(&buf[lfanew+4]);
                    switch(machine){
                        case 0x8664: m.arch=ARCH_X86_64; break;
                        case 0x014C: m.arch=ARCH_X86_32; break;
                        case 0xAA64: m.arch=ARCH_ARM64;  break;
                        case 0x01C0:
                        case 0x01C4: m.arch=ARCH_ARM;    break;
                        default: m.arch=ARCH_X86_64; break;
                    }
                }
            }
        }
    }
    return m;
}

// ----------------------------- Minimal PE structs (cross-platform) -----------------------------
#pragma pack(push,1)
struct IMAGE_DOS_HEADER_ {
    uint16_t e_magic;    // MZ
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs;
    uint16_t e_lfarlc, e_ovno, e_res[4], e_oemid, e_oeminfo, e_res2[10];
    int32_t  e_lfanew;
};
struct IMAGE_FILE_HEADER_{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};
struct IMAGE_DATA_DIRECTORY_ { uint32_t VirtualAddress; uint32_t Size; };
struct IMAGE_OPTIONAL_HEADER64_{
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit;
    uint64_t SizeOfHeapReserve, uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_ DataDirectory[16];
};
struct IMAGE_NT_HEADERS64_{
    uint32_t Signature; // "PE\0\0"
    IMAGE_FILE_HEADER_ FileHeader;
    IMAGE_OPTIONAL_HEADER64_ OptionalHeader;
};
struct IMAGE_SECTION_HEADER_ {
    uint8_t  Name[8];
    union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
struct IMAGE_IMPORT_DESCRIPTOR_{
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};
struct IMAGE_THUNK_DATA64_ { uint64_t u1; };
struct IMAGE_IMPORT_BY_NAME_ { uint16_t Hint; char Name[1]; };
#pragma pack(pop)

uint32_t rva_to_foa(uint32_t rva, const IMAGE_NT_HEADERS64_* nth, const IMAGE_SECTION_HEADER_* sec, int nsec){
    for(int i=0;i<nsec;i++){
        uint32_t va = sec[i].VirtualAddress;
        uint32_t sz = max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
        if(rva >= va && rva < va + sz){
            return sec[i].PointerToRawData + (rva - va);
        }
    }
    return 0;
}

// ----------------------------- ELF parsing (dynsym/dynstr minimal API-surface) -----------------------------
struct ELFInfo{
    bool is64=false;
    uint64_t entry=0;
    vector<string> sections;
    vector<string> dynfuncs;
    bool nx=false, pie=false, relro=false;
};
ELFInfo parse_elf(const vector<uint8_t>& buf){
    ELFInfo info;
    if(buf.size()<sizeof(Elf64_Ehdr)) return info;
    const unsigned char* e_ident = buf.data();
    info.is64 = (e_ident[4] == ELFCLASS64);
    if(info.is64){
        const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(buf.data());
        info.entry = eh->e_entry;
        const Elf64_Shdr* sh_table = reinterpret_cast<const Elf64_Shdr*>(buf.data()+eh->e_shoff);
        const Elf64_Shdr& sh_strtab = sh_table[eh->e_shstrndx];
        const char* sh_strs = reinterpret_cast<const char*>(buf.data()+sh_strtab.sh_offset);
        int dynsym_idx=-1, dynstr_idx=-1, gnu_stack=-1, gnu_relro=-1;
        for(int i=0;i<eh->e_shnum;i++){
            string name = string(sh_strs + sh_table[i].sh_name);
            info.sections.emplace_back(name);
            if(name==".dynsym") dynsym_idx=i;
            if(name==".dynstr") dynstr_idx=i;
            if(name==".note.gnu.property") gnu_relro=i;
            if(name==".note.GNU-stack" || name==".gnu.warning.GNU-stack") gnu_stack=i;
        }
        info.pie = (eh->e_type == ET_DYN);
        if(dynsym_idx>=0 && dynstr_idx>=0){
            const Elf64_Shdr& dynsym = sh_table[dynsym_idx];
            const Elf64_Shdr& dynstr = sh_table[dynstr_idx];
            const Elf64_Sym* syms = reinterpret_cast<const Elf64_Sym*>(buf.data()+dynsym.sh_offset);
            size_t nsyms = dynsym.sh_size / sizeof(Elf64_Sym);
            const char* strtab = reinterpret_cast<const char*>(buf.data()+dynstr.sh_offset);
            for(size_t i=0;i<nsyms;i++){
                if(ELF64_ST_TYPE(syms[i].st_info)==STT_FUNC && syms[i].st_name){
                    string sname = string(strtab + syms[i].st_name);
                    if(!sname.empty()) info.dynfuncs.push_back(sname);
                }
            }
        }
        info.nx = (gnu_stack>=0);
        info.relro = (gnu_relro>=0);
    }else{
        const Elf32_Ehdr* eh = reinterpret_cast<const Elf32_Ehdr*>(buf.data());
        info.entry = eh->e_entry;
        const Elf32_Shdr* sh_table = reinterpret_cast<const Elf32_Shdr*>(buf.data()+eh->e_shoff);
        const Elf32_Shdr& sh_strtab = sh_table[eh->e_shstrndx];
        const char* sh_strs = reinterpret_cast<const char*>(buf.data()+sh_strtab.sh_offset);
        int dynsym_idx=-1, dynstr_idx=-1;
        for(int i=0;i<eh->e_shnum;i++){
            string name = string(sh_strs + sh_table[i].sh_name);
            info.sections.emplace_back(name);
            if(name==".dynsym") dynsym_idx=i;
            if(name==".dynstr") dynstr_idx=i;
        }
        if(dynsym_idx>=0 && dynstr_idx>=0){
            const Elf32_Shdr& dynsym = sh_table[dynsym_idx];
            const Elf32_Shdr& dynstr = sh_table[dynstr_idx];
            const Elf32_Sym* syms = reinterpret_cast<const Elf32_Sym*>(buf.data()+dynsym.sh_offset);
            size_t nsyms = dynsym.sh_size / sizeof(Elf32_Sym);
            const char* strtab = reinterpret_cast<const char*>(buf.data()+dynstr.sh_offset);
            for(size_t i=0;i<nsyms;i++){
                if(ELF32_ST_TYPE(syms[i].st_info)==STT_FUNC && syms[i].st_name){
                    string sname = string(strtab + syms[i].st_name);
                    if(!sname.empty()) info.dynfuncs.push_back(sname);
                }
            }
        }
    }
    return info;
}

// ----------------------------- PE parsing (imports only) -----------------------------
struct PEInfo{
    uint32_t entry=0;
    uint64_t imageBase=0;
    uint16_t sections=0;
    vector<string> imports;
    bool nx=false, aslr=false, cfg=false;
};
PEInfo parse_pe(const vector<uint8_t>& buf){
    PEInfo pi{};
    if(buf.size()<sizeof(IMAGE_DOS_HEADER_)) return pi;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER_*>(buf.data());
    if(dos->e_magic != 0x5A4D) return pi;
    auto nth = reinterpret_cast<const IMAGE_NT_HEADERS64_*>(buf.data()+dos->e_lfanew);
    if(nth->Signature != 0x00004550) return pi; // "PE\0\0"
    pi.entry = nth->OptionalHeader.AddressOfEntryPoint;
    pi.imageBase = nth->OptionalHeader.ImageBase;
    pi.sections = nth->FileHeader.NumberOfSections;
    pi.nx = (nth->OptionalHeader.DllCharacteristics & 0x0100) != 0;
    pi.aslr = (nth->OptionalHeader.DllCharacteristics & 0x0040) != 0;
    pi.cfg = false;

    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER_*>(reinterpret_cast<const uint8_t*>(nth) + sizeof(IMAGE_NT_HEADERS64_));
    const auto& dir = nth->OptionalHeader.DataDirectory[1];
    if(dir.VirtualAddress && dir.Size){
        uint32_t imp_off = rva_to_foa(dir.VirtualAddress, nth, sec, pi.sections);
        if(imp_off && imp_off + sizeof(IMAGE_IMPORT_DESCRIPTOR_) < buf.size()){
            const IMAGE_IMPORT_DESCRIPTOR_* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR_*>(buf.data()+imp_off);
            while(imp->Name){
                uint32_t oft_off = rva_to_foa(imp->OriginalFirstThunk?imp->OriginalFirstThunk:imp->FirstThunk, nth, sec, pi.sections);
                if(!oft_off || oft_off >= buf.size()) break;
                const IMAGE_THUNK_DATA64_* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64_*>(buf.data()+oft_off);
                while(thunk->u1){
                    if((thunk->u1 & 0x8000000000000000ull)==0){
                        uint32_t ibn_rva = (uint32_t)(thunk->u1 & 0xffffffff);
                        uint32_t ibn_off = rva_to_foa(ibn_rva, nth, sec, pi.sections);
                        if(ibn_off && ibn_off+sizeof(IMAGE_IMPORT_BY_NAME_)<buf.size()){
                            const IMAGE_IMPORT_BY_NAME_* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME_*>(buf.data()+ibn_off);
                            string fname = string(ibn->Name);
                            if(!fname.empty()) pi.imports.push_back(fname);
                        }
                    }
                    ++thunk;
                }
                ++imp;
            }
        }
    }
    return pi;
}

// ----------------------------- Disassembly & gadgets -----------------------------
struct Insn { uint64_t addr; string mnemonic; string op; };
struct Gadget { uint64_t addr; vector<Insn> insns; string kind; };

DisasConfig make_disas_config(enum Arch a, bool thumb){
    DisasConfig c{};
    switch(a){
        case ARCH_X86_64: c.arch=CS_ARCH_X86; c.mode=CS_MODE_64; break;
        case ARCH_X86_32: c.arch=CS_ARCH_X86; c.mode=CS_MODE_32; break;
        case ARCH_ARM64:  c.arch=CS_ARCH_ARM64; c.mode=(cs_mode)0; break;
        case ARCH_ARM:    c.arch=CS_ARCH_ARM; c.mode = thumb? CS_MODE_THUMB : CS_MODE_ARM; break;
    }
    return c;
}
vector<Insn> disassemble_cap(const vector<uint8_t>& buf, uint64_t base, const DisasConfig& dc, size_t max_insn=600000){
    csh handle; cs_insn* insn;
    vector<Insn> out;
    if(cs_open(dc.arch, dc.mode, &handle)!=CS_ERR_OK){ return out; }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    size_t count = cs_disasm(handle, buf.data(), buf.size(), base, 0, &insn);
    for(size_t i=0;i<count;i++){
        out.push_back({insn[i].address, insn[i].mnemonic, insn[i].op_str});
        if(out.size()>max_insn){ break; }
    }
    cs_free(insn, count); cs_close(&handle);
    return out;
}
// Quality scoring for ARM/Thumb
int arm_quality_score(const vector<Insn>& v){
    int score=0;
    for(const auto& in : v){
        if(in.mnemonic=="bx" && in.op.find("lr")!=string::npos) score+=3;
        if(in.mnemonic=="push" && in.op.find("lr")!=string::npos) score+=2;
        if(in.mnemonic=="pop"  && in.op.find("pc")!=string::npos) score+=3;
        if(in.mnemonic=="bl" || in.mnemonic=="blx") score+=1;
    }
    return score + (int)min<size_t>(v.size()/200, 100);
}

bool is_indirect_branch(const string& mnem, const string& op, enum Arch a){
    if(a==ARCH_X86_64 || a==ARCH_X86_32){
        if((mnem=="jmp"||mnem=="call") && op.find("0x")==string::npos) return true;
    } else if(a==ARCH_ARM){
        if(mnem=="bx" || mnem=="blx"){
            if(op.find("r")!=string::npos) return true;
        }
    } else if(a==ARCH_ARM64){
        if(mnem=="br" || mnem=="blr"){
            if(op.find("x")!=string::npos) return true;
        }
    }
    return false;
}
bool is_ret_like(const string& mnem, const string& op, enum Arch a){
    if(a==ARCH_X86_64 || a==ARCH_X86_32) return (mnem=="ret");
    if(a==ARCH_ARM)    return (mnem=="bx" && op.find("lr")!=string::npos) || (mnem=="pop" && op.find("pc")!=string::npos);
    if(a==ARCH_ARM64)  return (mnem=="ret");
    return false;
}
vector<Gadget> find_gadgets(const vector<Insn>& insns, int maxGadgets, enum Arch arch){
    vector<Gadget> g;
    for(size_t i=0;i<insns.size();++i){
        const auto& in = insns[i];
        bool is_ret = is_ret_like(in.mnemonic, in.op, arch);
        bool is_jmp_ind = is_indirect_branch(in.mnemonic, in.op, arch) && (in.mnemonic!="call" && in.mnemonic!="blr" && in.mnemonic!="blx");
        bool is_call_ind= is_indirect_branch(in.mnemonic, in.op, arch) && (in.mnemonic=="call" || in.mnemonic=="blr" || in.mnemonic=="blx");
        if(is_ret || is_jmp_ind || is_call_ind){
            Gadget ga; ga.addr = in.addr; ga.kind = is_ret?"ROP":"JOP";
            size_t back = (arch==ARCH_ARM || arch==ARCH_ARM64)? 8 : 6;
            size_t start = (i>=back)? i-back : 0;
            for(size_t k=start;k<=i;k++) ga.insns.push_back(insns[k]);
            g.push_back(move(ga));
            if((int)g.size()>=maxGadgets) break;
        }
    }
    return g;
}

// ----------------------------- Tokenization & ONNX -----------------------------
uint64_t fnv1a64(const string& s){ uint64_t h=1469598103934665603ull; for(unsigned char c: s){ h^=c; h*=1099511628211ull; } return h; }
struct Tokenizer {
#ifdef HAVE_HF_TOKENIZERS
    tokenizers_tokenizer* tkz = nullptr;
    bool has_hf=false;
    bool load_hf(const string& tokenizer_json){
        if(tokenizers_from_file(tokenizer_json.c_str(), &tkz)==0){ has_hf=true; return true; }
        return false;
    }
    vector<int64_t> encode_ids(const string& text, int L){
        if(has_hf){
            tokenizers_encoding* enc=nullptr;
            tokenizers_encode(tkz, text.c_str(), &enc);
            size_t n=0; const uint32_t* ids=nullptr;
            tokenizers_get_ids(enc, &ids, &n);
            vector<int64_t> out(L,0);
            for(int i=0;i<L;i++) out[i] = (i<(int)n)? ids[i] : 0;
            tokenizers_free_encoding(enc);
            return out;
        } else
#endif
        {
            vector<int64_t> ids(L);
            for(int i=0;i<L;i++){
                string chunk = text.substr((i*text.size())/L, text.size()/L + 1);
                ids[i] = static_cast<int64_t>(fnv1a64(chunk) % 30522);
            }
            return ids;
        }
    }
    ~Tokenizer(){
#ifdef HAVE_HF_TOKENIZERS
        if(tkz) tokenizers_free(tkz);
#endif
    }
};
struct Model {
    Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "ASENEG"};
    unique_ptr<Ort::Session> session;
    Ort::SessionOptions opts;
    bool init(const string& modelPath){
        opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        try{ session = make_unique<Ort::Session>(env, modelPath.c_str(), opts); }
        catch(const std::exception& e){ cerr<<"[-] ONNX load failed: "<<e.what()<<"\n"; return false; }
        return true;
    }
    vector<float> score_batch(const vector<vector<int64_t>>& batch){
        int B=(int)batch.size(); if(B==0) return {};
        int L=(int)batch[0].size();
        vector<int64_t> flat(B*L);
        for(int b=0;b<B;b++) for(int i=0;i<L;i++) flat[b*L+i]=batch[b][i];
        array<int64_t,2> shape{B,L};
        Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input = Ort::Value::CreateTensor<int64_t>(mem, flat.data(), flat.size(), shape.data(), shape.size());
        vector<const char*> in_names, out_names;
        Ort::AllocatorWithDefaultOptions alloc;
        in_names.push_back(session->GetInputName(0, alloc));
        out_names.push_back(session->GetOutputName(0, alloc));
        auto out = session->Run(Ort::RunOptions{nullptr}, in_names.data(), &input, 1, out_names.data(), 1);
        float* logits = out.front().GetTensorMutableData<float>();
        vector<float> probs(B);
        for(int b=0;b<B;b++){
            float l0 = logits[b*2+0], l1 = logits[b*2+1];
            float d = l1-l0;
            probs[b] = 1.f/(1.f+expf(-d));
        }
        return probs;
    }
};

// ----------------------------- Z3 modeling -----------------------------
struct ConstraintResult{ bool sat=false; string model; string rationale; };
ConstraintResult check_rce_feasibility(uint64_t addr, int timeoutMs, bool pc_control_hint, bool api_surface){
    z3::context ctx;
    z3::params p(ctx); p.set("timeout", timeoutMs);
    z3::solver s(ctx); s.set(p);
    auto in_len = ctx.bv_const("in_len", 16);
    auto buf_sz = ctx.bv_val(512, 16);
    auto taint_pc = ctx.bool_const("taint_pc");
    auto has_net = ctx.bool_val(api_surface);
    auto guard = ctx.bv_val((uint32_t)(addr & 0xffffffff), 32);
    auto input_key = ctx.bv_const("input_key", 32);
    s.add(z3::ugt(in_len, buf_sz));
    if(pc_control_hint) s.add(taint_pc == ctx.bool_val(true));
    else s.add(taint_pc == ctx.bool_val(false) || z3::ugt(in_len, buf_sz));
    s.add((input_key ^ guard) == ctx.bv_val(0,32));
    if(api_surface) s.add(z3::ugt(in_len, ctx.bv_val(64,16)));
    ConstraintResult r;
    if(s.check()==z3::sat){ r.sat=true; r.model = s.get_model().to_string(); r.rationale = string("in_len>buf && taint_pc=")+(pc_control_hint?"true":"false")+ (api_surface?" && net_surface":""); }
    else { r.sat=false; r.rationale="unsat: no feasible overflow/pc-control"; }
    return r;
}

// ----------------------------- Mechanisms & CFG -----------------------------
struct MechFlags { bool rop=false, jop=false, dop=false, cfb=false; };
struct CFGEdge { uint64_t from; uint64_t to; string kind; };
struct CFG { vector<uint64_t> nodes; vector<CFGEdge> edges; };

bool parse_imm_target(const string& op, uint64_t& tgt){
    size_t pos = op.find("0x");
    if(pos==string::npos) return false;
    size_t end=pos+2;
    while(end<op.size()){
        char c=op[end];
        if((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')) end++;
        else break;
    }
    string hs = op.substr(pos, end-pos);
    try{ tgt = stoull(hs, nullptr, 16); return true; }catch(...){ return false; }
}

CFG build_cfg(const vector<Insn>& insns){
    CFG g; g.nodes.reserve(insns.size());
    for(const auto& in: insns) g.nodes.push_back(in.addr);
    for(size_t i=0;i<insns.size();++i){
        const auto& in = insns[i];
        uint64_t tgt=0;
        bool hasImm = parse_imm_target(in.op, tgt);
        if(in.mnemonic=="jmp" || in.mnemonic=="b"){
            if(hasImm) g.edges.push_back({in.addr, tgt, "jmp"});
        } else if(in.mnemonic=="call" || in.mnemonic=="bl" || in.mnemonic=="blr" || in.mnemonic=="blx"){
            if(hasImm) g.edges.push_back({in.addr, tgt, "call"});
            if(i+1<insns.size()) g.edges.push_back({in.addr, insns[i+1].addr, "fallthrough"});
        } else if(in.mnemonic=="ret" || in.mnemonic=="bx"){
            // none
        } else {
            if(i+1<insns.size()) g.edges.push_back({in.addr, insns[i+1].addr, "fallthrough"});
        }
    }
    return g;
}
string cfg_to_dot(const CFG& cfg){
    stringstream ss;
    ss<<"digraph CFG {\n  node [shape=box,fontname=\"Courier\"];\n";
    for(auto n: cfg.nodes){ ss<<"  \""<<hex64(n)<<"\";\n"; }
    for(const auto& e: cfg.edges){
        ss<<"  \""<<hex64(e.from)<<"\" -> \""<<hex64(e.to)<<"\" [label=\""<<e.kind<<"\"];\n";
    }
    ss<<"}\n";
    return ss.str();
}
string cfg_to_json(const CFG& cfg){
    stringstream ss;
    ss<<"{\n  \"nodes\": [";
    for(size_t i=0;i<cfg.nodes.size();++i){ ss<<"\""<<hex64(cfg.nodes[i])<<"\""<<(i+1<cfg.nodes.size()?",":""); }
    ss<<"],\n  \"edges\": [\n";
    for(size_t i=0;i<cfg.edges.size();++i){
        const auto& e=cfg.edges[i];
        ss<<"    {\"from\":\""<<hex64(e.from)<<"\",\"to\":\""<<hex64(e.to)<<"\",\"kind\":\""<<e.kind<<"\"}"<<(i+1<cfg.edges.size()?",":"")<<"\n";
    }
    ss<<"  ]\n}\n";
    return ss.str();
}

// ----------------------------- Function recovery -----------------------------
struct Function {
    uint64_t start=0, end=0;
    size_t idx_start=0, idx_end=0;
    string name;
};

bool is_prolog_x86(const Insn& a, const Insn& b){
    return ((a.mnemonic=="push" && (a.op=="rbp"||a.op=="ebp")) &&
            (b.mnemonic=="mov"  && (b.op=="rbp, rsp"||b.op=="ebp, esp")));
}
bool is_small_prolog_x86(const Insn& a){
    if(a.mnemonic=="sub" && a.op.find("rsp")!=string::npos) return true;
    if(a.mnemonic=="and" && a.op.find("rsp")!=string::npos) return true;
    if(a.mnemonic=="push") return true;
    return false;
}
bool is_epilog_x86(const Insn& a, const Insn& b){
    if(a.mnemonic=="leave" && b.mnemonic=="ret") return true;
    if(a.mnemonic=="pop" && (a.op=="rbp"||a.op=="ebp") && b.mnemonic=="ret") return true;
    return false;
}
bool is_prolog_arm(const Insn& a, const Insn& b){
    if(a.mnemonic=="push" && a.op.find("lr")!=string::npos) return true;
    if(a.mnemonic=="stmdb" && a.op.find("sp!")!=string::npos && a.op.find("lr")!=string::npos) return true;
    if(a.mnemonic=="mov" && (a.op.find("r11, sp")!=string::npos || a.op.find("fp, sp")!=string::npos)) return true;
    if(a.mnemonic=="push" && b.mnemonic=="sub" && b.op.find("sp")!=string::npos) return true;
    return false;
}
bool is_epilog_arm(const Insn& a, const Insn& b){
    if(a.mnemonic=="pop" && a.op.find("pc")!=string::npos) return true;
    if(a.mnemonic=="ldmia" && a.op.find("sp!")!=string::npos && a.op.find("pc")!=string::npos) return true;
    if(a.mnemonic=="add" && a.op.find("sp")!=string::npos && b.mnemonic=="bx" && b.op.find("lr")!=string::npos) return true;
    return false;
}
bool is_prolog_a64(const Insn& a, const Insn& b){
    if(a.mnemonic=="stp" && a.op.find("x29")!=string::npos && a.op.find("x30")!=string::npos && a.op.find("[sp")!=string::npos) return true;
    if(a.mnemonic=="mov" && a.op.find("x29, sp")!=string::npos) return true;
    if(a.mnemonic=="sub" && a.op.find("sp")!=string::npos && b.mnemonic=="stp" && b.op.find("x29")!=string::npos) return true;
    return false;
}
bool is_epilog_a64(const Insn& a, const Insn& b){
    if(a.mnemonic=="ldp" && a.op.find("x29")!=string::npos && a.op.find("x30")!=string::npos && a.op.find("[sp]")!=string::npos) return true;
    if(a.mnemonic=="ret") return true;
    return false;
}

vector<Function> recover_functions(const vector<Insn>& insns, Arch arch){
    vector<Function> funcs;
    if(insns.empty()) return funcs;
    size_t i=0, N=insns.size();
    auto start_new = [&](size_t idx){
        Function f; f.idx_start=idx; f.start=insns[idx].addr;
        f.name = string("sub_") + to_string((unsigned long long)insns[idx].addr);
        funcs.push_back(move(f));
    };
    auto close_last = [&](size_t idx){
        if(funcs.empty()) return;
        funcs.back().idx_end = idx;
        funcs.back().end = insns[idx].addr;
    };
    start_new(0);
    while(i+1<N){
        const auto& a = insns[i];
        const auto& b = insns[i+1];
        bool prolog=false, epilog=false;
        if(arch==ARCH_X86_64 || arch==ARCH_X86_32){
            prolog = is_prolog_x86(a,b) || is_small_prolog_x86(a);
            epilog = is_epilog_x86(a,b) || (a.mnemonic=="ret");
        } else if(arch==ARCH_ARM){
            prolog = is_prolog_arm(a,b);
            epilog = is_epilog_arm(a,b) || (a.mnemonic=="bx" && a.op.find("lr")!=string::npos);
        } else if(arch==ARCH_ARM64){
            prolog = is_prolog_a64(a,b);
            epilog = is_epilog_a64(a,b);
        }
        if(prolog){
            if(!funcs.empty() && (i - funcs.back().idx_start) > 6){
                close_last(i-1);
                start_new(i);
            }
        }
        if(epilog){
            close_last(i);
            if(i+1<N) start_new(i+1);
        }
        i++;
    }
    close_last(N-1);
    // Merge tiny ones
    vector<Function> merged;
    for(const auto& f : funcs){
        size_t len = (f.idx_end>=f.idx_start)? (f.idx_end - f.idx_start + 1) : 0;
        if(!merged.empty() && len < 5){
            merged.back().idx_end = f.idx_end;
            merged.back().end = f.end;
        } else {
            merged.push_back(f);
        }
    }
    // Dedup overlaps
    vector<Function> compact;
    for(const auto& f: merged){
        if(compact.empty() || f.idx_start > compact.back().idx_end){
            compact.push_back(f);
        } else {
            if(f.idx_end > compact.back().idx_end) compact.back().idx_end = f.idx_end, compact.back().end = f.end;
        }
    }
    for(size_t k=0;k<compact.size();++k){
        compact[k].name = string("func_") + to_string(k) + "_" + compact[k].name;
    }
    return compact;
}

// ----------------------------- Hybrid ARM/Thumb merging per function -----------------------------
int function_quality(const vector<Insn>& insns, const Function& f){
    int q=0;
    for(size_t i=f.idx_start;i<=f.idx_end && i<insns.size();++i){
        const auto& in = insns[i];
        if(in.mnemonic=="bl"||in.mnemonic=="blx") q++;
        if(in.mnemonic=="bx" && in.op.find("lr")!=string::npos) q+=2;
        if(in.mnemonic=="push"||in.mnemonic=="pop") q++;
        if(in.mnemonic=="cmp"||in.mnemonic=="tst") q++;
    }
    return q + (int)min<size_t>( (f.idx_end - f.idx_start + 1)/16, 50);
}

vector<Insn> merge_arm_thumb_by_function(const vector<uint8_t>& buf, uint64_t base){
    // Disassemble both modes
    auto arm  = disassemble_cap(buf, base, make_disas_config(ARCH_ARM, false));
    auto thm  = disassemble_cap(buf, base, make_disas_config(ARCH_ARM, true));
    // Recover functions on both
    auto f_arm = recover_functions(arm, ARCH_ARM);
    auto f_thm = recover_functions(thm, ARCH_ARM);
    // Index functions by approx start (bucket by 64 bytes)
    auto bucket = [](uint64_t a){ return (a>>6); };
    unordered_map<uint64_t, Function> bestF; // from chosen mode
    unordered_map<uint64_t, pair<bool,int>> bestMeta; // (isThumb, quality)
    // Put ARM
    for(const auto& f: f_arm){
        int q = function_quality(arm, f);
        uint64_t b = bucket(arm[f.idx_start].addr);
        if(!bestMeta.count(b) || q>bestMeta[b].second){
            bestMeta[b] = {false, q};
            bestF[b] = f;
        }
    }
    // Compete with THUMB
    for(const auto& f: f_thm){
        int q = function_quality(thm, f);
        uint64_t b = bucket(thm[f.idx_start].addr);
        if(!bestMeta.count(b) || q>bestMeta[b].second){
            bestMeta[b] = {true, q};
            bestF[b] = f;
        }
    }
    // Stitch merged instruction list in bucket order
    vector<pair<uint64_t, uint64_t>> order; // (bucket, start-addr)
    order.reserve(bestF.size());
    for(auto& kv: bestF){
        uint64_t b=kv.first;
        uint64_t sa = (bestMeta[b].first? thm[kv.second.idx_start].addr : arm[kv.second.idx_start].addr);
        order.push_back({b, sa});
    }
    sort(order.begin(), order.end(), [](auto&a, auto&b){ return a.second < b.second; });
    vector<Insn> merged;
    for(auto& it: order){
        uint64_t b = it.first;
        bool thumb = bestMeta[b].first;
        const auto& f = bestF[b];
        if(thumb){
            for(size_t i=f.idx_start;i<=f.idx_end && i<thm.size();++i) merged.push_back(thm[i]);
        }else{
            for(size_t i=f.idx_start;i<=f.idx_end && i<arm.size();++i) merged.push_back(arm[i]);
        }
    }
    return merged;
}

// ----------------------------- Findings & reports -----------------------------
struct Finding{
    string id;
    string type; // RCE/CE/PrivEsc/InfoLeak/DoS/MemoryCorruption
    float score=0.0f;    // combined
    float ai_score=0.0f; // raw AI
    float score_ai=0, score_gadget=0, score_mech=0, score_z3=0, score_api=0; // breakdown
    uint64_t location=0;
    string func_name;
    vector<Gadget> gadgets;
    vector<string> constraints;
    vector<string> mechanisms; // ROP/JOP/DOP/CFB
    vector<string> evidence_ops;
    string ce_class; // "RCE" or "CE" or ""
    string rationale;
    vector<string> api_surface;
    bool nx=false, pie=false, relro=false, aslr=false, cfg=false;
};

string sanitize_filename(string s){
    for(char& c: s){ if(!(isalnum((unsigned char)c)||c=='_'||c=='-')) c='_'; }
    return s;
}

string to_json(const Finding& f){
    stringstream ss;
    ss<<"{\n";
    ss<<"  \"id\": \""<<f.id<<"\",\n";
    ss<<"  \"type\": \""<<f.type<<"\",\n";
    ss<<"  \"ce_class\": \""<<f.ce_class<<"\",\n";
    ss<<"  \"confidence\": "<<fixed<<setprecision(3)<<f.score<<",\n";
    ss<<"  \"ai_score\": "<<fixed<<setprecision(3)<<f.ai_score<<",\n";
    ss<<"  \"score_breakdown\": {\"ai\":"<<f.score_ai<<",\"gadget\":"<<f.score_gadget<<",\"mechanism\":"<<f.score_mech<<",\"z3\":"<<f.score_z3<<",\"api\":"<<f.score_api<<"},\n";
    ss<<"  \"location\": \""<<hex64(f.location)<<"\",\n";
    ss<<"  \"function\": \""<<f.func_name<<"\",\n";
    ss<<"  \"mechanisms\": [";
    for(size_t i=0;i<f.mechanisms.size();++i){ ss<<"\""<<f.mechanisms[i]<<"\""<<(i+1<f.mechanisms.size()?",":""); }
    ss<<"],\n  \"gadgets\": [\n";
    for(size_t i=0;i<f.gadgets.size();++i){
        ss<<"    {\"addr\":\""<<hex64(f.gadgets[i].addr)<<"\",\"kind\":\""<<f.gadgets[i].kind<<"\",\"insns\":\"";
        for(const auto& ins: f.gadgets[i].insns){ ss<<ins.mnemonic<<" "<<ins.op<<"; "; }
        ss<<"\"}"<<(i+1<f.gadgets.size()?",":"")<<"\n";
    }
    ss<<"  ],\n  \"constraints\": [";
    for(size_t i=0;i<f.constraints.size();++i){ ss<<"\""<<f.constraints[i]<<"\""<<(i+1<f.constraints.size()?",":""); }
    ss<<"],\n  \"evidence_ops\": [";
    for(size_t i=0;i<f.evidence_ops.size();++i){ ss<<"\""<<f.evidence_ops[i]<<"\""<<(i+1<f.evidence_ops.size()?",":""); }
    ss<<"],\n  \"api_surface\": [";
    for(size_t i=0;i<f.api_surface.size();++i){ ss<<"\""<<f.api_surface[i]<<"\""<<(i+1<f.api_surface.size()?",":""); }
    ss<<"],\n  \"env\": {\"nx\":"<<(f.nx?"true":"false")<<",\"pie\":"<<(f.pie?"true":"false")<<",\"relro\":"<<(f.relro?"true":"false")<<",\"aslr\":"<<(f.aslr?"true":"false")<<",\"cfg\":"<<(f.cfg?"true":"false")<<"},\n";
    ss<<"  \"rationale\": \"";
    for(char c: f.rationale){ if(c=='\"') ss<<'\\'; ss<<c; }
    ss<<"\"\n}\n";
    return ss.str();
}

string to_markdown(const Finding& f){
    stringstream ss;
    ss<<"# Vulnerability Report – "<<f.type<<"\n\n";
    ss<<"**ID:** `"<<f.id<<"`  \n";
    ss<<"**Confidence:** "<<fixed<<setprecision(2)<<(f.score*100)<<"%  \n";
    ss<<"**AI Score:** "<<fixed<<setprecision(2)<<(f.ai_score*100)<<"%  \n";
    if(!f.ce_class.empty()) ss<<"**CE Class:** "<<f.ce_class<<"  \n";
    ss<<"**Location:** "<<hex64(f.location)<<"  \n";
    if(!f.func_name.empty()) ss<<"**Function:** "<<f.func_name<<"\n\n";

    ss<<"## Score Breakdown\n";
    ss<<"- AI: "<<f.score_ai<<"\n- Gadgets: "<<f.score_gadget<<"\n- Mechanisms: "<<f.score_mech<<"\n- Z3: "<<f.score_z3<<"\n- API-Surface: "<<f.score_api<<"\n";

    ss<<"\n## Mechanisms\n";
    if(f.mechanisms.empty()) ss<<"- (none detected)\n"; else for(const auto& m: f.mechanisms) ss<<"- "<<m<<"\n";

    ss<<"\n## Evidence (instruction window)\n";
    for(const auto& e: f.evidence_ops) ss<<"- `"<<e<<"`\n";

    ss<<"\n## Gadgets (nearby)\n";
    for(const auto& g: f.gadgets){
        ss<<"- "<<g.kind<<" @ "<<hex64(g.addr)<<": ";
        for(const auto& in: g.insns) ss<<in.mnemonic<<" "<<in.op<<"; ";
        ss<<"\n";
    }

    ss<<"\n## Z3 Feasibility\n";
    for(const auto& c: f.constraints) ss<<"- "<<c<<"\n";
    ss<<"\n**Rationale:** "<<f.rationale<<"\n";

    ss<<"\n## API Surface\n";
    if(f.api_surface.empty()) ss<<"- (none detected)\n"; else for(const auto& n: f.api_surface) ss<<"- "<<n<<"\n";

    ss<<"\n## Environment & Mitigations\n";
    ss<<"- NX: "<<(f.nx?"enabled":"unknown/disabled")<<"\n";
    ss<<"- PIE/ASLR: "<<(f.pie||f.aslr?"enabled/possible":"disabled/unknown")<<"\n";
    ss<<"- RELRO/CFG: "<<(f.relro||f.cfg?"present/partial":"absent/unknown")<<"\n";
    ss<<"**Recommended mitigations:** bounds checks on untrusted inputs; validate indirect calls; enable CFI; compile with full RELRO & PIE; audit gadget-rich regions.\n";

    ss<<"\n> Defense-only blueprint. No exploit or payload is generated.\n";
    return ss.str();
}

// ----------------------------- Utility -----------------------------
vector<Insn> slice_window(const vector<Insn>& insns, size_t center, int radius){
    size_t from = (center> (size_t)radius ? center - radius : 0);
    size_t to   = min(insns.size()-1, center + (size_t)radius);
    return vector<Insn>(insns.begin()+from, insns.begin()+to+1);
}

// ----------------------------- Platform-specific API profiles -----------------------------
enum Platform {PLAT_UNKNOWN, PLAT_WINDOWS, PLAT_LINUX, PLAT_ANDROID, PLAT_IOS};
struct ApiProfile{
    vector<string> high; // strong RCE risk
    vector<string> mid;  // medium
    vector<string> low;  // benign/telemetry
};
ApiProfile profile_windows(){
    return {
        // high
        {"CreateProcess","WinExec","ShellExecute","system","LoadLibrary","LoadLibraryEx","VirtualProtect","VirtualAlloc","WriteProcessMemory","SetThreadContext","QueueUserAPC","WSARecv","recv","InternetReadFile","URLDownloadToFile"},
        // mid
        {"GetProcAddress","GetModuleHandle","MapViewOfFile","CreateFile","ReadFile","WriteFile","HttpSendRequest","InternetOpenUrl"},
        // low
        {"printf","memcpy","strlen","strcpy","fopen","fwrite","close"}
    };
}
ApiProfile profile_linux(){
    return {
        {"execve","system","popen","dlopen","mprotect","mmap","ptrace","prctl","recv","recvfrom","accept","read","readv","ioctl"},
        {"dlsym","fork","clone","socket","connect","send","sendto","write","writev","pipe"},
        {"printf","puts","strlen","strcpy","memcpy","memcmp","fopen","fwrite","close"}
    };
}
ApiProfile profile_android(){
    return {
        {"__system_property_get","system","dlopen","mprotect","mmap","art_quick_invoke_static","Java_*","AAssetManager_open","am_start"},
        {"dlsym","socket","connect","recv","accept","read","binder_*"},
        {"__android_log_print","ALooper_*","ANativeWindow_*","strlen","memcpy"}
    };
}
ApiProfile profile_ios(){
    // iOS is not supported (Mach-O), keep as placeholder for potential future Mach-O support.
    return {
        {"posix_spawn","dlopen","mprotect","mmap","objc_msgSend"},
        {"dlsym","socket","connect","recv","accept","read"},
        {"NSLog","printf","strlen","memcpy"}
    };
}

Platform detect_platform(BinType bt, const vector<string>& apis){
    if(bt==BIN_PE) return PLAT_WINDOWS;
    if(bt==BIN_ELF){
        // Heuristic: Android if android/bionic symbols present
        for(const auto& s: apis){
            if(s.find("__system_property_get")!=string::npos || s.find("AAssetManager_")!=string::npos || s.find("android_")!=string::npos)
                return PLAT_ANDROID;
        }
        return PLAT_LINUX;
    }
    return PLAT_UNKNOWN;
}

float api_risk_component(const vector<string>& apis, Platform p){
    ApiProfile prof;
    switch(p){
        case PLAT_WINDOWS: prof=profile_windows(); break;
        case PLAT_LINUX:   prof=profile_linux(); break;
        case PLAT_ANDROID: prof=profile_android(); break;
        case PLAT_IOS:     prof=profile_ios(); break;
        default:           prof=profile_linux(); break;
    }
    int hi=0, mi=0, lo=0;
    for(const auto& a: apis){
        for(const auto& k: prof.high){ if(a.find(k)!=string::npos){ hi++; goto next; } }
        for(const auto& k: prof.mid ){ if(a.find(k)!=string::npos){ mi++; goto next; } }
        for(const auto& k: prof.low ){ if(a.find(k)!=string::npos){ lo++; goto next; } }
        next: ;
    }
    // Weighted risk -> 0..1
    float score = min(1.f, (hi*1.0f + mi*0.5f) / max(1, hi+mi+lo));
    return score;
}

// ----------------------------- Analysis pipeline -----------------------------
struct AnalysisEnv { bool nx=false,pie=false,relro=false,aslr=false,cfg=false; vector<string> apis; Platform plat=PLAT_UNKNOWN; };

vector<Finding> analyze(const Options& opt,
                        vector<Insn>& out_insns,
                        CFG& out_global_cfg,
                        vector<Function>& out_funcs){
    vector<uint8_t> buf = read_all(opt.file);
    if(buf.empty()){ ui::err("Failed to read file"); return {}; }
    auto meta = detect_meta(buf);
    if(meta.bt==BIN_UNKNOWN){ ui::err("Unknown/unsupported binary format"); return {}; }
    ui::ok(string("Detected binary: ")+(meta.bt==BIN_ELF?"ELF":"PE"));

    // API surface and env
    uint64_t base = 0x1000;
    AnalysisEnv env;
    if(meta.bt==BIN_ELF){
        auto ei = parse_elf(buf);
        base = ei.entry? (ei.entry & ~0xfffull) : (meta.arch==ARCH_X86_64?0x400000:0x10000);
        ui::info("ELF entry: "+hex64(ei.entry));
        env.apis = ei.dynfuncs;
        env.nx=ei.nx; env.pie=ei.pie; env.relro=ei.relro; env.aslr=ei.pie; env.cfg=false;
    } else {
        auto pi = parse_pe(buf);
        base = (uint64_t)pi.imageBase;
        ui::info("PE entry RVA: "+hex64(pi.entry));
        env.apis = pi.imports;
        env.nx=pi.nx; env.aslr=pi.aslr; env.cfg=pi.cfg; env.pie=false; env.relro=false;
    }
    env.plat = detect_platform(meta.bt, env.apis);
    ui::info(string("Platform profile: ")+ (env.plat==PLAT_WINDOWS?"Windows": env.plat==PLAT_LINUX?"Linux": env.plat==PLAT_ANDROID?"Android": env.plat==PLAT_IOS?"iOS":"Unknown"));

    // Disassembly
    vector<Insn> insns;
    if(meta.arch==ARCH_ARM){
        // Hybrid merging per function
        insns = merge_arm_thumb_by_function(buf, base);
        ui::info(string("ARM hybrid (per-function) merged insns: ")+to_string(insns.size()));
    }else{
        insns = disassemble_cap(buf, base, make_disas_config(meta.arch, meta.thumb));
    }
    ui::ok("Disassembled instructions: "+to_string(insns.size()));

    // Function recovery on the final instruction stream
    auto funcs = recover_functions(insns, meta.arch);
    ui::ok("Recovered functions: "+to_string(funcs.size()));
    out_funcs = funcs;

    // Gadgets
    auto gadgets = find_gadgets(insns, /*maxGadgets*/256, meta.arch);
    ui::ok("Gadgets found: "+to_string(gadgets.size()));

    // Global CFG
    out_global_cfg = build_cfg(insns);
    out_insns = insns;

    // Prepare tokenizer/model
    Tokenizer tk;
#ifdef HAVE_HF_TOKENIZERS
    try{
        fs::path tkp = fs::path(opt.onnxModel).parent_path() / "tokenizer.json";
        if(fs::exists(tkp)) tk.load_hf(tkp.string());
    }catch(...){}
#endif
    Model mdl;
    if(!mdl.init(opt.onnxModel)){ ui::err("Model init failed"); return {}; }

    // Build sampled lines
    vector<size_t> sample_idx;
    size_t step = max<size_t>(1, insns.size()/384);
    for(size_t i=0;i<insns.size(); i+= step ) sample_idx.push_back(i);

    // Parallel ONNX shards
    int shards = max(1, min((int)sample_idx.size(), (int)std::thread::hardware_concurrency()));
    vector<vector<size_t>> shard_idx(shards);
    for(size_t i=0;i<sample_idx.size();++i) shard_idx[i%shards].push_back(sample_idx[i]);

    mutex mtx;
    vector<pair<size_t,float>> scored_all;
    auto worker = [&](const vector<size_t>& idxs){
        vector<vector<int64_t>> batch;
        vector<size_t> backref;
        for(size_t idx : idxs){
            string line = insns[idx].mnemonic + string(" ") + insns[idx].op;
            batch.push_back(tk.encode_ids(line, /*L*/64));
            backref.push_back(idx);
            if(batch.size()==128){
                auto probs = mdl.score_batch(batch);
                lock_guard<mutex> lk(mtx);
                for(size_t b=0;b<probs.size();++b) scored_all.push_back({backref[b], probs[b]});
                batch.clear(); backref.clear();
            }
        }
        if(!batch.empty()){
            auto probs = mdl.score_batch(batch);
            lock_guard<mutex> lk(mtx);
            for(size_t b=0;b<probs.size();++b) scored_all.push_back({backref[b], probs[b]});
        }
    };

    vector<thread> pool;
    for(int s=0;s<shards;s++) pool.emplace_back(worker, cref(shard_idx[s]));
    for(auto& th: pool) th.join();

    sort(scored_all.begin(), scored_all.end(), [](auto&a, auto&b){return a.second>b.second;});

    // Platform-specific API risk
    float api_score_weighted = api_risk_component(env.apis, env.plat);
    set<string> api_surface(env.apis.begin(), env.apis.end());

    // Z3 feasibility (parallel) + findings
    vector<Finding> findings;
    mutex out_mtx;
    auto z3_worker = [&](const vector<pair<size_t,float>>& items){
        for(const auto& pr : items){
            size_t idx = pr.first; float ai = pr.second;
            if(ai < 0.52f) continue;

            auto window = slice_window(insns, idx, opt.maxWindow);
            vector<Gadget> nearG;
            for(const auto& g : gadgets){
                if(g.addr >= window.front().addr && g.addr <= window.back().addr)
                    nearG.push_back(g);
                if(nearG.size()>=12) break;
            }
            // Mechanisms
            MechFlags mech{};
            // simple mechanism tagging inline to avoid re-iterating
            int dop_hits=0; bool has_indirect=false, prior_check=false;
            vector<string> ev;
            for(const auto& w : window){
                string op = w.mnemonic + " " + w.op;
                ev.push_back(op);
                if(is_indirect_branch(w.mnemonic, w.op, meta.arch)) has_indirect=true;
                if(w.mnemonic=="cmp"||w.mnemonic=="tst"||w.mnemonic=="test") prior_check=true;
                if(w.mnemonic=="mov"||w.mnemonic=="str"||w.mnemonic=="strb"||w.mnemonic=="strh") dop_hits++;
            }
            for(const auto& g: nearG){
                if(g.kind=="ROP") mech.rop=true;
                if(g.kind=="JOP") mech.jop=true;
            }
            if(dop_hits>=3) mech.dop=true;
            if(has_indirect && !prior_check) mech.cfb=true;

            bool pc_control = has_indirect;
            auto cz = check_rce_feasibility(insns[idx].addr, opt.timeoutMs, (pc_control && !prior_check), api_score_weighted>0.5f);

            int gadgetScore = (int)nearG.size();
            int mechScore = (mech.rop?1:0) + (mech.jop?1:0) + (mech.dop?1:0) + (mech.cfb?1:0);

            float s_ai = 0.36f*ai;
            float s_g  = 0.22f*min(1.0f, gadgetScore/8.0f);
            float s_m  = 0.12f*min(1.0f, mechScore/3.0f);
            float s_z  = 0.20f*(cz.sat?1.0f:0.0f);
            float s_a  = 0.10f*api_score_weighted;
            float S = s_ai + s_g + s_m + s_z + s_a;

            if(S < (opt.strictRCE?0.76f:0.70f)) continue;

            // map location to recovered function
            string fname;
            for(const auto& f : funcs){
                if(idx >= f.idx_start && idx <= f.idx_end){ fname = f.name; break; }
            }

            Finding f;
            static atomic<int> gid{1};
            f.id = string("VULN_")+to_string(gid++);
            f.score = S;
            f.ai_score = ai;
            f.score_ai=s_ai; f.score_gadget=s_g; f.score_mech=s_m; f.score_z3=s_z; f.score_api=s_a;
            f.location = insns[idx].addr;
            f.func_name = fname;
            f.gadgets = nearG;
            f.constraints.push_back(string("sat=")+(cz.sat?"true":"false"));
            if(cz.sat) f.constraints.push_back(cz.model.substr(0, 800));
            if(mech.rop) f.mechanisms.push_back("ROP");
            if(mech.jop) f.mechanisms.push_back("JOP");
            if(mech.dop) f.mechanisms.push_back("DOP");
            if(mech.cfb) f.mechanisms.push_back("CFB");
            f.evidence_ops = ev;
            f.rationale = cz.rationale;
            for(const auto& a: api_surface) f.api_surface.push_back(a);
            f.nx=env.nx; f.pie=env.pie; f.relro=env.relro; f.aslr=env.aslr; f.cfg=env.cfg;

            if(pc_control && api_score_weighted>0.5f){
                f.type="RCE"; f.ce_class="RCE";
            } else if(pc_control){
                f.type="CE"; f.ce_class="CE";
            } else if(mech.dop) f.type="MemoryCorruption";
            else if(mech.rop && api_score_weighted<=0.5f) f.type="PrivEsc";
            else if(!cz.sat) f.type="DoS";
            else f.type="InfoLeak";

            lock_guard<mutex> lk(out_mtx);
            findings.push_back(move(f));
        }
    };

    size_t topN = min<size_t>(scored_all.size(), 64);
    vector<vector<pair<size_t,float>>> z3_batches;
    int threads = max(1, min((int)topN, (int)std::thread::hardware_concurrency()));
    z3_batches.resize(threads);
    for(size_t i=0;i<topN;i++) z3_batches[i % threads].push_back(scored_all[i]);

    vector<thread> z3pool;
    for(auto& batch : z3_batches) z3pool.emplace_back(z3_worker, cref(batch));
    for(auto& th : z3pool) th.join();

    sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b){ return a.score>b.score; });
    return findings;
}

// ----------------------------- Main -----------------------------
int main(int argc, char** argv){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    Options opt;
    if(!parse_cli(argc, argv, opt)) return 2;
    if(!fs::exists(opt.file)){ ui::err("Input file not found: "+opt.file); return 2; }
    if(!fs::exists(opt.onnxModel)){ ui::err("ONNX model not found: "+opt.onnxModel); return 2; }
    fs::create_directories(opt.outdir);

    ui::info("ASENEG (Defense Edition) – v10 (Hybrid ARM/Thumb per function, Platform-specific API profiles, function recovery, multi-arch, parallel ONNX/Z3)");
    auto t0 = chrono::steady_clock::now();

    vector<Insn> all_insns;
    CFG global_cfg;
    vector<Function> funcs;
    auto findings = analyze(opt, all_insns, global_cfg, funcs);

    if(opt.exportGraphs){
        string dot = cfg_to_dot(global_cfg);
        string jso = cfg_to_json(global_cfg);
        write_text(fs::path(opt.outdir)/"cfg_global.dot", dot);
        write_text(fs::path(opt.outdir)/"cfg_global.json", jso);
        ui::ok("Wrote global CFG: cfg_global.dot / cfg_global.json");
    }

    if(findings.empty()){
        ui::warn("No high-confidence findings. Nothing to report.");
        return 0;
    }

    int count=0;
    for(const auto& f: findings){
        string stem = sanitize_filename(f.id + string("_") + f.type + (f.ce_class.empty()?string(""):string("_")+f.ce_class));
        fs::path j = fs::path(opt.outdir)/ (stem + ".json");
        fs::path m = fs::path(opt.outdir)/ (stem + ".md");

        if(!write_text(j, to_json(f))) ui::err("Failed to write "+j.string());
        if(!write_text(m, to_markdown(f))) ui::err("Failed to write "+m.string());
        ui::ok("Wrote "+j.string()+" and "+m.string());

        if(opt.exportGraphs){
            // per-finding window CFG
            size_t idx=0; uint64_t bestdiff=~0ull;
            for(size_t i=0;i<all_insns.size();++i){
                auto d = (all_insns[i].addr > f.location)? (all_insns[i].addr - f.location) : (f.location - all_insns[i].addr);
                if(d < bestdiff){ bestdiff=d; idx=i; }
            }
            auto win = slice_window(all_insns, idx, /*radius*/ 20);
            CFG local = build_cfg(win);
            write_text(fs::path(opt.outdir)/ (stem + "_window.dot"), cfg_to_dot(local));
            write_text(fs::path(opt.outdir)/ (stem + "_window.json"), cfg_to_json(local));

            // per-function CFG
            for(const auto& fn : funcs){
                if(fn.name == f.func_name){
                    // slice of function instructions
                    vector<Insn> slice;
                    for(size_t i=fn.idx_start;i<=fn.idx_end && i<all_insns.size();++i) slice.push_back(all_insns[i]);
                    write_text(fs::path(opt.outdir)/ (stem + "_" + sanitize_filename(fn.name) + "_func.dot"), cfg_to_dot(build_cfg(slice)));
                    write_text(fs::path(opt.outdir)/ (stem + "_" + sanitize_filename(fn.name) + "_func.json"), cfg_to_json(build_cfg(slice)));
                    break;
                }
            }
        }
        count++;
    }

    auto t1 = chrono::steady_clock::now();
    auto ms = chrono::duration_cast<chrono::milliseconds>(t1-t0).count();
    ui::ok("Analysis done. Findings: "+to_string(count)+"  Time: "+to_string(ms)+" ms");
    ui::info("Run `aseneg_defense help` to see options.");
    return 0;
}
