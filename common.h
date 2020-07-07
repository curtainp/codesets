# ifndef __COMMON_H__
# define __COMMON_H__

# define ELF_BEGIN_NAMESPACE  namespace elf {
# define ELF_END_NAMESPACE	}

# include <cstdint>
# include <cstring>

ELF_BEGIN_NAMESPACE

# define ELF_IDENT 16
enum class byte_order : unsigned char
{
	native,
	lsb,
	msb,
};

// resolve byte_order object's byte order,
// only do it when object's current order native.
static inline byte_order
resolve_byte_order(byte_order bo)
{
	static const char c[sizeof(int)] = {1};
	if (bo == byte_order::native)
		return 1 == c[0] ? byte_order::lsb : byte_order::msb;
	return bo;
}

// according byte order convert T
template <typename T>
T
convert(T obj, byte_order from, byte_order to)
{
	static_assert(	sizeof(T) == 1 ||
					sizeof(T) == 2 ||
					sizeof(T) == 4 ||
					sizeof(T) == 8,
	"can't convert obj biger than 8 byte");
	from = resolve_byte_order(from);
	to = resolve_byte_order(to);

	if (from == to || 1 == sizeof(T))
		return obj;
	switch (sizeof(T))
	{
		case 2:
			std::uint16_t tmp = (std::uint16_t)obj;
			return (T)((tmp & 0xff) << 8) | (tmp >> 8);
			break;
		case 4:
			return (T)__builtin_bswap32((std::uint32_t)obj);
		case 8:
			return (T)__builtin_bswap64((std::uint64_t)obj);
	}
}

enum class elfclass : unsigned char
{
	_32b = 1,
	_64b = 2,
};
struct elf_typedef
{
	typedef std::uint16_t Half;
	typedef std::uint32_t Word;
	typedef std::int32_t  Sword;
};

struct elf_32 : public elf_typedef
{
	const elfclass cls = elfclass::_32b;

	typedef std::uint32_t Addr;
	typedef std::uint32_t Off;
	typedef std::uint32_t Xword;
	typedef std::int32_t  Sword;
};
struct elf_64 : public elf_typedef
{
	const elfclass cls = elfclass::_64b;

	typedef std::uint64_t Addr;
	typedef std::uint64_t Off;
	typedef std::uint64_t Xword;
	typedef std::int64_t  Sxword;
};

// ident bit 5 -> elf byte order
enum class elfdata : unsigned char
{
	lsb,
	msb,
};

enum class elftype : elf_typedef::Half
{
	et_none  = 0,
	et_reloc = 1,
	et_exec	 = 2,
	et_dyna  = 3,
	et_core  = 4,
	et_loproc= 0xff00,
	et_hiproc= 0xffff,
};

//sizeof(Ehdr32) = 52byte
//sizeof(Ehdr64) = 64byte
template<typename E = elf_64, byte_order bo = byte_order::native>
struct Ehdr
{
	typedef E ELF;
	const byte_order order = bo;

	unsigned char ei_magic[4];		//"0x7fELF"
	elfclass ei_cls;					// bit 4
	elfdata	 ei_data;
	unsigned char ei_version;
	unsigned char ei_osabi;
	unsigned char ei_abiversion;
	unsigned char ei_paded[7];

	elftype e_type;
	typename ELF::Half e_machine;
	typename ELF::Word e_version;
	typename ELF::Addr e_entry;		//define by bit class
	typename ELF::Off  e_phoff;		//define by bit class
	typename ELF::Off  e_shoff;		//define by bit class
	typename ELF::Word e_flags;
	typename ELF::Half e_ehsize;	//sizeof this
	typename ELF::Half e_phentsize;
	typename ELF::Half e_phnum;
	typename ELF::Half e_shentsize;
	typename ELF::Half e_shnum;
	typename ELF::Half e_shstridx;

	template<typename E2>
	void copy_from_ehdr(const E2& ehdr)
	{
		std::memcpy(ei_magic, ehdr.ei_magic, ELF_IDENT);		//copy ident[16]
		e_type		= convert(ehdr.e_type, ehdr.order, order);
		e_machine	= convert(ehdr.e_machine, ehdr.order, order);
		e_version	= convert(ehdr.e_version, ehdr.order, order);
		e_entry		= convert(ehdr.e_entry, ehdr.order, order);
		e_phoff		= convert(ehdr.e_phoff, ehdr.order, order);
		e_shoff		= convert(ehdr.e_shoff, ehdr.order, order);
		e_flags		= convert(ehdr.e_flags, ehdr.order, order);
		e_ehsize	= convert(ehdr.e_ehsize, ehdr.order, order);
		e_phentsize = convert(ehdr.e_phentsize, ehdr.order, order);
		e_phnum		= convert(ehdr.e_phnum, ehdr.order, order);
		e_shentsize = convert(ehdr.e_shentsize, ehdr.order, order);
		e_shnum		= convert(ehdr.e_shnum, ehdr.order, order);
		e_shstridx  = convert(ehdr.e_shstridx, ehdr.order, order);
	}
};

enum class sh_type : elf_typedef::Word
{
	sht_null		= 0,
	sht_progbits	= 1,
	sht_symtab		= 2,
	sht_strtab		= 3,
	sht_rela_info	= 4,  //"rela" relocation info
	sht_hash		= 5,  //contain symbol hash table
	sht_dynamic		= 6,  //contain dynamic link table
	sht_note		= 7,
	sht_nobits		= 8,  //not occupy space in file
	sht_rel_info	= 9,  //"rel" relocation info
	sht_shlib		= 10, //reserved
	sht_dynsym		= 11, //dynamic loader info
	sht_num			= 12,
	sht_loproc		= 0x70000000,
	sht_hiproc		= 0x7fffffff,
	sht_louser		= 0x80000000,
	sht_hiuser		= 0xffffffff,
};

enum class sh_flag : elf_typedef::Word
{
	shf_write		= 0x1,
	shf_alloc		= 0x2,
	shf_execinstr	= 0x4,
	shf_maskproc	= 0xf0000000,
};

//sizeof(Shdr32) = 40
//sizeof(Shdr64) = 64
template<typename E = elf_64, byte_order bo = byte_order::native>
struct Shdr
{
	typedef E ELF;
	const byte_order order = bo;

	typename ELF::Word	s_name;
	sh_type				s_type;
	typename ELF::Xword s_flag;			//define by bit class
	typename ELF::Addr	s_addr;			//define by bit class
	typename ELF::Off	s_offset;		//define by bit class
	typename ELF::Xword s_size;			//define by bit class
	typename ELF::Word	s_link;
	typename ELF::Word	s_info;
	typename ELF::Xword	s_addralign;	//define by bit class
	typename ELF::Xword	s_entsize;		//define by bit class
	template<typename E2>
	void copy_from_shdr(const E2& shdr)
	{
		s_name		= convert(shdr.s_name, shdr.order, order);
		s_type		= convert(shdr.s_type, shdr.order, order);
		s_flag		= convert(shdr.s_flag, shdr.order, order);
		s_addr		= convert(shdr.s_addr, shdr.order, order);
		s_offset	= convert(shdr.s_offset, shdr.order, order);
		s_size		= convert(shdr.s_size, shdr.order, order);
		s_link		= convert(shdr.s_link, shdr.order, order);
		s_info		= convert(shdr.s_info, shdr.order, order);
		s_addralign = convert(shdr.s_addralign, shdr.order, order);
		s_entsize	= convert(shdr.s_entsize, shdr.order, order);
	}
};

enum class seg_type : elf_typedef::Word
{
	seg_null	= 0,
	seg_load	= 1,
	seg_dynamic = 2,
	seg_interp	= 3,
	seg_note	= 4,
	seg_shlib	= 5,
	seg_phdr	= 6,
	seg_tls		= 7,
	seg_loos	= 0x60000000,
	seg_hios	= 0x6fffffff,
	seg_loproc	= 0x70000000,
	seg_hiproc	= 0x7fffffff,
	seg_gnu_eh_frame = 0x6474e550,
	seg_gnu_stack	 = (seg_loos + 0x474e551),
};

enum class seg_flag : elf_typedef::Word
{
	seg_read	= 0x4,
	seg_write	= 0x2,
	seg_exec	= 0x1,
};

template<typename E = elf_64, byte_order bo = byte_order::native>
struct Phdr;

template<byte_order bo>
struct Phdr<elf_32, bo>
{
	typedef elf_32 ELF;
	const byte_order order = bo;

	seg_type		   p_type;
	typename ELF::Off  p_offset;
	typename ELF::Addr p_vaddr;
	typename ELF::Addr p_paddr;
	typename ELF::Word p_filesz;
	typename ELF::Word p_memsz;
	seg_flag		   p_flag;
	typename ELF::Word p_align;
	template<typename E2>
	void copy_from_phdr(const E2& phdr)
	{
		p_type	= convert(phdr.p_type, phdr.order, order);
		p_offset= convert(phdr.p_offset, phdr.order, order);
		p_vaddr	= convert(phdr.p_vaddr, phdr.order, order);
		p_paddr	= convert(phdr.p_paddr, phdr.order, order);
		p_filesz= convert(phdr.p_filesz, phdr.order, order);
		p_memsz	= convert(phdr.p_memsz, phdr.order, order);
		p_flag	= convert(phdr.p_flag, phdr.order, order);
		p_align	= convert(phdr.p_align, phdr.order, order);
	}
};

template<byte_order bo>
struct Phdr<elf_64, bo>
{
	typedef elf_64 ELF;
	const byte_order order = bo;

	seg_type			p_type;
	seg_flag			p_flag;
	typename ELF::Off	p_offset;
	typename ELF::Addr	p_vaddr;
	typename ELF::Addr	p_paddr;
	typename ELF::Xword	p_filesz;
	typename ELF::Xword	p_memsz;
	typename ELF::Xword	p_align;
	template<typename E2>
	void copy_from_phdr(const E2& phdr)
	{
		p_type	= convert(phdr.p_type, phdr.order, order);
		p_offset= convert(phdr.p_offset, phdr.order, order);
		p_vaddr	= convert(phdr.p_vaddr, phdr.order, order);
		p_paddr	= convert(phdr.p_paddr, phdr.order, order);
		p_filesz= convert(phdr.p_filesz, phdr.order, order);
		p_memsz	= convert(phdr.p_memsz, phdr.order, order);
		p_flag	= convert(phdr.p_flag, phdr.order, order);
		p_align	= convert(phdr.p_align, phdr.order, order);
	}
};

enum class stb : unsigned char
{
	stb_local	= 0,
	stb_global	= 1,
	stb_weak	= 2,
};

enum class stt : unsigned char
{
	stt_notype	= 0,
	stt_object	= 1,
	stt_func	= 2,
	stt_section	= 3,
	stt_file	= 4,
	stt_common	= 5,
	stt_tls		= 6,
};
template<typename E = elf_64, byte_order bo = byte_order::native>
struct Sym;

template<byte_order bo>
struct Sym<elf_32, bo>
{
	typedef elf_32 ELF;
	const byte_order order = bo;

	typename ELF::Word	st_name;	//strtab offset
	typename ELF::Addr	st_value;	//address
	typename ELF::Word	st_size;
	unsigned char		st_info;	//type and bind attr
	unsigned char		st_other;
	typename ELF::Half	st_shidx;
	template<typename E2>
	void copy_from_Sym(const E2& Sym)
	{
		st_name = convert(Sym.st_name, Sym.order, order);
		st_value = convert(Sym.st_value, Sym.order, order);
		st_size = convert(Sym.st_size, Sym.order, order);
		st_info = Sym.st_info;
		st_other = Sym.st_other;
		st_shidx = convert(Sym.st_shidx, Sym.order, order);
	}
	stb get_stb() const
	{
		return (stb)(st_info >> 4);
	}
	void set_stb(stb s)
	{
		st_info = (st_info & 0x0f) | ((unsigned char)s << 4);
	}
	stt get_stt() const
	{
		return (stt)(st_info & 0x0f);
	}
	void set_stt(stt s)
	{
		st_info = (st_info & 0xf0) | (unsigned char)s;
	}
};

template<byte_order bo>
struct Sym<elf_64, bo>
{
	typedef elf_64 ELF;
	const byte_order order = bo;

	typename ELF::Word	st_name;	//strtab offset
	unsigned char		st_info;	//type and bind attr
	unsigned char		st_other;
	typename ELF::Half	st_shidx;
	typename ELF::Addr	st_value;	//address
	typename ELF::Xword	st_size;
	template<typename E2>
	void copy_from_Sym(const E2& Sym)
	{
		st_name = convert(Sym.st_name, Sym.order, order);
		st_value = convert(Sym.st_value, Sym.order, order);
		st_size = convert(Sym.st_size, Sym.order, order);
		st_info = Sym.st_info;
		st_other = Sym.st_other;
		st_shidx = convert(Sym.st_shidx, Sym.order, order);
	}
	stb get_stb() const
	{
		return (stb)(st_info >> 4);
	}
	void set_stb(stb s)
	{
		st_info = (st_info & 0x0f) | ((unsigned char)s << 4);
	}
	stt get_stt() const
	{
		return (stt)(st_info & 0x0f);
	}
	void set_stt(stt s)
	{
		st_info = (st_info & 0xf0) | (unsigned char)s;
	}
};
ELF_END_NAMESPACE

# endif
