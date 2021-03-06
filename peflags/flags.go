package peflags

type ScnFlag uint32

const (
	IMAGE_SCN_TYPE_NOPAD             ScnFlag = 0x00000008
	IMAGE_SCN_CNT_CODE               ScnFlag = 0x00000020
	IMAGE_SCN_CNT_INITIALIZED_DATA   ScnFlag = 0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA ScnFlag = 0x00000080
	IMAGE_SCN_LNK_COMDAT             ScnFlag = 0x00001000
	IMAGE_SCN_MEM_DISCARDABLE        ScnFlag = 0x02000000
	IMAGE_SCN_MEM_EXECUTE            ScnFlag = 0x20000000
	IMAGE_SCN_MEM_READ               ScnFlag = 0x40000000
	IMAGE_SCN_MEM_WRITE              ScnFlag = 0x80000000
)

type SymClass uint8

const (
	IMAGE_SYM_CLASS_END_OF_FUNCTION  SymClass = 0xff // -1
	IMAGE_SYM_CLASS_NULL             SymClass = 0
	IMAGE_SYM_CLASS_AUTOMATIC        SymClass = 1
	IMAGE_SYM_CLASS_EXTERNAL         SymClass = 2
	IMAGE_SYM_CLASS_STATIC           SymClass = 3
	IMAGE_SYM_CLASS_REGISTER         SymClass = 4
	IMAGE_SYM_CLASS_EXTERNAL_DEF     SymClass = 5
	IMAGE_SYM_CLASS_LABEL            SymClass = 6
	IMAGE_SYM_CLASS_UNDEFINED_LABEL  SymClass = 7
	IMAGE_SYM_CLASS_MEMBER_OF_STRUCT SymClass = 8
	IMAGE_SYM_CLASS_ARGUMENT         SymClass = 9
	IMAGE_SYM_CLASS_STRUCT_TAG       SymClass = 10
	IMAGE_SYM_CLASS_MEMBER_OF_UNION  SymClass = 11
	IMAGE_SYM_CLASS_UNION_TAG        SymClass = 12
	IMAGE_SYM_CLASS_TYPE_DEFINITION  SymClass = 13
	IMAGE_SYM_CLASS_UNDEFINED_STATIC SymClass = 14
	IMAGE_SYM_CLASS_ENUM_TAG         SymClass = 15
	IMAGE_SYM_CLASS_MEMBER_OF_ENUM   SymClass = 16
	IMAGE_SYM_CLASS_REGISTER_PARAM   SymClass = 17
	IMAGE_SYM_CLASS_BIT_FIELD        SymClass = 18
	IMAGE_SYM_CLASS_FAR_EXTERNAL     SymClass = 68 /* Not in PECOFF v8 spec */
	IMAGE_SYM_CLASS_BLOCK            SymClass = 100
	IMAGE_SYM_CLASS_FUNCTION         SymClass = 101
	IMAGE_SYM_CLASS_END_OF_STRUCT    SymClass = 102
	IMAGE_SYM_CLASS_FILE             SymClass = 103
	IMAGE_SYM_CLASS_SECTION          SymClass = 104
	IMAGE_SYM_CLASS_WEAK_EXTERNAL    SymClass = 105
	IMAGE_SYM_CLASS_CLR_TOKEN        SymClass = 107
)

type ComdatSelection uint8

const (
	IMAGE_COMDAT_SELECT_NODUPLICATES ComdatSelection = 1
	IMAGE_COMDAT_SELECT_ANY          ComdatSelection = 2
	IMAGE_COMDAT_SELECT_SAME_SIZE    ComdatSelection = 3
	IMAGE_COMDAT_SELECT_EXACT_MATCH  ComdatSelection = 4
	IMAGE_COMDAT_SELECT_ASSOCIATIVE  ComdatSelection = 5
	IMAGE_COMDAT_SELECT_LARGEST      ComdatSelection = 6
)
