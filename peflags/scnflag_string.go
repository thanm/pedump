// Code generated by "stringer -trimprefix IMAGE_ -type=ScnFlag"; DO NOT EDIT.

package peflags

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[IMAGE_SCN_TYPE_NOPAD-8]
	_ = x[IMAGE_SCN_CNT_CODE-32]
	_ = x[IMAGE_SCN_CNT_INITIALIZED_DATA-64]
	_ = x[IMAGE_SCN_CNT_UNINITIALIZED_DATA-128]
	_ = x[IMAGE_SCN_LNK_COMDAT-4096]
	_ = x[IMAGE_SCN_MEM_DISCARDABLE-33554432]
	_ = x[IMAGE_SCN_MEM_EXECUTE-536870912]
	_ = x[IMAGE_SCN_MEM_READ-1073741824]
	_ = x[IMAGE_SCN_MEM_WRITE-2147483648]
}

const (
	_ScnFlag_name_0 = "SCN_TYPE_NOPAD"
	_ScnFlag_name_1 = "SCN_CNT_CODE"
	_ScnFlag_name_2 = "SCN_CNT_INITIALIZED_DATA"
	_ScnFlag_name_3 = "SCN_CNT_UNINITIALIZED_DATA"
	_ScnFlag_name_4 = "SCN_LNK_COMDAT"
	_ScnFlag_name_5 = "SCN_MEM_DISCARDABLE"
	_ScnFlag_name_6 = "SCN_MEM_EXECUTE"
	_ScnFlag_name_7 = "SCN_MEM_READ"
	_ScnFlag_name_8 = "SCN_MEM_WRITE"
)

func (i ScnFlag) String() string {
	switch {
	case i == 8:
		return _ScnFlag_name_0
	case i == 32:
		return _ScnFlag_name_1
	case i == 64:
		return _ScnFlag_name_2
	case i == 128:
		return _ScnFlag_name_3
	case i == 4096:
		return _ScnFlag_name_4
	case i == 33554432:
		return _ScnFlag_name_5
	case i == 536870912:
		return _ScnFlag_name_6
	case i == 1073741824:
		return _ScnFlag_name_7
	case i == 2147483648:
		return _ScnFlag_name_8
	default:
		return "ScnFlag(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
