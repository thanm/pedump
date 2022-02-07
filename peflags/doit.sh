#!env bash
stringer -trimprefix IMAGE_ -type=ScnFlag
stringer -trimprefix IMAGE_SYM_CLASS_ -type=SymClass
stringer -trimprefix IMAGE_COMDAT_SELECT_ -type=ComdatSelection
