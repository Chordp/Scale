#include "shellcode.h"

//全局变量测试
SC_EXPORT uint64_t GLOBAL_VARIABLE = 123;
//入口函数
SC_EXPORT void go() {
	LI_FN(LoadLibraryA).get()("user32.dll");
	LI_FN(MessageBoxA).get()(0, xorstr_("hello world"),0,0);
}