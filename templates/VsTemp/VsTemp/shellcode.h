#pragma once

#include <cstdint>
#include <cstdio>
#include <intrin.h>

#include <lazy_importer.hpp>
#include <xorstr.hpp>
#include <Windows.h>


#define SC_EXPORT extern "C" _declspec(dllexport)
#define GET_OFFSETS(t, m) DWORD_PTR(&(((t*)0)->m))