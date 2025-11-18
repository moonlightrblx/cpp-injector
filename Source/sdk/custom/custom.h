#pragma once
#include <Windows.h>

#include <random>
#include <fstream>
// this is NOT the version actually used in the real cloudsdk so don't think you can bypass anything :D 

namespace custom {
	inline bool dev_cached = false;
	inline bool dev = false;
	inline bool free = false;


	__forceinline bool strcmp(const char* a, const char* b, bool caseInsensitive = false, size_t maxLen = (size_t)-1) // custom strcmp cause too lazy to use the real c func <3
	{
		size_t count = 0;

		while (*a && *b && count < maxLen) {
			char ca = *a;
			char cb = *b;

			if (caseInsensitive) {
				ca = (char)tolower((unsigned char)ca);
				cb = (char)tolower((unsigned char)cb);
			}

			if (ca != cb)
				return false;

			++a;
			++b;
			++count;
		}

		// both must end OR we hit maxLen
		return (count == maxLen) || (*a == *b);
	}

	__forceinline bool is_dev() {

		if (!dev_cached) {
			if (free) {
				dev = false;
				return dev;
			}
			char username[256];
			DWORD size = sizeof(username);
			auto user1 = "Cxfd";
			auto user2 = "conspiracy";
			auto user3 = "emili";
			if (GetUserNameA(username, &size)) {
				if (strcmp(user1, username, true)) {
					dev = true;
					user1;
				}
				if (strcmp(user2, username, true)) {
					dev = true;

				}
				if (strcmp(user3, username, true)) {

					dev = true;
					user3;
				}
			}
		}
		dev_cached = true;
		return dev;
	}

	__forceinline inline std::wstring random_wstring(size_t length) {
		const std::wstring characters =
			L"0123456789"
			L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			L"abcdefghijklmnopqrstuvwxyz";

		std::wstring result;
		result.reserve(length);

		std::mt19937 rng(static_cast<unsigned int>(std::time(nullptr)));
		std::uniform_int_distribution<> dist(0, characters.size() - 1);

		for (size_t i = 0; i < length; ++i) {
			result += characters[dist(rng)];
		}

		return result;
	}
	__forceinline std::string random_string(size_t length) {
		const std::string characters =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		std::string result;
		result.reserve(length);
		std::mt19937 rng(static_cast<unsigned int>(std::time(nullptr)));
		std::uniform_int_distribution<> dist(0, characters.size() - 1);
		for (size_t i = 0; i < length; ++i) {
			result += characters[dist(rng)];
		}
		return result;
	}

	__forceinline std::string to_string(const wchar_t* wstr) {
		int len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
		std::string str(len, '\0');
		WideCharToMultiByte(CP_ACP, 0, wstr, -1, &str[0], len, nullptr, nullptr);
		if (!str.empty() && str.back() == '\0') str.pop_back();
		return str;
	}

	__forceinline std::wstring to_wstring(const char* str) {
		int len = MultiByteToWideChar(CP_ACP, 0, str, -1, nullptr, 0);
		std::wstring wstr(len, L'\0');
		MultiByteToWideChar(CP_ACP, 0, str, -1, &wstr[0], len);
		if (!wstr.empty() && wstr.back() == L'\0') wstr.pop_back();
		return wstr;
	}
}