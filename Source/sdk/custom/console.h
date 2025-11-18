#pragma once

#include <sstream>

#include <iostream>
#include <Windows.h>

#include "cfg.h"
#include "prot/xor.h"


class c_console {
private:
	__forceinline int clamp(int value, int min, int max) {
		if (value < min) return min;
		if (value > max) return max;
		return value;
	}

	__forceinline std::string greenblue(const std::string& text) {
		std::stringstream faded;
		int blue = 255;  // Start with the lightest blue.
		std::istringstream lines(text);
		std::string line;

		while (std::getline(lines, line)) {
			faded << _C("\033[38;2;0;0;") << blue << _C("m") << line << _C("\033[0m\n"); 
			// god im sorry for whoever is reading this :fire:
			blue -= 15;
			if (blue < 0) {
				blue = 0;
			}
		}

		return faded.str();
	}
	__forceinline void fade(const std::string& text) {
		std::cout << greenblue(text);
		std::cout << "\033[0m" << std::endl;
	}
	HANDLE hConsole;
public:
	__forceinline void setfont(LPCWSTR font = L"Consolas") {

		CONSOLE_FONT_INFOEX cfi{};
		cfi.cbSize = sizeof(CONSOLE_FONT_INFOEX);

		if (GetCurrentConsoleFontEx( this->hConsole, FALSE, &cfi))
		{
			wcscpy_s(cfi.FaceName, font);
			cfi.dwFontSize.X = 0;
			cfi.dwFontSize.Y = 18;
			SetCurrentConsoleFontEx( this->hConsole, FALSE, &cfi);
		}
	}
	__forceinline void init() {
		
#if _WINDLL  //todo: only alloc when theres not already a console open
		// alloc console work
		//if (!GetConsoleWindow()) { // ?
		AllocConsole();
		FILE* fp;
		if (freopen_s(&fp, "CONOUT$", "w", stdout) == 0) {
			setvbuf(stdout, nullptr, _IONBF, 0); // no buffering :3
		}

		// Redirect STDIN
		if (freopen_s(&fp, "CONIN$", "r", stdin) == 0) {
			setvbuf(stdin, nullptr, _IONBF, 0);
		}

		// Redirect STDERR
		if (freopen_s(&fp, "CONOUT$", "w", stderr) == 0) {
			setvbuf(stderr, nullptr, _IONBF, 0);
		}
		// }
#endif
		hConsole = GetStdHandle(STD_OUTPUT_HANDLE); // used in legit modules so no need to spoof (probably?)

		/*CONSOLE_SCREEN_BUFFER_INFO scrBufferInfo;
		GetConsoleScreenBufferInfo(hConsole, &scrBufferInfo);

		short winWidth = scrBufferInfo.srWindow.Right - scrBufferInfo.srWindow.Left + 1;
		short winHeight = scrBufferInfo.srWindow.Bottom - scrBufferInfo.srWindow.Top + 1;
		short scrBufferWidth = scrBufferInfo.dwSize.X;
		short scrBufferHeight = scrBufferInfo.dwSize.Y;
		COORD newSize;
		newSize.X = scrBufferWidth;
		newSize.Y = winHeight;

		int Status = SetConsoleScreenBufferSize(hConsole, newSize);*/
		// enable ansi
		DWORD dwMode = 0;


		HWND consoleWindow = GetConsoleWindow();
		SetWindowLongA(consoleWindow, GWL_STYLE,
			GetWindowLongA(consoleWindow, GWL_STYLE) & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX & ~WS_MINIMIZEBOX);
		GetConsoleMode(hConsole, &dwMode);
		dwMode |= 0x0004; // enable ANSI escape codes
		SetConsoleMode(hConsole, dwMode); // :/ didnt work cause aids



#if !_WINDLL
		set_highest_priority(); // bad for internals but this is very useful externally 
		// i went from like 40ish fps in an external to 2000+ with this
		// but yeah dont use in dlls please
		// this will make the entire process have high priority 
		// which is terrible for memory and cpu usage
#endif
		set_transparency(255);
		setfont(L"roboto");
	}

	__forceinline void set_title(std::string title) {

		SetConsoleTitleA(title.c_str());
	}
	 
	__forceinline void set_transparency(int opacity) {
		HWND consoleWindow = GetConsoleWindow();
		SetLayeredWindowAttributes(consoleWindow, 0, opacity, LWA_ALPHA);
	}

	__forceinline void clear() {

		std::cout << _C("\033[2J\033[H") << std::flush; // ascii clear screen
		fade(logo);
	}

	__forceinline void print(const std::string& txt, int err = 0) {
		CONSOLE_SCREEN_BUFFER_INFO csbi;


		GetConsoleScreenBufferInfo(hConsole, &csbi);

		WORD defaultAttributes = csbi.wAttributes;
		int color = defaultAttributes;
		std::string symbol;

		switch (err) {
		case 0: // success 
			color = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
			symbol = _C("[+] ");
			break;
		case 1: // error / warning
			color = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY;
			symbol = _C("[!] ");
			break;
		case 2: // debug
			color = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
			symbol = _C("[?] ");
		}


		SetConsoleTextAttribute(hConsole, color);

		std::cout << symbol;

		SetConsoleTextAttribute(hConsole, defaultAttributes);


		std::cout << txt << std::endl;
	}
	__forceinline void printf(const char* fmt, int err, ...) {
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		WORD defaultAttributes;
		int color;
		std::string symbol;


		GetConsoleScreenBufferInfo(hConsole, &csbi);

		defaultAttributes = csbi.wAttributes;

		switch (err) {
		case 0: // success
			color = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
			symbol = "[+] ";
			break;
		case 1: // error / warning
			color = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY;
			symbol = "[!] ";
			break;
		case 2: // debug
			color = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
			symbol = "[?] ";
			break;
		default:
			color = defaultAttributes;
			symbol = "";
			break;
		}

		SetConsoleTextAttribute(hConsole, color);

		std::cout << symbol;

		SetConsoleTextAttribute(hConsole, defaultAttributes);


		// Format the string
		char buffer[1024];
		va_list args;
		va_start(args, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);

		std::cout << buffer << std::endl;
	}

	__forceinline bool set_highest_priority() {
		BOOL result = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
		if (result == 0) {
			return false;
		}

		return true;
	}
};
