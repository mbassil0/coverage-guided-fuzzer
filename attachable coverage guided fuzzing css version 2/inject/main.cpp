#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>
#include <stdio.h>
#include "inject.h"

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

DWORD pid;


void GetInput()
{

}

bool run_srcds()
{
	//srcds.exe -game cstrike  -console -insecure

	return true;
}

void inject_fuzzer_to_client()
{
	//C:\Users\b\Desktop\new_fuzzer\trying to find something\Project1\x64\Debug\Project1.dll
	//LoadLibraryInjection("srcds.exe", "C:\\Users\\b\\source\\repos\\attachable coverage guided fuzzing css\\Release\\harness.dll");
	printf("%d \n", LoadLibraryInjection("srcds.exe", "C:\\Users\\b\\Desktop\\new_fuzzer\\trying to find something\\Project1\x64\\Debug\Project1.dll"));
	//while (LoadLibraryInjection("hl2.exe", "C:\\Users\\b\source\\repos\\css client fuzzer\\Release\\to inject.dll") == false)
	//{
	Sleep(100);
	//}


}

/*
called when the program we are fuzzing crashes
purpose: logging the memory that made the proram crash
*/
void on_srcds_crash()
{

}



/*
CSS client must be running
*/
//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
int main()
{

	FILE* f;
	/*AllocConsole();
	freopen_s(&f, "CONIN$", "r", stdin);
	freopen_s(&f, "CONOUT$", "w", stdout);
	freopen_s(&f, "CONOUT$", "w", stderr);*/
	printf("aa");
	inject_fuzzer_to_client();

	/*	bool shoud_exit = false;

		while (shoud_exit == false)
		{

			//if (srcs isnt running)
			{
				on_srcds_crash();
				run_srcds();
			}
			Sleep(1000);
		}*/

}


