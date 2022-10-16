#include <windows.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/md5.h>
#include "resource.h"
#include <tchar.h>

#define ESM_POKECODEANDLOOKUP    (WM_USER + 100)

HANDLE hFile;             // 
HANDLE hMapFile;          // Global File HANDLE
LPTSTR pMap;              // MapViewOfFile
CHAR FileName[MAX_PATH];  // Used to receive File Name and set the file name to the edit

CHAR md5Result[MD5_DIGEST_LENGTH + 1];     // The buffer to be filled in the MD5SUM and SHA256SUM
CHAR sha256Result[SHA256_DIGEST_LENGTH + 1];

void Get_Open_File(HWND hwnd)
{
  OPENFILENAME ofn;
  ZeroMemory(&ofn, sizeof(OPENFILENAME));
  ZeroMemory(FileName, sizeof(FileName));
  
  ofn.lStructSize = sizeof(OPENFILENAME);
  ofn.lpstrFile = FileName;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = "All files\0*.*";
  ofn.nFilterIndex = 1;
  GetOpenFileName(&ofn);
}

void ConvertBuff(LPSTR result, unsigned char* buf, DWORD size)
{
  ZeroMemory(result, size + 1);
  for (DWORD nIndex = 0; nIndex < size; nIndex ++)
  {
      sprintf(result+nIndex*2, "%02x\t", buf[nIndex]);
  }
}

void CalcSum(LPCTSTR fileName) {
  unsigned char md5_buff[MD5_DIGEST_LENGTH];
  unsigned char sha256_buff[SHA256_DIGEST_LENGTH];

  ZeroMemory(sha256_buff, sizeof(sha256_buff));
  ZeroMemory(md5_buff, sizeof(md5_buff));

  hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    MessageBox(NULL, "File Open Failed", "Open", MB_OK);
    return;   // or exit
  }
  
  DWORD fSize = GetFileSize(hFile, NULL);
  if (fSize == 0) {
    MessageBox(NULL, "File Size 0", "Open", MB_OK);
    return;
  }

  hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, fSize, NULL);
  if (hMapFile == NULL) {
    MessageBox(NULL, "CreateFileMapping Failed", "File Mapping", MB_OK);
    return;
  }

  pMap = (LPTSTR) MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, fSize);

  if (pMap == NULL) {
    MessageBox(NULL, "could not map view of file","Map File",  MB_OK);
    return;
  }       // We Have Prepared the Content to calculate the Sum of Digest
  
  MD5_CTX md5_ctx;
  SHA256_CTX sha256_ctx;

  MD5_Init(&md5_ctx);
  MD5_Update(&md5_ctx, pMap, fSize);
  MD5_Final(md5_buff, &md5_ctx);

  SHA256_Init(&sha256_ctx);
  SHA256_Update(&sha256_ctx, pMap, fSize);
  SHA256_Final(sha256_buff, &sha256_ctx);
  
  ConvertBuff((LPSTR) md5Result, md5_buff, sizeof(md5_buff));
  ConvertBuff((LPSTR) sha256Result, sha256_buff, sizeof(sha256_buff));

  UnmapViewOfFile(pMap);
  CloseHandle(hFile);
  CloseHandle(hMapFile);
  return;
}

void Dlg_OnCommand(HWND hwnd, WPARAM wParam, LPARAM lParam)
{
  switch (wParam) {
  case IDCANCEL:
    EndDialog(hwnd, wParam);
    break;
  case IDOK:
    CalcSum(FileName);
    SetDlgItemText(hwnd, IDC_EDIT2, md5Result);
    SetDlgItemText(hwnd, IDC_EDIT3, sha256Result);
    break;
  case IDC_OPEN:
    Get_Open_File(hwnd);
    SetDlgItemText(hwnd, IDC_EDIT1, FileName);
    SetDlgItemText(hwnd, IDC_EDIT2, "");
    SetDlgItemText(hwnd, IDC_EDIT3, "");
    break;
  }
}

LRESULT WINAPI Dlg_Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  switch (uMsg) {
  case WM_INITDIALOG:
    return(TRUE);
  case WM_COMMAND:
    Dlg_OnCommand(hwnd, wParam, lParam);   // To DO
    return TRUE;
  }
  return FALSE;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPTSTR lpCmdLine, int nShowCmd)
{
  HWND hwnd = FindWindow(TEXT("#32770"), TEXT("±¨ÎÄÕªÒª"));
  if (IsWindow(hwnd)) {
    // An instance is already running, activate it and send it the new #
    SendMessage(hwnd, ESM_POKECODEANDLOOKUP, _ttoi(lpCmdLine), 0); 
  } else {
    DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, Dlg_Proc, _ttoi(lpCmdLine));
  }
  return 0;
}
