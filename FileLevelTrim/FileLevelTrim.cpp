// FileLevelTrim.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <memory>
#include <Windows.h>
#include <handleapi.h>

class BuffImpl
{
    int size;
    char* ptr;

public:
    BuffImpl(int s)
    {
        size = s;
        ptr = (char*)malloc(size);

        if (ptr == NULL)
        {
            size = 0;
        }
        else
        {
            memset(ptr, 0, size);
        }
    }

    ~BuffImpl()
    {
        if (ptr)
        {
            memset(ptr, 0, size);
            free(ptr);
            size = 0;
            ptr = NULL;
        }
    }

    char* getBuffer()
    {
        return ptr;
    }

    int getSize()
    {
        return size;
    }

};

static HANDLE filehandle = NULL;
static int filesize = 4096 * 16;
static bool fileAlreadyExists = false;

bool openFileHandle(const std::string& filename)
{
    filehandle = CreateFile(filename.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_FLAG_NO_BUFFERING,
        NULL);

    if (filehandle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    int lastErr = GetLastError();
    if (lastErr == ERROR_ALREADY_EXISTS)
    {
        std::cout << "File already exists.." << std::endl;
        fileAlreadyExists = true;
        return false;
    }

    // Set size
    LARGE_INTEGER size;
    size.QuadPart = filesize;

    if (!SetFilePointerEx(filehandle, size, NULL, FILE_BEGIN))
    {
        return false;
    }

    if (!SetEndOfFile(filehandle))
    {
        return false;
    }

    return true;
}

uint64_t getFileSize()
{
    if (filehandle == NULL || filehandle == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    LARGE_INTEGER largeInteger;
    if (!GetFileSizeEx(filehandle, &largeInteger))
    {
        int lastErr = GetLastError();
        std::cout << "File Size Error: " << lastErr << std::endl;
        return -1;
    }

    std::cout << "File Size: " << largeInteger.QuadPart << std::endl;
    return largeInteger.QuadPart;
}

bool trimFile(uint64_t size)
{
    if (filehandle == NULL || filehandle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    BuffImpl fileInput(offsetof(FILE_LEVEL_TRIM, Ranges) + sizeof(FILE_LEVEL_TRIM_RANGE));

    auto trimRanges = reinterpret_cast<FILE_LEVEL_TRIM*>(fileInput.getBuffer());

    trimRanges->NumRanges = 1;

    auto trimRange = reinterpret_cast<FILE_LEVEL_TRIM_RANGE*>(&trimRanges->Ranges[0]);
    trimRange->Offset = 0;
    trimRange->Length = size;

    DWORD bytesReturned;
    if (!DeviceIoControl(filehandle,
        FSCTL_FILE_LEVEL_TRIM,
        fileInput.getBuffer(),
        fileInput.getSize(),
        fileInput.getBuffer(),
        fileInput.getSize(),
        &bytesReturned,
        NULL))
    {
        int lastErr = GetLastError();
        std::cout << "Trim File Error: " << lastErr << std::endl;
        return false;
    }

    return true;
}

void cleanup(const std::string& msg, std::string filename = "")
{
    if (filehandle != NULL && filehandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(filehandle);
        filehandle = NULL;
    }
    if (filename != "" && !fileAlreadyExists)
    {
        std::cout << "Deleting file: " << filename << std::endl;
        DeleteFile(filename.c_str());
    }

    std::cout << msg << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        std::cout << "Specify a filename.." << std::endl;
        return -1;
    }

    if (argc > 2)
    {
        filesize = atoi(argv[2]);
    }

    std::string filename = argv[1];

    if (!openFileHandle(filename))
    {
        cleanup("Opening filename failed", filename);
        return -1;
    }

    auto size = getFileSize();
    if (size < 0)
    {
        cleanup("Failed to get file size!", filename);
        return -1;
    }

    if (!trimFile(size))
    {
        cleanup("Failed to trim file!", filename);
        return -1;
    }

    cleanup("Trimming successful!", filename);
    return 0;
}