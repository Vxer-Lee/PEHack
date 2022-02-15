/**************************************************************/
/*
/* 学习滴水逆向 PE结构分析代码练习
/* 海东老师 Bilibili：滴水逆向三期
/* 
/* PE结构分析类，可读取PE文件，解析PE头，解析节表，目录表 以及输入导出表
****************************************************************/
#pragma once
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <Windows.h>

#include <map>
#include <vector>
#include <iostream>
#include <algorithm>
using namespace std;


class PE
{
private:
	HANDLE handle;

	public:
		PE(const char* path); //PE类构造
		PE(LPVOID pFileBuffer,BOOL isMemLoad=FALSE);
		~PE();                //PE类析构

		//获取PE在文件中的Buffer 和 在内存中的Buffer
		LPVOID GetFileBuffer()  { return m_FileBuffer; }
		LPVOID GetImageBuffer() { return m_ImageBuffer; }
		//解析PE头
		PIMAGE_DOS_HEADER       GetDosHeader()     { return m_DOS_Header; }    //DOS头
		LPVOID					GetDosStub()       { return m_DosStub; }       //DOS残留垃圾数据
		LPVOID			        GetNTHeader()      { return m_NT_Header; }     //NT头
		PIMAGE_FILE_HEADER      GetStdPEHeader()   { return m_File_Header; }   //标准PE头
		PIMAGE_OPTIONAL_HEADER  GetOptionPEHeader(){ return m_Option_Header; } //可选PE头
		DWORD					GetDosStubSize()   { return m_DosStubSize; }   //DOS残留垃圾数据大小
		DWORD ReadPE_File(__in char* lpszFile, __out LPVOID* pFileBuffer);
		DWORD CopyFileBufferToImageBuffer(__in LPVOID pFileBuffer, __out LPVOID* pImageBuffer);


		//功能函数
		BOOL  RVAToFOA(DWORD RVA, DWORD& FOA,BOOL=FALSE);
		DWORD FeatureCodeMatch(std::vector<unsigned char> hexData, std::vector<unsigned int>& MachAddress, BYTE* bMask, char* szMask, DWORD AddressBase);

		//输出信息
		void Print_All();

		void Print_Usage();
		void Print_DOS_Infomation();
		void Print_Stand_PE_Infomation();
		void Print_Optional_PE_Infomation();
		void Print_Directory_Table_Infomation();
		void Print_Section_Infomation();
		void Print_ImageBuffer_Infomation();
		void Print_Export_Table();
		void Print_Import_Table();

	private:
		//成员
		LPVOID m_FileBuffer;
		LPVOID m_ImageBuffer;
		DWORD  m_ImageBufferSize;
		PIMAGE_DOS_HEADER      m_DOS_Header;
		LPVOID                 m_DosStub;
		DWORD				   m_DosStubSize;
		PIMAGE_NT_HEADERS      m_NT_Header;
		PIMAGE_FILE_HEADER	   m_File_Header;
		PIMAGE_OPTIONAL_HEADER m_Option_Header;
		struct StucDirectoryTable
		{
			_IMAGE_DATA_DIRECTORY export_table;
			_IMAGE_DATA_DIRECTORY import_table;
			_IMAGE_DATA_DIRECTORY resource_table;
			_IMAGE_DATA_DIRECTORY exception_table;
			_IMAGE_DATA_DIRECTORY security_table;
			_IMAGE_DATA_DIRECTORY basereloc_table;
			_IMAGE_DATA_DIRECTORY debuginfo_table;
			_IMAGE_DATA_DIRECTORY copyright_table;
			_IMAGE_DATA_DIRECTORY globalptr_table;
			_IMAGE_DATA_DIRECTORY tls_table;
			_IMAGE_DATA_DIRECTORY loadconfig_table;
			_IMAGE_DATA_DIRECTORY bound_import_table;
			_IMAGE_DATA_DIRECTORY iat_table;
			_IMAGE_DATA_DIRECTORY delay_import_table;
			_IMAGE_DATA_DIRECTORY com_descriptor_table;
			_IMAGE_DATA_DIRECTORY null_table;
		}*m_Diretory_Table;
		vector<pair<string, PIMAGE_SECTION_HEADER>> m_vec_section;
		vector<string> m_vec_import_dllname;

		typedef struct StructV2FAddress
		{
			DWORD rva;
			DWORD va; 
			DWORD foa;
		}V2FAddress, *PV2FAddress;
		typedef struct StructExportFunction
		{
			WORD   serialno;
			string functionanme;
			DWORD  rva_address;
			DWORD  va_address;
			DWORD  foa_address;
			//PExport_Fun_Address address;
		}Exprot_Function,*PExport_Function;

		typedef struct StructExportAddressTable
		{
			V2FAddress serialno_table;
			V2FAddress export_functionname_table;
			V2FAddress export_function_table;
		}ExportAddressTable,*PExportAddressTable;

		vector<pair<string, Exprot_Function>> m_vec_exportfunction;

		struct StructExportTable
		{
			//typedef struct _IMAGE_EXPORT_DIRECTORY {
			//	DWORD   Characteristics;
			//	DWORD   TimeDateStamp;          //创建时间
			//	WORD    MajorVersion;           //主版本号
			//	WORD    MinorVersion;           //次版本号
			//	DWORD   Name;                   //动态库名
			//	DWORD   Base;                   //起始函数序号
			//	DWORD   NumberOfFunctions;      //导出函数的总数
			//	DWORD   NumberOfNames;          //名称导出函数总数量
			//	DWORD   AddressOfFunctions;     //导出函数地址表
			//	DWORD   AddressOfNames;         //导出函数名表
			//	DWORD   AddressOfNameOrdinals;  //导出函数名序号表
			//} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;
			//动态库名
			//
			//导出函数起始序号 - Base
			//导出函数总数
			//函数结构体 |序号|hint|RVA|FOA|VA|Size|函数名| -|汇编代码|C++代码
			// 
			// 
			// 
			//来一个指针
			PIMAGE_EXPORT_DIRECTORY _this;

			//动态库名
			string dllname;
			//创建时间
			string datetime;
			//版本号
			string version;
			//起始序号
			DWORD  serialno;
			//导出函数总数
			DWORD  count;
			//导出函数
			ExportAddressTable function;

			DWORD rva_address;
			DWORD va_address;
			DWORD foa_address;
			DWORD size;

			BOOL isValid;
			//Function SerialNo Table|序号
			//Function NameTable|名称
			//Function Table|函数地址
		}m_Export_Table;

		//PIMAGE_EXPORT_DIRECTORY m_Export_Table;//导出表
		typedef struct StructImportDLLInfo
		{
			std::string dllname;
			DWORD OriginalFirstThunk;
			DWORD FirstThunk;

		}ImportDllInfo , * pImportDllInfo;

		//输入表IAT表，INT表，函数名 函数地址
		typedef struct StrucImportFunc
		{
			DWORD       SerialNumber;
			string      funcName;
		}ImportFunc, * pImportFunc;

		typedef struct StructImportIatAddress
		{
			DWORD dwAddress;
			string funcName;
		}ImportIatAddress, * pImportIatAddress;

		typedef struct StructImportFuncInfo
		{
			BOOL   hasSerialName;
			vector <ImportFunc>       import_functionVec;
			vector <ImportIatAddress> iat_functionvec;
			int    nFunctionCount;
		}ImportFuncInfo,*pImportFuncInfo;

		typedef struct StructINT_Info
		{
			DWORD rva_address;
			DWORD va_address;
			DWORD foa_address;
			int nSize;
		}INT_Info,*pINT_Info;
		typedef struct StructIAT_Info
		{
			DWORD rva_address;
			DWORD va_address;
			DWORD foa_address;
			int nSize;
		}IAT_Info,* pIAT_Info;
		struct StructImportTable//输入表
		{
			union MyUnion
			{
				DWORD Characteristics;
				DWORD OriginalFirstThunk;
			};

			//来一个指针
			PIMAGE_IMPORT_DESCRIPTOR _this;

			DWORD rva_address;
			DWORD va_address;
			DWORD foa_address;
			//pImport_descriptor->OriginalFirstThunk
			vector<ImportDllInfo> dllname_vec;
			//INT Table(导入函数名称表)
			INT_Info import_name_table;
			IAT_Info import_address_table;
			//IAT Table(导入函数地址表)
			//IDT Table(导入DLL表)
			DWORD size;
			BOOL isValid;

			int nDLLCount;
			map<string, ImportFuncInfo> m_map_importdll;
		}m_Import_Table;
		BOOL isMemoryLoad;

		//PIMAGE_DATA_DIRECTORY  m_Diretory_Table;
		//解析方法
		void Anysis_Header();
		void Anysis_Section_Table();
		void Anysis_Export_Table();
		void Anysis_Import_Table();

private:
		//功能函数，私有方法
		BOOL   bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
		int    CalculateThunkData(DWORD ThunkBaseAddr, ImportFuncInfo &importfunc_info);
		int    CalculateFirstThunkData(DWORD FirstThunkBaseAddr, ImportFuncInfo& importfunc_info);

		



public:
	StucDirectoryTable* GetDirectoryTable() { return m_Diretory_Table; }//目录表
};

void OutputDebugStringEx(const char* strOutputString, ...);
