/**************************************************************/
/*
/* ѧϰ��ˮ���� PE�ṹ����������ϰ
/* ������ʦ Bilibili����ˮ��������
/* 
/* PE�ṹ�����࣬�ɶ�ȡPE�ļ�������PEͷ�������ڱ�Ŀ¼�� �Լ����뵼����
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
		PE(const char* path); //PE�๹��
		PE(LPVOID pFileBuffer,BOOL isMemLoad=FALSE);
		~PE();                //PE������

		//��ȡPE���ļ��е�Buffer �� ���ڴ��е�Buffer
		LPVOID GetFileBuffer()  { return m_FileBuffer; }
		LPVOID GetImageBuffer() { return m_ImageBuffer; }
		//����PEͷ
		PIMAGE_DOS_HEADER       GetDosHeader()     { return m_DOS_Header; }    //DOSͷ
		LPVOID					GetDosStub()       { return m_DosStub; }       //DOS������������
		LPVOID			        GetNTHeader()      { return m_NT_Header; }     //NTͷ
		PIMAGE_FILE_HEADER      GetStdPEHeader()   { return m_File_Header; }   //��׼PEͷ
		PIMAGE_OPTIONAL_HEADER  GetOptionPEHeader(){ return m_Option_Header; } //��ѡPEͷ
		DWORD					GetDosStubSize()   { return m_DosStubSize; }   //DOS�����������ݴ�С
		DWORD ReadPE_File(__in char* lpszFile, __out LPVOID* pFileBuffer);
		DWORD CopyFileBufferToImageBuffer(__in LPVOID pFileBuffer, __out LPVOID* pImageBuffer);


		//���ܺ���
		BOOL  RVAToFOA(DWORD RVA, DWORD& FOA,BOOL=FALSE);
		DWORD FeatureCodeMatch(std::vector<unsigned char> hexData, std::vector<unsigned int>& MachAddress, BYTE* bMask, char* szMask, DWORD AddressBase);

		//�����Ϣ
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
		//��Ա
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
			//	DWORD   TimeDateStamp;          //����ʱ��
			//	WORD    MajorVersion;           //���汾��
			//	WORD    MinorVersion;           //�ΰ汾��
			//	DWORD   Name;                   //��̬����
			//	DWORD   Base;                   //��ʼ�������
			//	DWORD   NumberOfFunctions;      //��������������
			//	DWORD   NumberOfNames;          //���Ƶ�������������
			//	DWORD   AddressOfFunctions;     //����������ַ��
			//	DWORD   AddressOfNames;         //������������
			//	DWORD   AddressOfNameOrdinals;  //������������ű�
			//} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;
			//��̬����
			//
			//����������ʼ��� - Base
			//������������
			//�����ṹ�� |���|hint|RVA|FOA|VA|Size|������| -|������|C++����
			// 
			// 
			// 
			//��һ��ָ��
			PIMAGE_EXPORT_DIRECTORY _this;

			//��̬����
			string dllname;
			//����ʱ��
			string datetime;
			//�汾��
			string version;
			//��ʼ���
			DWORD  serialno;
			//������������
			DWORD  count;
			//��������
			ExportAddressTable function;

			DWORD rva_address;
			DWORD va_address;
			DWORD foa_address;
			DWORD size;

			BOOL isValid;
			//Function SerialNo Table|���
			//Function NameTable|����
			//Function Table|������ַ
		}m_Export_Table;

		//PIMAGE_EXPORT_DIRECTORY m_Export_Table;//������
		typedef struct StructImportDLLInfo
		{
			std::string dllname;
			DWORD OriginalFirstThunk;
			DWORD FirstThunk;

		}ImportDllInfo , * pImportDllInfo;

		//�����IAT��INT�������� ������ַ
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
		struct StructImportTable//�����
		{
			union MyUnion
			{
				DWORD Characteristics;
				DWORD OriginalFirstThunk;
			};

			//��һ��ָ��
			PIMAGE_IMPORT_DESCRIPTOR _this;

			DWORD rva_address;
			DWORD va_address;
			DWORD foa_address;
			//pImport_descriptor->OriginalFirstThunk
			vector<ImportDllInfo> dllname_vec;
			//INT Table(���뺯�����Ʊ�)
			INT_Info import_name_table;
			IAT_Info import_address_table;
			//IAT Table(���뺯����ַ��)
			//IDT Table(����DLL��)
			DWORD size;
			BOOL isValid;

			int nDLLCount;
			map<string, ImportFuncInfo> m_map_importdll;
		}m_Import_Table;
		BOOL isMemoryLoad;

		//PIMAGE_DATA_DIRECTORY  m_Diretory_Table;
		//��������
		void Anysis_Header();
		void Anysis_Section_Table();
		void Anysis_Export_Table();
		void Anysis_Import_Table();

private:
		//���ܺ�����˽�з���
		BOOL   bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
		int    CalculateThunkData(DWORD ThunkBaseAddr, ImportFuncInfo &importfunc_info);
		int    CalculateFirstThunkData(DWORD FirstThunkBaseAddr, ImportFuncInfo& importfunc_info);

		



public:
	StucDirectoryTable* GetDirectoryTable() { return m_Diretory_Table; }//Ŀ¼��
};

void OutputDebugStringEx(const char* strOutputString, ...);
