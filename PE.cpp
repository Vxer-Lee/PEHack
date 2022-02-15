#include "PE.h"

#if _WINDOWS 
#define TRACEEX(...) OutputDebugStringEx(__VA_ARGS__) 
#elif _CONSOLE 
#define TRACEEX(...) printf(__VA_ARGS__) 
#else 
#define TRACEEX(...) OutputDebugStringA(__VA_ARGS__)
#endif

void OutputDebugStringEx(const char* strOutputString, ...)
{
	va_list vlArgs = NULL;
	va_start(vlArgs, strOutputString);
	size_t nLen = _vscprintf(strOutputString, vlArgs) + 1;
	char* strBuffer = new char[nLen + 8];
	_vsnprintf_s(strBuffer, nLen, nLen, strOutputString, vlArgs);
	va_end(vlArgs);
	OutputDebugStringA(strBuffer);
	delete[] strBuffer;
}


PE::PE(const char* path)
{
	handle = GetStdHandle(STD_OUTPUT_HANDLE);
	isMemoryLoad = FALSE;
	ReadPE_File((char*)path, &m_FileBuffer);
	Anysis_Header();
	Anysis_Section_Table();
	CopyFileBufferToImageBuffer(m_FileBuffer, &m_ImageBuffer);
	Anysis_Export_Table();
	Anysis_Import_Table();
}
PE::PE(LPVOID pFileBuffer,BOOL isMemLoad)
{
	handle = GetStdHandle(STD_OUTPUT_HANDLE);
	m_FileBuffer = pFileBuffer;
	m_ImageBuffer = pFileBuffer;
	isMemoryLoad = isMemLoad;
	Anysis_Header();
	Anysis_Section_Table();
	Anysis_Export_Table();
	Anysis_Import_Table();
}
PE::~PE()
{
	 free(m_FileBuffer);
	 m_FileBuffer = NULL;
	 m_ImageBuffer = NULL;
	 m_DOS_Header = NULL;
	 m_DosStub = NULL;
	 m_DosStubSize = NULL;
	 m_NT_Header = NULL;
	 m_File_Header = NULL;
	 m_Option_Header = NULL;
	 m_Diretory_Table = NULL;
}

/***********************************
* 函数：bCompare
* 说明：字节比较，比较特征码是否匹配，含有占位符。
*
* 参数：pData    需要比较的数据
*	   bMask    特征码，字节
*      szMask   占位符，匹配
*
* 返回：失败->0
************************************/
BOOL PE::bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)   return 0;
	return (*szMask) == NULL;
}
/***********************************
* 函数：FeatureCodeMatch
* 说明：特征码匹配,将所有匹配的地址push到MachAddress中
*
* 参数：hexData     buffer
*      MachAddress 传出匹配到的地址
*      bMask       特征码
*      szMask      占位符，模糊匹配
*      AddressBase 基地址
*
* 返回：失败->0 成功->寻找到的基地址
************************************/
DWORD PE::FeatureCodeMatch(std::vector<unsigned char> hexData,std::vector<unsigned int> &MachAddress,BYTE* bMask, char* szMask, DWORD AddressBase)
{
	for (DWORD i = 0; i < hexData.size(); i++)
	{
		if (bCompare((BYTE*)&hexData[0]+i, bMask, szMask))
		{
			MachAddress.push_back(AddressBase + i);
		}
	}
	return 0;
}
/***********************************
* 函数：CalculateThunkData
* 说明：计算IMAGE_THUNK_DATA数组的数量，
*      规则是遇到零就停止。
*
*         
* 参数：ThunkBaseAddr(传入的thunkData结构地址)
*      
*
* 返回：失败->0 成功->数量
************************************/
int  PE::CalculateThunkData(DWORD ThunkBaseAddr, ImportFuncInfo &importfunc_info)
{
	int nCount = 0;
	DWORD tmpThunkBaseAddr = ThunkBaseAddr;
	importfunc_info.hasSerialName = false;

	char szMsg[MAX_PATH] = { 0 };
	while (true)
	{
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)tmpThunkBaseAddr;
		//这里判断是否循环结束
		if (pThunk->u1.AddressOfData == 0)
		{
			break;
		}
		//这里判断是否用的是序号方式
		if (0x80000000 & pThunk->u1.AddressOfData)
		{
			//序号名方式
			importfunc_info.hasSerialName = true;
			DWORD Serinumber = pThunk->u1.AddressOfData & 0x7FFFFFFF;
			wsprintfA(szMsg, "函数序号:[%d]", Serinumber);
			
			ImportFunc import_func;
			import_func.SerialNumber = 0;
			import_func.funcName = szMsg;
			importfunc_info.import_functionVec.push_back(import_func);
		}
		else
		{
			//函数名字方式
			DWORD AddressOfDataFOA = 0;
			RVAToFOA(pThunk->u1.AddressOfData, AddressOfDataFOA);
			PIMAGE_IMPORT_BY_NAME pImageImportByName = PIMAGE_IMPORT_BY_NAME((unsigned char*)m_FileBuffer + (isMemoryLoad?pThunk->u1.AddressOfData:AddressOfDataFOA) );

			ImportFunc import_func;
			import_func.SerialNumber = pImageImportByName->Hint;
			import_func.funcName = pImageImportByName->Name;
			importfunc_info.import_functionVec.push_back(import_func);
		}
		nCount++;
		tmpThunkBaseAddr += 4;
	}
	return nCount;
}
/***********************************
* 函数：CalculateThunkData
* 说明：计算IMAGE_THUNK_DATA数组的数量，
*      规则是遇到零就停止。
*
*
* 参数：ThunkBaseAddr(传入的thunkData结构地址)
*
*
* 返回：失败->0 成功->数量
************************************/
int  PE::CalculateFirstThunkData(DWORD FirstThunkBaseAddr, ImportFuncInfo& importfunc_info)
{
	int nCount = 0;
	DWORD tmpThunkBaseAddr = FirstThunkBaseAddr;
	importfunc_info.hasSerialName = false;

	char szMsg[MAX_PATH] = { 0 };
	if (isMemoryLoad)
	{
		while (true)
		{
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)FirstThunkBaseAddr;
			//这里判断循环结束
			if (pThunk->u1.AddressOfData == 0)
			{
				break;
			}
			//内存加载的话不存在序号方式
			ImportIatAddress import_addressfunc;
			import_addressfunc.dwAddress = pThunk->u1.AddressOfData;
			import_addressfunc.funcName  = "";
			importfunc_info.iat_functionvec.push_back(import_addressfunc);
			nCount++;
			FirstThunkBaseAddr += 4;
		}

	}
	else
	{
		while (true)
		{
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)tmpThunkBaseAddr;
			//这里判断是否循环结束
			if (pThunk->u1.AddressOfData == 0)
			{
				break;
			}
			//这里判断是否用的是序号方式
			if (0x80000000 & pThunk->u1.AddressOfData)
			{
				//序号名方式
				importfunc_info.hasSerialName = true;
				DWORD Serinumber = pThunk->u1.AddressOfData & 0x7FFFFFFF;
				wsprintfA(szMsg, "函数序号:[%d]", Serinumber);
				ImportIatAddress import_addressfunc;
				import_addressfunc.dwAddress = pThunk->u1.AddressOfData;
				import_addressfunc.funcName = szMsg;
				importfunc_info.iat_functionvec.push_back(import_addressfunc);
			}
			else
			{
				//函数名字方式
				DWORD AddressOfDataFOA = 0;
				RVAToFOA(pThunk->u1.AddressOfData, AddressOfDataFOA);
				PIMAGE_IMPORT_BY_NAME pImageImportByName = PIMAGE_IMPORT_BY_NAME((unsigned char*)m_FileBuffer + AddressOfDataFOA);
				ImportIatAddress import_addressfunc;
				import_addressfunc.dwAddress = pThunk->u1.AddressOfData;
				import_addressfunc.funcName = pImageImportByName->Name;
				importfunc_info.iat_functionvec.push_back(import_addressfunc);
			}
			nCount++;
			tmpThunkBaseAddr += 4;
		}
	}





	return nCount;
}
/***********************************
* 函数：ReadPEFile
* 说明：读取PE文件到缓冲区中
*
* 参数：lpszFile    文件路径
*	   pFileBuffer 缓冲区指针
*
* 返回：失败->0 成功->实际读取大小
************************************/
DWORD PE::ReadPE_File(__in char* lpszFile, __out LPVOID* pFileBuffer)
{
	FILE* fp = fopen(lpszFile, "rb");
	if (fp == NULL)
	{
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	int nSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (nSize > 0xFFFFFFFF) {
		fclose(fp);
		return 0;
	}
	*pFileBuffer = malloc(nSize);
	fread(*pFileBuffer, 1, nSize, fp);
	fclose(fp);
	return nSize;
}
/***********************************
* 函数：CopyFileBufferToImageBuffer()
* 说明：将文件从FileBuffer 拷贝到ImageBuffer
*
* 参数：pFileBuffer  FileBuffer指针
*	   pImageBuffer ImageBuffer指针
*
* 返回：失败->0 成功->复制的大小
************************************/
DWORD PE::CopyFileBufferToImageBuffer(__in LPVOID pFileBuffer, __out LPVOID* pImageBuffer)
{
	//ImageBuffer的大小
	DWORD nImageBufferSize = m_Option_Header->SizeOfImage;
	*pImageBuffer = VirtualAlloc(NULL, nImageBufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(*pImageBuffer, 0, nImageBufferSize);

	//获取对其大小 和 PE头大小
	int nAllFile_HeaderSize = m_Option_Header->SizeOfHeaders;
	int nFileAlignment = m_Option_Header->FileAlignment;
	int nImageAlignment = m_Option_Header->SectionAlignment;

	//拷贝PE头
	memcpy(*pImageBuffer, pFileBuffer, nAllFile_HeaderSize);
	
	//拷贝节表
	for (vector<pair<string, PIMAGE_SECTION_HEADER>>::iterator iter = m_vec_section.begin(); iter != m_vec_section.end(); iter++)
	{
		DWORD dwVirtualAddress = iter->second->VirtualAddress;
		DWORD dwRawAddress = iter->second->PointerToRawData;
		memcpy((unsigned char*)*pImageBuffer + dwVirtualAddress, (unsigned char*)pFileBuffer + dwRawAddress, iter->second->SizeOfRawData);
	}
	m_ImageBufferSize = nImageBufferSize;
	return nImageBufferSize;
//
//
//	//赋值各个相关字段
//	pDosHeder = (PIMAGE_DOS_HEADER)*pImageBuffer;
//	pNtHeder = (PIMAGE_NT_HEADERS)((char*)*pImageBuffer + pDosHeder->e_lfanew);
//	pFileHeder = (PIMAGE_FILE_HEADER)&pNtHeder->FileHeader;
//	pOptHeder = (PIMAGE_OPTIONAL_HEADER)&pNtHeder->OptionalHeader;
//	pSec = (PIMAGE_SECTION_HEADER)&pNtHeder[1];
//	
//	pOptHeder->ImageBase = (DWORD)(unsigned char*)*pImageBuffer;
//
//	DWORD dwOEP = IMAGE_NT_HREADERS_2.OptionalHeader.AddressOfEntryPoint + (DWORD)(unsigned char*)*pImageBuffer;
//	DWORD OldProtext = 0;
//	VirtualProtect((LPVOID)dwOEP, nImageBufferSize, PAGE_EXECUTE_READWRITE, &OldProtext);
//	return 0;
}

/***********************************
* 函数：Anysis_Header
* 说明：解析PE头
* **********************************/
void PE::Anysis_Header()
{
	m_DOS_Header     = (PIMAGE_DOS_HEADER)m_FileBuffer;
	m_DosStub        = ((unsigned char*)m_FileBuffer + sizeof(_IMAGE_DOS_HEADER));
	m_NT_Header      = (PIMAGE_NT_HEADERS) ( (DWORD) ((unsigned char*)m_FileBuffer + m_DOS_Header->e_lfanew) );
	m_File_Header    = (PIMAGE_FILE_HEADER)&m_NT_Header->FileHeader;
	m_Option_Header  = (PIMAGE_OPTIONAL_HEADER)&m_NT_Header->OptionalHeader;
	m_DosStubSize    = (DWORD)m_NT_Header - (DWORD)m_DosStub;
	m_Diretory_Table = (StucDirectoryTable*)&m_NT_Header->OptionalHeader.DataDirectory;
}

/************************************
* 函数：ReadSection_Table
* 说明：解析PE节表
* ************************************/
void PE::Anysis_Section_Table()
{
	DWORD dwAddress = (DWORD)(unsigned char*)m_FileBuffer + sizeof(*m_DOS_Header) + m_DosStubSize + sizeof(*m_NT_Header);
	PIMAGE_SECTION_HEADER tmp_section_header = (PIMAGE_SECTION_HEADER)dwAddress;

	for (size_t i = 0; i < m_NT_Header->FileHeader.NumberOfSections; i++)
	{
		string strTemp = (char*)tmp_section_header->Name;
		m_vec_section.push_back(pair<string, PIMAGE_SECTION_HEADER>(strTemp, tmp_section_header));
		tmp_section_header = (PIMAGE_SECTION_HEADER)((DWORD)(unsigned char*)tmp_section_header + sizeof(_IMAGE_SECTION_HEADER));
	}
}

/************************************
* 函数：Anysis_Export_Table
* 说明：解析导出表
* ************************************/
void PE::Anysis_Export_Table()
{
	//1.解析导出表，需要先根据目录表中找到导出表的地址和大小
	DWORD RVA_ExportTable = m_Diretory_Table->export_table.VirtualAddress;
	//如果RVA_ExportTable为0 说明没有导入表就不在解析了
	if (RVA_ExportTable == 0 || m_Diretory_Table->export_table.Size<=0 )
	{
		m_Export_Table.isValid = false;
		return;
	}
	DWORD dwSize_ExportTable = m_Diretory_Table->export_table.Size;
	DWORD FOA_ExportTable = 0;
	RVAToFOA(RVA_ExportTable, FOA_ExportTable);
	m_Export_Table.rva_address = RVA_ExportTable;
	m_Export_Table.va_address  = m_Option_Header->ImageBase +  RVA_ExportTable;
	m_Export_Table.foa_address = FOA_ExportTable;
	m_Export_Table.size = dwSize_ExportTable;
	//2.解析导出表名字,导出表创建时间,导出表版本号,导出表总数
	//导出表指针
	m_Export_Table._this = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)m_FileBuffer + (isMemoryLoad?RVA_ExportTable:FOA_ExportTable) );
	//[创建时间TimeDateStamp]
	struct  tm test_gmtime_s;
	test_gmtime_s = *gmtime((time_t*)&m_Export_Table._this->TimeDateStamp);
	//errno_t err = gmtime_s(&test_gmtime_s, (time_t*)&m_Export_Table._this->TimeDateStamp);
	char Time_Temp[256] = { 0 };
	sprintf(Time_Temp, "%d年%d月%d日 %02d时:%02d分:%02d秒(周%d)", test_gmtime_s.tm_year + 1900, test_gmtime_s.tm_mon, test_gmtime_s.tm_mday,
		test_gmtime_s.tm_hour + 8, test_gmtime_s.tm_min, test_gmtime_s.tm_sec, test_gmtime_s.tm_wday);
	m_Export_Table.datetime = Time_Temp;
	//[版本号MajorVersion&MinorVersion]
	char Temp[20] = { 0 };
	sprintf(Temp, "%2d.%2d", m_Export_Table._this->MajorVersion, m_Export_Table._this->MinorVersion);
	m_Export_Table.version = Temp;
	//[文件名Name]
	char dllname[256] = { 0 };
	DWORD RVA_DLLName = m_Export_Table._this->Name;
	DWORD VA_DLLName = m_Option_Header->ImageBase + RVA_DLLName;
	DWORD FOA_DLLName = 0;
	RVAToFOA(RVA_DLLName, FOA_DLLName);
	sprintf(dllname, "%s", (char*)(unsigned char*)m_FileBuffer + (isMemoryLoad?RVA_DLLName:FOA_DLLName) );
	m_Export_Table.dllname = dllname;
	//[导出函数起始序号 Base]
	m_Export_Table.serialno = m_Export_Table._this->Base;
	//[导出函数总数量 NumberOfFunctions NumberOfNames]
	m_Export_Table.count = m_Export_Table._this->NumberOfFunctions;

	//[函数名序号表]
	DWORD RVA_Serialno = m_Export_Table._this->AddressOfNameOrdinals;
	DWORD VA_Serialno = m_Option_Header->ImageBase + RVA_Serialno;
	DWORD FOA_Serialno = 0;
	RVAToFOA(RVA_Serialno, FOA_Serialno);
	//[函数名称表]
	DWORD RVA_ExportFunctionName = m_Export_Table._this->AddressOfNames;
	DWORD VA_ExportFunctionName = m_Option_Header->ImageBase + RVA_ExportFunctionName;
	DWORD FOA_ExportFunctionName = 0;
	RVAToFOA(RVA_ExportFunctionName, FOA_ExportFunctionName);
	//[函数地址表]
	DWORD RVA_ExportFunction = m_Export_Table._this->AddressOfFunctions;
	DWORD VA_ExportFunction = m_Option_Header->ImageBase + RVA_ExportFunction;
	DWORD FOA_ExportFunction = 0;
	RVAToFOA(RVA_ExportFunction, FOA_ExportFunction);
	//赋值
	m_Export_Table.function.serialno_table.rva = RVA_Serialno;
	m_Export_Table.function.serialno_table.va = VA_Serialno;
	m_Export_Table.function.serialno_table.foa = FOA_Serialno;
	m_Export_Table.function.export_functionname_table.rva = RVA_ExportFunctionName;
	m_Export_Table.function.export_functionname_table.va = VA_ExportFunctionName;
	m_Export_Table.function.export_functionname_table.foa = FOA_ExportFunctionName;
	m_Export_Table.function.export_function_table.rva = RVA_ExportFunction;
	m_Export_Table.function.export_function_table.va = VA_ExportFunction;
	m_Export_Table.function.export_function_table.foa = FOA_ExportFunction;

	//开始遍历导出函数
	Exprot_Function function;
	WORD  exportfun_serino = 0;
	char  exportfun_szName[256] = { 0 };
	DWORD exportfun_rva_address = 0;
	DWORD exportfun_va_address = 0;
	DWORD exportfun_foa_address = 0;
	vector <string> func_names;
	vector <DWORD> func_address;
	vector <WORD> func_serinumbers;
	DWORD tmp = 0;

	//地址表
	for (size_t i = 0; i < m_Export_Table.count; i++)
	{
		DWORD dwFunAddr = *((DWORD*)((unsigned char*)m_FileBuffer + (isMemoryLoad ? RVA_ExportFunction : FOA_ExportFunction)) + i);
		func_address.push_back(dwFunAddr);
	}
	//名字表
	for (size_t i = 0; i < m_Export_Table._this->NumberOfNames; i++)
	{
		DWORD dwFunName = *((DWORD*)((unsigned char*)m_FileBuffer + (isMemoryLoad ? RVA_ExportFunctionName : FOA_ExportFunctionName)) + i);
		RVAToFOA(dwFunName, tmp);
		string name = (char*)(unsigned char*)m_FileBuffer + (isMemoryLoad?dwFunName:tmp);
		func_names.push_back(name);
	}
	//序号表
	for (size_t i = 0; i < m_Export_Table._this->NumberOfNames; i++)
	{
		int nIndex    = i;
		DWORD Offset  = (isMemoryLoad ? RVA_Serialno : FOA_Serialno);//序号表偏移
		LPVOID pbuf   = (unsigned char*)m_FileBuffer + Offset ;      //PE文件内容Buffer
		WORD wOrdinal = *( (WORD*)pbuf+ nIndex);                     //强转WORD* [nIdex]序号表索引
		     wOrdinal = m_Export_Table._this->Base + wOrdinal;       //取出序号 + Base
		func_serinumbers.push_back(wOrdinal);
	}


	DWORD tmpfoa = 0;
	char szTmp[512] = { 0 };
	for (size_t i = 0; i < func_address.size(); i++)
	{
		//函数地址，RVA 、VA、FOA
		function.rva_address = func_address[i];
		if (function.rva_address <= 0)
		{
			function.va_address = m_Option_Header->AddressOfEntryPoint;
		}
		else
		{
			function.va_address = m_Option_Header->ImageBase + function.rva_address;
		}
		RVAToFOA(function.rva_address, tmpfoa);
		function.foa_address = tmpfoa;

		//function.serialno = exportfun_serino;
		//function.functionanme = exportfun_szName;
		// 
		//函数地址索引
		int nFunAddrIndex = i+m_Export_Table._this->Base;
		//查序号表
		vector<WORD>::iterator iter = find(func_serinumbers.begin(), func_serinumbers.end(), nFunAddrIndex);
		if (iter!= func_serinumbers.end())
		{
			//用函数名方式导出
			function.serialno = *iter;
			int nPos = std::distance(func_serinumbers.begin(), iter);// std::begin(func_serinumbers)
			function.functionanme = func_names[nPos];
		}
		else
		{
			//用序号名方式导出
			function.serialno = nFunAddrIndex;
			wsprintfA(szTmp,"[序号名:%d]", function.serialno);
			function.functionanme = szTmp;
		}
		m_vec_exportfunction.push_back(pair<string, Exprot_Function>(function.functionanme, function));
	}
	m_Export_Table.isValid = true;
	return;

	////按照函数名解析的话有4个。
	////按照序号解析的话也是4个.
	////所以我还是按照序号来进行解析吧，因为不用序号进行解析的话 那速度就是太慢了。 
	//for (size_t i = 0; i < m_Export_Table.count; i++)
	//{
	//	//取出函数地址、名字表RVA、序号
	//	DWORD dwFunAddr = *((DWORD*)((unsigned char*)m_FileBuffer + (isMemoryLoad?RVA_ExportFunction:FOA_ExportFunction) ) + i);
	//	//判断地址是否有效
	//	//if (dwFunAddr == 0)
	//	//{
	//	//	continue;
	//	//}
	//	DWORD dwFunName = *((DWORD*)((unsigned char*)m_FileBuffer + (isMemoryLoad?RVA_ExportFunctionName:FOA_ExportFunctionName) ) + i);
	//	WORD   wOrdinal = *(WORD*)((unsigned char*)m_FileBuffer   + (isMemoryLoad?RVA_Serialno:FOA_Serialno) ) + i;

	//	
	//	int n = 5;
	//	//这里可以优化!
	//	DWORD temp_funname_rva = *((DWORD*)((unsigned char*)m_FileBuffer + FOA_ExportFunctionName) + i);
	//	DWORD temp_funname_foa = 0;
	//	RVAToFOA(temp_funname_rva, temp_funname_foa);
	//	DWORD temp_fun_rva = *((DWORD*)((unsigned char*)m_FileBuffer + FOA_ExportFunction) + i);
	//	DWORD temp_fun_foa = 0;
	//	RVAToFOA(temp_fun_rva, temp_fun_foa);

	//	//取出函数名称
	//	strcpy(exportfun_szName, (char*)(unsigned char*)m_FileBuffer + temp_funname_foa);
	//	//取出序号
	//	exportfun_serino = *(WORD*)((unsigned char*)m_FileBuffer + FOA_Serialno) + i;
	//	//取出地址
	//	exportfun_rva_address = temp_fun_rva;
	//	//VA
	//	exportfun_va_address = m_Option_Header->ImageBase + exportfun_rva_address;
	//	//FOA
	//	exportfun_foa_address = temp_fun_foa;

	//	Exprot_Function function;
	//	function.serialno = exportfun_serino;
	//	function.functionanme = exportfun_szName;
	//	function.rva_address = exportfun_rva_address;
	//	function.va_address = exportfun_va_address;
	//	function.foa_address = exportfun_foa_address;
	//	//赋值给vector
	//	m_vec_exportfunction.push_back(pair<string, Exprot_Function>(exportfun_szName, function));
	//}
	//m_Export_Table.isValid = true;
}
/************************************
* 函数：Anysis_Import_Table
* 说明：解析导入表
* ************************************/
void PE::Anysis_Import_Table()
{
	//1.解析导入表，需要先根据目录表中找到导入表的地址和大小
	DWORD RVA_ImportTable = m_Diretory_Table->import_table.VirtualAddress;
	//如果RVA_ImportTable为0 说明没有导入表,就不再解析了。
	if (RVA_ImportTable == 0)
	{
		m_Import_Table.isValid = false;
		return;
	}
	DWORD dwSize_ImportTable = m_Diretory_Table->import_table.Size;
	//RVA VA 大小基址赋值
	DWORD FOA_ImportTable = 0;
	RVAToFOA(RVA_ImportTable, FOA_ImportTable);
	m_Import_Table.rva_address = RVA_ImportTable;
	m_Import_Table.va_address = m_Option_Header->ImageBase + RVA_ImportTable;
	m_Import_Table.foa_address = FOA_ImportTable;
	m_Import_Table.size = dwSize_ImportTable;

	DWORD tmp = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImport_descriptorTmp = (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char*)m_FileBuffer + (isMemoryLoad?RVA_ImportTable:FOA_ImportTable) + sizeof(IMAGE_IMPORT_DESCRIPTOR) );
	m_Import_Table.import_name_table.rva_address = pImport_descriptorTmp->OriginalFirstThunk;
	m_Import_Table.import_name_table.va_address = pImport_descriptorTmp->OriginalFirstThunk + m_Option_Header->ImageBase;
	RVAToFOA(pImport_descriptorTmp->OriginalFirstThunk, tmp);
	m_Import_Table.import_name_table.foa_address = tmp;
	m_Import_Table.import_name_table.nSize = 0;
	DWORD tmp2 = 0;
	m_Import_Table.import_address_table.rva_address = pImport_descriptorTmp->FirstThunk;
	m_Import_Table.import_address_table.va_address = pImport_descriptorTmp->FirstThunk + m_Option_Header->ImageBase;
	RVAToFOA(pImport_descriptorTmp->FirstThunk, tmp2);
	m_Import_Table.import_address_table.foa_address = tmp2;
	m_Import_Table.import_address_table.nSize = 0;

	//DLL名字
	//pImport_descriptorTmp->Name
	RVAToFOA(pImport_descriptorTmp->Name, tmp);


	//DLL名字不能这样解析，得根据dll名字表来进行遍历到底有多少dll名
	//2. 解析导入表，DLL名字 -->vector 数组赋值
	PIMAGE_IMPORT_DESCRIPTOR pImport_descriptor = NULL;
	int nDllCount = 0;
	DWORD dwLen = 0;
	int i = 0;
	if (pImport_descriptorTmp->Name!=0)
	{
		while (true)
		{
			LPCSTR c_dllname = (char*)((unsigned char*)m_FileBuffer + (isMemoryLoad ? pImport_descriptorTmp->Name : tmp) + dwLen);
			if (strlen(c_dllname) == 0)
			{
				break;
			}
			//根据DLL名字来进行循环.
			pImport_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char*)m_FileBuffer + (isMemoryLoad ? RVA_ImportTable : FOA_ImportTable) + sizeof(IMAGE_IMPORT_DESCRIPTOR) * i);
			//std::string str_dllname = dllname;
			DWORD foa = 0;
			RVAToFOA(pImport_descriptor->Name, foa);
			std::string dllname = (char*)((unsigned char*)m_FileBuffer + (isMemoryLoad ? pImport_descriptor->Name : foa));
			ImportDllInfo tmp_dllinfo;
			tmp_dllinfo.dllname = dllname;
			tmp_dllinfo.OriginalFirstThunk = pImport_descriptor->OriginalFirstThunk;
			tmp_dllinfo.FirstThunk = pImport_descriptor->FirstThunk;
			m_vec_import_dllname.push_back(dllname);
			m_Import_Table.dllname_vec.push_back(tmp_dllinfo);
			dwLen += strlen(c_dllname) + 1;
			nDllCount++;
			i++;
		}
	}



	//for (size_t i = 0; i < dwSize_ImportTable / sizeof(IMAGE_IMPORT_DESCRIPTOR); i++)
	//{
	//	pImport_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char*)m_FileBuffer + (isMemoryLoad?RVA_ImportTable:FOA_ImportTable) + sizeof(IMAGE_IMPORT_DESCRIPTOR) * i);
	//	//DLL名
	//	if (pImport_descriptor->Name != 0)
	//	{
	//		DWORD foa = 0;
	//		RVAToFOA(pImport_descriptor->Name, foa);
	//		std::string dllname = (char*)((unsigned char*)m_FileBuffer + (isMemoryLoad?pImport_descriptor->Name:foa) );
	//		TRACEEX("引用动态库:%s,(%d)\n", dllname.c_str() , nDllCount);
	//		ImportDllInfo tmp_dllinfo;
	//		tmp_dllinfo.dllname = dllname;
	//		tmp_dllinfo.OriginalFirstThunk = pImport_descriptor->OriginalFirstThunk;
	//		tmp_dllinfo.FirstThunk         = pImport_descriptor->FirstThunk;

	//		m_vec_import_dllname.push_back(dllname);
	//		m_Import_Table.dllname_vec.push_back(tmp_dllinfo);
	//		nDllCount++;
	//	}
	//}
	m_Import_Table.nDLLCount = nDllCount;
	//3. 解析导入表，Dll 函数名|序号名 , IAT表
	for (size_t i = 0; i < m_Import_Table.dllname_vec.size(); i++)
	{
		
		//TRACEEX("-----------------------------%s-------------------------------\n", m_Import_Table.dllname_vec[i].dllname.c_str());
		//INT表
		ImportFuncInfo importfunc_info;
		int nFunctionCount=0;
		if (m_Import_Table.dllname_vec[i].OriginalFirstThunk!=0)
		{
			DWORD ThunkBaseAddr = 0;
			DWORD ThunkBaseAddrFOA = 0;
			RVAToFOA(m_Import_Table.dllname_vec[i].OriginalFirstThunk, ThunkBaseAddrFOA);
			ThunkBaseAddr = (DWORD)((unsigned char*)m_FileBuffer + (isMemoryLoad ? m_Import_Table.dllname_vec[i].OriginalFirstThunk : ThunkBaseAddrFOA));

			nFunctionCount = CalculateThunkData(ThunkBaseAddr, importfunc_info);
			m_Import_Table.import_name_table.nSize += nFunctionCount * (DWORD)(sizeof(IMAGE_THUNK_DATA));
		}

		if (m_Import_Table.dllname_vec[i].FirstThunk!=0)
		{
			//IAT表
			DWORD FirstThunkAddr = 0;
			DWORD FirstThunkAddrFOA = 0;
			RVAToFOA(m_Import_Table.dllname_vec[i].FirstThunk, FirstThunkAddrFOA);
			FirstThunkAddr = (DWORD)((unsigned char*)m_FileBuffer + (isMemoryLoad ? m_Import_Table.dllname_vec[i].FirstThunk : FirstThunkAddrFOA));

			int nIatAddressCount = CalculateFirstThunkData(FirstThunkAddr, importfunc_info);
			m_Import_Table.import_address_table.nSize += nIatAddressCount * (DWORD)(sizeof(IMAGE_THUNK_DATA));
		}


		importfunc_info.nFunctionCount = nFunctionCount;
		m_Import_Table.m_map_importdll.insert(std::pair<std::string, ImportFuncInfo>(m_Import_Table.dllname_vec[i].dllname, importfunc_info));
		//TRACEEX("---------------------------------------------------------------------------\n");
	}
}
/************************************
* 函数：RVAToFOA
* 说明：从内存偏移转换到文件偏移
* ************************************/
BOOL PE::RVAToFOA(DWORD RVA,DWORD &FOA,BOOL IsEnableLog)
{
	/*
	* 计算公式：
	*         	    1. 先计算出此RVA 属于那个节
					2. 该节与文件节的差值k
					3. RVA - 差 = FOA
	*/
	if (IsEnableLog)
	{
		TRACEEX("\n----RVA信息----\n");
	}
	
	DWORD min = m_vec_section.begin()->second->VirtualAddress;
	DWORD max = (m_vec_section.end()-1) ->second->VirtualAddress;
	string max_name = (char*)(m_vec_section.end() - 1)->second->Name;
	DWORD  max_size = (m_vec_section.end() - 1)->second->Misc.VirtualSize;
	DWORD  max_foa = (m_vec_section.end() - 1)->second->PointerToRawData;
	if (RVA < min || RVA > max)
	{
		if (IsEnableLog)
		{
			TRACEEX("RVA范围错误!\n");
			TRACEEX("-------------\n\n");
		}
		return FALSE;
	}
	else
	{
		//这里直接判断掉是否属于最后一个节，方便后面vector的遍历了.
		if (RVA >= max && RVA <= (max+ max_size))
		{

			//根据公式计算
			int k = max - max_foa;
			FOA = RVA - k;
			if (IsEnableLog)
			{
				TRACEEX("隶属于(%s)节,RVA=0x%08X,FOA=0x%08X\n", max_name.c_str(), max, max_foa);
				TRACEEX("当前文件偏移:[0x%08X] RVA:0x%08x\n", FOA,RVA);
				TRACEEX("-------------\n\n");
			}
			return TRUE;
		}
	}
	//遍历属于哪个节,因为最后一个节已经判断过了,所以可以直接排除掉最后一个节.
	string BelongToSectionName;
	int    Currentflag;
	for (vector<pair<string, PIMAGE_SECTION_HEADER>>::iterator iter = m_vec_section.begin(); iter != m_vec_section.end()-1; iter++)
	{
		DWORD address     = iter->second->VirtualAddress;
		DWORD address_foa = iter->second->PointerToRawData;
		if (RVA >= address && RVA < (iter+1)->second->VirtualAddress)
		{
			//根据公式计算
			int k = address - address_foa;
			FOA = RVA - k;
			if (IsEnableLog)
			{
				TRACEEX("隶属于(%s)节,RVA=0x%08X,FOA=0x%08X\n", iter->second->Name, address, address_foa);
				TRACEEX("当前文件偏移:[0x%08X] RVA:0x%08x\n", FOA,RVA);
				TRACEEX("-------------\n\n");
			}
			return TRUE;
		}
	}
	return TRUE;
	//接下来进行判断 属于哪个节.     输入的RVA:0x000b447c
	//(.text)节 RVA : 0x00001000, FOA : 0x00000600, 差值(K) = 0x00000A00(2560)
	//(.data)节 RVA : 0x0009E000, FOA : 0x0009D600, 差值(K) = 0x00000A00(2560)
	//(.rdata)节RVA : 0x000A0000, FOA : 0x0009F400, 差值(K) = 0x00000C00(3072)
	//(.bss)节  RVA : 0x000B3000, FOA : 0x00000000, 差值(K) = 0x000B3000(733184)
	//(.edata)节RVA : 0x000B4000, FOA : 0x000B1E00, 差值(K) = 0x00002200(8704)
	//(.idata)节RVA : 0x000B7000, FOA : 0x000B4200, 差值(K) = 0x00002E00(11776)
	//(.CRT)节  RVA : 0x000B8000, FOA : 0x000B5000, 差值(K) = 0x00003000(12288)
	//(.tls)节  RVA : 0x000B9000, FOA : 0x000B5200, 差值(K) = 0x00003E00(15872)
	//(.rsrc)节 RVA : 0x000BA000, FOA : 0x000B5400, 差值(K) = 0x00004C00(19456)
	//(.reloc)节RVA : 0x000BB000, FOA : 0x000B5A00, 差值(K) = 0x00005600(22016)
	//(/ 4)节   RVA : 0x000BF000, FOA : 0x000B9000, 差值(K) = 0x00006000(24576)
	//(/ 19)节  RVA : 0x000C0000, FOA : 0x000B9400, 差值(K) = 0x00006C00(27648)
	//(/ 31)节  RVA : 0x000CA000, FOA : 0x000C2E00, 差值(K) = 0x00007200(29184)
	//(/ 45)节  RVA : 0x000CC000, FOA : 0x000C4A00, 差值(K) = 0x00007600(30208)
	//(/ 57)节  RVA : 0x000CE000, FOA : 0x000C6600, 差值(K) = 0x00007A00(31232)
	//(/ 70)节  RVA : 0x000CF000, FOA : 0x000C7000, 差值(K) = 0x00008000(32768)
	//(/ 81)节  RVA : 0x000D0000, FOA : 0x000C7400, 差值(K) = 0x00008C00(35840)
	//(/ 92)节  RVA : 0x000D2000, FOA : 0x000C9200, 差值(K) = 0x00008E00(36352)
}

void PE::Print_All()
{
	Print_Usage();
	Print_DOS_Infomation();
	Print_Stand_PE_Infomation();
	Print_Optional_PE_Infomation();
	Print_Directory_Table_Infomation();
	Print_Section_Infomation();
	Print_ImageBuffer_Infomation();
	Print_Export_Table();
	Print_Import_Table();
}
void PE::Print_Usage()
{
	TRACEEX("\n");
	TRACEEX("\n");
	TRACEEX("██████╗ ███████╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗\n");
	TRACEEX("██╔══██╗██╔════╝    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝\n");
	TRACEEX("██████╔╝█████╗      ███████║███████║██║     █████╔╝\n");
	TRACEEX("██╔═══╝ ██╔══╝      ██╔══██║██╔══██║██║     ██╔═██╗\n");
	TRACEEX("██║     ███████╗    ██║  ██║██║  ██║╚██████╗██║  ██╗\n");
	TRACEEX("╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\n");
	TRACEEX("                     From PTU&三进制安全 Team. VxerLee\n");
	TRACEEX("\n");
	TRACEEX("\n");


}
void PE::Print_DOS_Infomation()
{
	TRACEEX("---------------PE头数据----------------\n");
	//输出DOS头信息
	TRACEEX("--> DOS头(_IMAGE_DOS_HEADER ) <--\n");

	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	char szMagic[3] = { 0 };
	memcpy(szMagic, &m_DOS_Header->e_magic, 2);
	TRACEEX("*DOS头魔数:0x%x|%s\n", m_DOS_Header->e_magic, szMagic);
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX("[Bytes on last page]:0x%x\n", m_DOS_Header->e_cblp);
	TRACEEX("[Pages in file]:0x%x\n", m_DOS_Header->e_cp);
	TRACEEX("[Relocations]:0x%x\n", m_DOS_Header->e_crlc);
	TRACEEX("[Size of header]:0x%x\n", m_DOS_Header->e_cparhdr);
	TRACEEX("[Minium memory]:0x%x\n", m_DOS_Header->e_minalloc);
	TRACEEX("[Maxium Memory]:0x%x\n", m_DOS_Header->e_maxalloc);
	TRACEEX("[Inital SS value]:0x%x\n", m_DOS_Header->e_ss);
	TRACEEX("[Inital SP value]:0x%x\n", m_DOS_Header->e_sp);
	TRACEEX("[Checksum]:0x%x\n", m_DOS_Header->e_csum);
	TRACEEX("[Inital IP value]:0x%x\n", m_DOS_Header->e_ip);
	TRACEEX("[Inital CS value]:0x%x\n", m_DOS_Header->e_cs);
	TRACEEX("[Table offset]:0x%x\n", m_DOS_Header->e_lfarlc);
	TRACEEX("[Overlay number]:0x%x\n", m_DOS_Header->e_ovno);
	TRACEEX("[Reserved words]:", m_DOS_Header->e_res);
	for (size_t i = 0; i < 4; i++)
	{
		TRACEEX("0x%x, ", m_DOS_Header->e_res[0]);
	}
	TRACEEX("\n");
	TRACEEX("[OEM id]:0x%x\n", m_DOS_Header->e_oemid);
	TRACEEX("[OEM infomation]:0x%x\n", m_DOS_Header->e_oeminfo);
	TRACEEX("[Reserved words]:", m_DOS_Header->e_res2);
	for (size_t i = 0; i < 10; i++)
	{
		TRACEEX("0x%x, ", m_DOS_Header->e_res2[0]);
	}
	TRACEEX("\n");
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*PE文件头地址:0x%x\n", m_DOS_Header->e_lfanew);
	SetConsoleTextAttribute(handle, 0x07);

	TRACEEX("DOS头大小:%d\n", sizeof(*m_DOS_Header));
	TRACEEX("\n");
}
void PE::Print_Stand_PE_Infomation()
{
	//输出标准PE头信息
	TRACEEX("--> 标准PE头(_IMAGE_FILE_HEADER) <--\n");

	char szNTSignature[3] = { 0 };
	memcpy(szNTSignature, &m_NT_Header->Signature, 2);
	TRACEEX("[NT头标识]:%s\n", szNTSignature);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[运行平台]:0x%x\n", m_File_Header->Machine);
	TRACEEX("*[节数量]:0x%x\n", m_File_Header->NumberOfSections);
	TRACEEX("*[时间戳]:0x%x\n", m_File_Header->TimeDateStamp);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
	struct  tm test_gmtime_s;
	errno_t err = gmtime_s(&test_gmtime_s, (time_t*)&m_File_Header->TimeDateStamp);
	TRACEEX("  文件创建时间:%d年%d月%d日 %02d时:%02d分:%02d秒(周%d)\n", test_gmtime_s.tm_year + 1900, test_gmtime_s.tm_mon, test_gmtime_s.tm_mday,
		test_gmtime_s.tm_hour + 8, test_gmtime_s.tm_min, test_gmtime_s.tm_sec, test_gmtime_s.tm_wday);
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX("[Pointer to COFF]:0x%x\n", m_File_Header->PointerToSymbolTable);
	TRACEEX("[COFF table size]:0x%x\n", m_File_Header->NumberOfSections);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[可选头大小]:0x%x\n", m_File_Header->SizeOfOptionalHeader);
	TRACEEX("*[特征/特性]:0x%x\n", m_File_Header->Characteristics);
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX("标准PE头大小:%d\n", sizeof(*m_File_Header));
	TRACEEX("\n");
}
void PE::Print_Optional_PE_Infomation()
{
	//输出可选PE头信息
	TRACEEX("--> 可选PE头(_IMAGE_OPTIONAL_HEADER) <--\n");

	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
	TRACEEX("*[程序内存入口点]:0x%x\n", m_Option_Header->AddressOfEntryPoint + m_Option_Header->ImageBase);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[可选PE头魔数]:0x%x\n", m_Option_Header->Magic);
	TRACEEX("*[主链接器版本]:0x%x\n", m_Option_Header->MajorLinkerVersion);
	TRACEEX("*[副链接器版本]:0x%x\n", m_Option_Header->MinorLinkerVersion);
	TRACEEX("*[代码段大小]:0x%x\n", m_Option_Header->SizeOfCode);
	TRACEEX("*[初始化数据大小]:0x%x\n", m_Option_Header->SizeOfInitializedData);
	TRACEEX("*[未初始化数据大小]:0x%x\n", m_Option_Header->SizeOfUninitializedData);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("*[程序入口点]:0x%x\n", m_Option_Header->AddressOfEntryPoint);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[代码段地址]:0x%x\n", m_Option_Header->BaseOfCode);
	TRACEEX("*[数据段地址]:0x%x\n", m_Option_Header->BaseOfData);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("*[PE文件基地址]:0x%x\n", m_Option_Header->ImageBase);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("[内存对其大小]:0x%x\n", m_Option_Header->SectionAlignment);
	TRACEEX("[文件对其大小]:0x%x\n", m_Option_Header->FileAlignment);
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX("[操作系统的主版本号]:0x%x\n", m_Option_Header->MajorOperatingSystemVersion);
	TRACEEX("[操作系统的次版本号]:0x%x\n", m_Option_Header->MinorOperatingSystemVersion);
	TRACEEX("[程序主版本号]:0x%x\n", m_Option_Header->MajorImageVersion);
	TRACEEX("[程序次版本号]:0x%x\n", m_Option_Header->MinorImageVersion);
	TRACEEX("[子系统主版本号]:0x%x\n", m_Option_Header->MajorSubsystemVersion);
	TRACEEX("[子系统次版本号]:0x%x\n", m_Option_Header->MinorSubsystemVersion);
	TRACEEX("[Win32版本值]:0x%x\n", m_Option_Header->Win32VersionValue);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("*[在内存中PE大小 SizeOfImage]:0x%x\n", m_Option_Header->SizeOfImage);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[DOS|PE|节头大小]:0x%x\n", m_Option_Header->SizeOfHeaders);
	TRACEEX("*[内存映像hash]:0x%x\n", m_Option_Header->CheckSum);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[程序类型]:0x%x\n", m_Option_Header->Subsystem);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[DLL映像的特征]:0x%x\n", m_Option_Header->DllCharacteristics);
	TRACEEX("*[获取保留堆栈的大小]:0x%x\n", m_Option_Header->SizeOfStackReserve);
	TRACEEX("*[获取要提交堆栈的大小]:0x%x\n", m_Option_Header->SizeOfStackCommit);
	TRACEEX("*[获取保留堆空间的大小]:0x%x\n", m_Option_Header->SizeOfHeapReserve);
	TRACEEX("*[获取要提交的本地堆空间大小]:0x%x\n", m_Option_Header->SizeOfHeapCommit);
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX("[加载标志(已废弃)]:0x%x\n", m_Option_Header->LoaderFlags);
	TRACEEX("[获取PEHeader剩余部分数据,位置和大小]:0x%x\n", m_Option_Header->NumberOfRvaAndSizes);
	TRACEEX("[指向IMAGE_DATA_DIRECTORY结构指针]:0x%x\n", m_Option_Header->DataDirectory);
	TRACEEX("可选PE头大小:%d\n", sizeof(*m_Option_Header));
	TRACEEX("\n");
}
void PE::Print_Directory_Table_Infomation()
{
	//输出目录数据
	TRACEEX("--> 目录表(_IMAGE_DATA_DIRECTORY[16]) <--\n");
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("*[导出表]----RVA:0x%x,  大小:0x%x\n", m_Diretory_Table->export_table.VirtualAddress, m_Diretory_Table->export_table.Size);
	TRACEEX("*[导入表]----RVA:0x%x,  大小:0x%x\n", m_Diretory_Table->import_table.VirtualAddress, m_Diretory_Table->import_table.Size);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX(" [资源]------RVA:0x%x,  大小:0x%x\n", m_Diretory_Table->resource_table.VirtualAddress,m_Diretory_Table->resource_table.Size);
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX(" [异常]------RVA:0x%x,     大小:0x%x\n",m_Diretory_Table->exception_table.VirtualAddress, m_Diretory_Table->exception_table.Size);
	TRACEEX(" [安全证书]--RVA:0x%x,     大小:0x%x\n",m_Diretory_Table->security_table.VirtualAddress,m_Diretory_Table->security_table.Size);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[重定位表]--RVA:0x%x,  大小:0x%x\n",m_Diretory_Table->basereloc_table.VirtualAddress,m_Diretory_Table->basereloc_table.Size);
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX(" [调试信息]--RVA:0x%x,  大小:0x%x\n", m_Diretory_Table->debuginfo_table.VirtualAddress,m_Diretory_Table->debuginfo_table.Size);
	TRACEEX(" [版权所有]--RVA:0x%x,     大小:0x%x\n", m_Diretory_Table->copyright_table.VirtualAddress,m_Diretory_Table->copyright_table.Size);
	TRACEEX(" [全局指针]--RVA:0x%x,     大小:0x%x\n", m_Diretory_Table->globalptr_table.VirtualAddress,m_Diretory_Table->globalptr_table.Size);
	TRACEEX(" [TLS表]-----RVA:0x%x,     大小:0x%x\n", m_Diretory_Table->tls_table.VirtualAddress,m_Diretory_Table->tls_table.Size);
	TRACEEX(" [加载配置]--RVA:0x%x,  大小:0x%x\n", m_Diretory_Table->loadconfig_table.VirtualAddress,m_Diretory_Table->loadconfig_table.Size);
	TRACEEX(" [绑定导入]--RVA:0x%x,     大小:0x%x\n", m_Diretory_Table->bound_import_table.VirtualAddress,m_Diretory_Table->bound_import_table.Size);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("*[IAT表]-----RVA:0x%x,  大小:0x%x\n",m_Diretory_Table->iat_table.VirtualAddress,m_Diretory_Table->iat_table.Size);
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX(" [延迟导入]--RVA:0x%x,     大小:0x%x\n", m_Diretory_Table->delay_import_table.VirtualAddress,m_Diretory_Table->delay_import_table.Size);
	TRACEEX(" [COM]-------RVA:0x%x,     大小:0x%x\n", m_Diretory_Table->com_descriptor_table.VirtualAddress, m_Diretory_Table->com_descriptor_table.Size);
	TRACEEX(" [保留]------RVA:0x%x,     大小:0x%x\n", m_Diretory_Table->null_table.VirtualAddress, m_Diretory_Table->null_table.Size);
	TRACEEX("目录表大小:%d\n", sizeof(IMAGE_DATA_DIRECTORY));
	TRACEEX("\n");
}
void PE::Print_Section_Infomation()
{
	TRACEEX("---------------节表数据----------------\n");
	TRACEEX("节数量:%d\n", m_vec_section.size());
	//遍历map容器 ，所有节数量
	for (vector<pair<string, PIMAGE_SECTION_HEADER>>::iterator iter = m_vec_section.begin(); iter!= m_vec_section.end(); iter++)
	{
		TRACEEX("--> %s段信息 <--\n", iter->first.c_str());
		SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
		TRACEEX("*[内存中段大小]:0x%x\n", iter->second->Misc.VirtualSize);
		SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
		TRACEEX("*[内存中偏移]:0x%x\n", iter->second->VirtualAddress);
		SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
		TRACEEX("*[文件中段大小]:0x%x\n", iter->second->SizeOfRawData);
		SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
		TRACEEX("*[文件中偏移]:0x%x\n", iter->second->PointerToRawData);
		SetConsoleTextAttribute(handle, 0x07);
		TRACEEX("[OBJ重定位偏移]:0x%x\n", iter->second->PointerToRelocations);
		TRACEEX("[OBJ重定位项数目]:0x%x\n", iter->second->NumberOfRelocations);
		TRACEEX("[行号表偏移]:0x%x\n", iter->second->PointerToLinenumbers);
		TRACEEX("[行号表中的数目]:0x%x\n",iter->second->NumberOfLinenumbers);
		SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
		TRACEEX("*[标志|属性]:0x%x ", iter->second->Characteristics);
		//区段的属性
		DWORD l_Charctieristics = (BYTE)((DWORD)(iter->second->Characteristics) & 0xFF);
		DWORD h_Charctieristics = (BYTE)(((DWORD)(iter->second->Characteristics) >> 24) & 0xFF);

		vector<byte> l_flag;
		vector<byte> h_flag;
		//低位
		l_flag.push_back((l_Charctieristics >> 7) ? 3 : 0);
		l_flag.push_back((l_Charctieristics >> 6) & 1 ? 2 : 0);
		l_flag.push_back((l_Charctieristics >> 5) & 1 ? 1 : 0);
		//高位
		h_flag.push_back((h_Charctieristics >> 7) ? 7 : 0);
		h_flag.push_back((h_Charctieristics >> 6) & 1 ? 6 : 0);
		h_flag.push_back((h_Charctieristics >> 5) & 1 ? 5 : 0);
		h_flag.push_back((h_Charctieristics >> 4) & 1 ? 4 : 0);

		//包含数据情况
		SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
		for (vector<byte>::iterator iter = l_flag.begin(); iter != l_flag.end(); iter++)
		{
			switch (*iter)
			{
			case 1:
				TRACEEX("(包含可执行代码),");
				break;
			case 2:
				TRACEEX("(包含已初始化数据),");
				break;
			case 3:
				TRACEEX("(包含未初始化数据),");
				break;
			default:
				break;
			}
		}
		//可读写执行情况
		for (vector<byte>::iterator iter = h_flag.begin(); iter != h_flag.end(); iter++)
		{
			switch (*iter)
			{
			case 4:
				TRACEEX("(共享),");
				break;
			case 5:
				TRACEEX("(可执行),");
				break;
			case 6:
				TRACEEX("(可读),");
				break;
			case 7:
				TRACEEX("(可写),");
				break;
			default:
				break;
			}
		}
		TRACEEX("\n\n");
		SetConsoleTextAttribute(handle, 0x07);
	}
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
	TRACEEX("--> 标志(属性块) 常用特征值对照表：<--\n");
	TRACEEX("[值:00000020h](*包含可执行代码)\n");//IMAGE_SCN_CNT_CODE
	TRACEEX("[值:00000040h](*该块包含已初始化的数据)\n");//IMAGE_SCN_CNT_INITIALIZED_DATA
	TRACEEX("[值:00000080h](*该块包含未初始化的数据)\n");//IMAGE_SCN_CNT_UNINITIALIZED_DATA
	TRACEEX("[值:00000200h][Section contains comments or some other type of information.]\n");//IMAGE_SCN_LNK_INFO
	TRACEEX("[值:00000800h][Section contents will not become part of image.]\n");//IMAGE_SCN_LNK_REMOVE
	TRACEEX("[值:00001000h][Section contents comdat.]\n");//IMAGE_SCN_LNK_COMDAT
	TRACEEX("[值:00004000h][Reset speculative exceptions handling bits in the TLB entries for this section.]\n");//IMAGE_SCN_NO_DEFER_SPEC_EXC
	TRACEEX("[值:00008000h][Section content can be accessed relative to GP.]\n");// IMAGE_SCN_GPREL
	TRACEEX("[值:00500000h][Default alignment if no others are specified.]\n");//IMAGE_SCN_ALIGN_16BYTES  
	TRACEEX("[值:01000000h][Section contains extended relocations.]\n");//IMAGE_SCN_LNK_NRELOC_OVFL
	TRACEEX("[值:02000000h][Section can be discarded.]\n");//IMAGE_SCN_MEM_DISCARDABLE
	TRACEEX("[值:04000000h][Section is not cachable.]\n");//IMAGE_SCN_MEM_NOT_CACHED
	TRACEEX("[值:08000000h][Section is not pageable.]\n");//IMAGE_SCN_MEM_NOT_PAGED
	TRACEEX("[值:10000000h](*该块为共享块).\n");//IMAGE_SCN_MEM_SHARED
	TRACEEX("[值:20000000h](*该块可执行)\n");//IMAGE_SCN_MEM_EXECUTE
	TRACEEX("[值:40000000h](*该块可读)\n");//IMAGE_SCN_MEM_READ
	TRACEEX("[值:80000000h](*该块可写)\n\n");// IMAGE_SCN_MEM_WRITE
	SetConsoleTextAttribute(handle, 0x07);//IMAGE_SCN_MEM_WRITE
}
void PE::Print_ImageBuffer_Infomation()
{
	TRACEEX("---------------内存镜像信息----------------\n");
	TRACEEX("内存镜像地址:0x%08X\n", m_ImageBuffer);
	if (!isMemoryLoad)
	{
		TRACEEX("内存镜像大小:0x%08X(%dbyte/%.2fkb/%.2fmb)\n\n", m_ImageBufferSize, m_ImageBufferSize, (float)m_ImageBufferSize / 1024, (float)m_ImageBufferSize / 1024 / 1024);
	}
}
void PE::Print_Export_Table()
{
	if (!m_Export_Table.isValid)
	{
		return;
	}
	TRACEEX("---------------导出表数据----------------\n");
	TRACEEX("\n--> 导出表位置及大小 <--\n");
	TRACEEX("[导出表偏移]:0x%08X\n", m_Export_Table.rva_address);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[导出表内存位置]:0x%08X\n",m_Export_Table.va_address);
	TRACEEX("*[导出表文件位置]:0x%X\n", m_Export_Table.foa_address);
	TRACEEX("*[导出表大小]:0x%x(%d)\n", m_Export_Table.size, m_Export_Table.size);
	SetConsoleTextAttribute(handle, 0x07);

	TRACEEX("\n--> 导出表基础信息 <--\n");
	TRACEEX("[特征信息]:0x%08X\n", m_Export_Table._this->Characteristics);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[动态库名]:%s\n", m_Export_Table.dllname.c_str());
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("[创建时间:]%s\n", m_Export_Table.datetime.c_str());
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX("[版本号:]%s\n", m_Export_Table.version.c_str());
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("[导出函数总数量]:%d\n", m_Export_Table.count);
	TRACEEX("[匿名导出函数]:%d\n", m_Export_Table.count - m_Export_Table._this->NumberOfNames);
	TRACEEX("[导出函数起始序号]:%d\n", m_Export_Table.serialno);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("[函数序号表]:0x%0X (内存位置:0x%08X|文件位置:0x%08X)\n", m_Export_Table.function.serialno_table.rva, m_Export_Table.function.serialno_table.va, m_Export_Table.function.serialno_table.foa);
	TRACEEX("[函数名称表]:0x%0X (内存位置:0x%08X|文件位置:0x%08X)\n", m_Export_Table.function.export_functionname_table.rva, m_Export_Table.function.export_functionname_table.va, m_Export_Table.function.export_functionname_table.foa);
	TRACEEX("[函数地址表]:0x%0X (内存位置:0x%08X|文件位置:0x%08X)\n", m_Export_Table.function.export_function_table.rva , m_Export_Table.function.export_function_table.va, m_Export_Table.function.export_function_table.foa);
	SetConsoleTextAttribute(handle, 0x07);

	TRACEEX("\n--> 导出表函数列表 <--\n");
	//遍历 m_vec_exportfunction

	//遍历容器 ，所有导出函数
	TRACEEX("|序号|   内存偏移  |   内存地址  |    文件地址   |   函数名   \n");
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
	for (vector<pair<string, Exprot_Function>>::iterator iter = m_vec_exportfunction.begin(); iter != m_vec_exportfunction.end(); iter++)
	{
		TRACEEX(" %.4d\t 0x%-8X   0x%08X      0x%-8X   %s\n", iter->second.serialno,iter->second.rva_address, iter->second.va_address, iter->second.foa_address, iter->first.c_str());
	}
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX("\n\n");
}
void PE::Print_Import_Table()
{
	if (!m_Import_Table.isValid)
	{
		return;
	}
	TRACEEX("---------------导入表数据----------------\n");
	TRACEEX("\n--> 导入表位置及大小 <--\n");
	TRACEEX("[导入表偏移]:0x%08X\n",m_Import_Table.rva_address);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
	TRACEEX("*[导入表内存位置]:0x%08X\n", m_Import_Table.va_address);
	TRACEEX("*[导入表文件位置]:0x%X\n", m_Import_Table.foa_address);
	TRACEEX("*[导入表大小]:0x%x(%d)\n", m_Import_Table.size, m_Import_Table.size);
	SetConsoleTextAttribute(handle, 0x07);

	TRACEEX("\n--> 导入表基础信息 <--\n");
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("[DLL数量]:%d\n", m_Import_Table.nDLLCount);
	SetConsoleTextAttribute(handle, 0x07);

	TRACEEX("\n--> INT表信息 <--\n");
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	TRACEEX("[INT表RVA]:0x%08X\n", m_Import_Table.import_name_table.rva_address);
	TRACEEX("[INT表内存位置]:0x%08X\n", m_Import_Table.import_name_table.va_address);
	TRACEEX("[INT表文件位置]:0x%08X\n", m_Import_Table.import_name_table.foa_address);
	TRACEEX("[INT表大小]:0x%x(%d)\n", m_Import_Table.import_name_table.nSize);
	SetConsoleTextAttribute(handle, 0x07);

	TRACEEX("\n--> IAT表信息 <--\n");
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
	TRACEEX("[IAT表RVA]:0x%08X\n", m_Import_Table.import_address_table.rva_address);
	TRACEEX("[IAT表内存位置]:0x%08X\n", m_Import_Table.import_address_table.va_address);
	TRACEEX("[IAT表文件位置]:0x%08X\n", m_Import_Table.import_address_table.foa_address);
	TRACEEX("[IAT表大小]:0x%x(%d)\n", m_Import_Table.import_address_table.nSize);
	//SetConsoleTextAttribute(handle, 0x07);
    //SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	if (isMemoryLoad)
	{
		for (map<string, ImportFuncInfo>::iterator iter = m_Import_Table.m_map_importdll.begin(); iter != m_Import_Table.m_map_importdll.end(); iter++)
		{
			SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
			TRACEEX("\n-----------------------------------------[%s]----------------------------------------\n", iter->first.c_str());
			TRACEEX("|序号|   内存地址  |   函数名   \n");
			SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
			vector<ImportIatAddress>::iterator iat_iter = iter->second.iat_functionvec.begin();
			for (vector<ImportFunc>::iterator func_iter = iter->second.import_functionVec.begin(); func_iter != iter->second.import_functionVec.end(); func_iter++)
			{
				TRACEEX(" %.4d\t 0x%08X   %s\n", func_iter->SerialNumber, iat_iter->dwAddress,func_iter->funcName.c_str());
				iat_iter++;
			}
		}
	}
	else
	{
		for (map<string, ImportFuncInfo>::iterator iter = m_Import_Table.m_map_importdll.begin(); iter != m_Import_Table.m_map_importdll.end(); iter++)
		{
			SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_RED);
			TRACEEX("\n-----------------------------------------[%s]----------------------------------------\n", iter->first.c_str());
			TRACEEX("|序号|   函数名   \n");
			SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
			for (vector<ImportFunc>::iterator func_iter = iter->second.import_functionVec.begin(); func_iter != iter->second.import_functionVec.end(); func_iter++)
			{
				TRACEEX(" %.4d\t %s\n", func_iter->SerialNumber, func_iter->funcName.c_str());
			}
		}
	}
	SetConsoleTextAttribute(handle, 0x07);
	TRACEEX("\n\n");
}