// ========================================================================================================================
// Scant
//
// Copyright ©2007 Liam Kirton <liam@int3.ws>
// ========================================================================================================================
// Scant.cpp
//
// Created: 16/03/2007
// ========================================================================================================================

#include <winsock2.h>
#include <windows.h>

#include <iphlpapi.h>
#include <wincrypt.h>

#include <algorithm>
#include <cmath>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <string>
#include <vector>

#include <pcap.h>

#include "Scant.h"

// ========================================================================================================================

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType);

DWORD WINAPI PcapListenThreadProc(LPVOID lpParameter);
void OnListenArp(pcap_pkthdr *pPktHeader, const u_char *pPktData);
void OnListenIpIcmp(pcap_pkthdr *pPktHeader, const u_char *pPktData);
void OnListenIpTcp(pcap_pkthdr *pPktHeader, const u_char *pPktData);
void OnListenIpUdp(pcap_pkthdr *pPktHeader, const u_char *pPktData);

DWORD WINAPI PcapScanThreadProc(LPVOID lpParameter);
DWORD WINAPI ResolveThreadProc(LPVOID lpParameter);

void GenerateScanStructs(std::string &targetString, std::string &portString);
void PrintResults(std::ostream &stream, std::ifstream &inOui);

void PrintResultsHostName(std::ostream &stream, const u_int ip);
void PrintResultsMacVendor(std::ostream &stream, std::ifstream &inOui, const u_char *mac);
void PrintResultsResponsesRange(std::ostream &stream, std::map<u_short, u_short> &responses, u_short responseType);

void PrintUsage();

// ========================================================================================================================

const char *g_cScantVersion = "0.4.10";

// ========================================================================================================================

CRITICAL_SECTION g_ConsoleCriticalSection;
HANDLE g_hExitEvent = NULL;
HANDLE g_hPcapListenThread = NULL;
HANDLE g_hPcapScanThread = NULL;
HANDLE g_hResolveThread = NULL;
HCRYPTPROV g_hCryptProv = NULL;

pcap_if_t *g_pDevice = NULL;
pcap_t *g_pAdapter = NULL;
PIP_ADAPTER_INFO g_pAdapterInfo = NULL;

u_short g_ScanType = 0x0000;
std::map<u_int, ScanStruct *> g_ScanStructs;
std::vector<u_short> g_ScanPorts;

u_short g_SourcePort = 0x0000;

bool g_bResolveHosts = false;
HANDLE g_hHostNamesMutex = NULL;
std::map<u_int, std::string> g_HostNames;

bool g_bNonAdapterIp = false;
u_int g_SourceIp = 0x00000000;
u_int g_SourceNetMask = 0x00000000;
u_int g_DefaultRouteIp = 0x00000000;
ScanStruct *g_DefaultRouteScanStruct = NULL;

u_int g_uPacketAttemptCount = 1;
u_int g_uPacketBlockCount = 1;
u_int g_uPacketIntervalMs = 100;
u_int g_uPacketQueueCount = 32;
u_int g_uWaitEndMs = 2500;
LARGE_INTEGER g_lCounterLastActivity;

// ========================================================================================================================

int main(int argc, char *argv[])
{
	std::cout << std::endl
			  << "Scant " << g_cScantVersion << std::endl
			  << "Copyright \xB8" << "2007-2008 Liam Kirton <liam@int3.ws>" << std::endl
			  << std::endl
			  << "Built at " << __TIME__ << " on " << __DATE__ << std::endl << std::endl;

	u_int uDeviceId = 0xFFFFFFFF;
	std::string portString;
	std::string outputFileName;
	std::string targetString;

	if(timeBeginPeriod(1) != TIMERR_NOERROR)
	{
		std::cout << "WARNING: timeBeginPeriod(1) Failed." << std::endl << std::endl;
	}

	try
	{
		for(int i = 1; i < argc; ++i)
		{
			std::string cmd = argv[i];
			std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

			if((cmd == "/device") && ((i + 1) < argc))
			{
				uDeviceId = static_cast<u_int>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "/target") && ((i + 1) < argc))
			{
				targetString = argv[++i];
			}
			else if((cmd == "/port") && ((i + 1) < argc))
			{
				portString = argv[++i];
			}
			else if(cmd == "/rst")
			{
				g_ScanType |= ScanTypeRst;
			}
			else if((cmd == "/sport") && ((i + 1) < argc))
			{
				g_ScanType |= ScanTypeSport;
				g_SourcePort = htons(static_cast<u_short>(strtol(argv[++i], NULL, 10)));
			}
			else if((cmd == "/ip") && ((i + 1) < argc))
			{
				g_SourceIp = inet_addr(argv[++i]);
			}
			else if((cmd == "/netmask") && ((i + 1) < argc))
			{
				g_SourceNetMask = inet_addr(argv[++i]);
			}
			else if((cmd == "/route") && ((i + 1) < argc))
			{
				g_DefaultRouteIp = inet_addr(argv[++i]);
			}
			else if((cmd == "/interval") && ((i + 1) < argc))
			{
				g_uPacketIntervalMs = static_cast<u_int>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "/block") && ((i + 1) < argc))
			{
				g_uPacketBlockCount = static_cast<u_int>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "/queue") && ((i + 1) < argc))
			{
				g_uPacketQueueCount = static_cast<u_int>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "/retry") && ((i + 1) < argc))
			{
				g_uPacketAttemptCount = static_cast<u_int>(strtol(argv[++i], NULL, 10)) + 1;
			}
			else if(cmd == "/arp")
			{
				g_ScanType |= ScanTypeArp;
			}
			else if(cmd == "/tcp")
			{
				g_ScanType |= ScanTypeTcp;
			}
			else if(cmd == "/udp")
			{
				g_ScanType |= ScanTypeUdp;
			}
			else if(cmd == "/dummy")
			{
				g_ScanType |= ScanTypeDummy;
			}
			else if((cmd == "/output") && ((i + 1) < argc))
			{
				outputFileName = argv[++i];
			}
			else if(cmd == "/verbose")
			{
				g_ScanType |= ScanTypeVerbose;
			}
			else if(cmd == "/resolve")
			{
				g_bResolveHosts = true;
			}
			else
			{
				throw std::exception("Unknown Command.");
			}
		}

		if((uDeviceId == 0xFFFFFFFF) || (targetString == "") ||
		   ((portString == "") && ((g_ScanType & ScanTypeTcp) || (g_ScanType & ScanTypeUdp))))
		{
			throw std::exception("Required Parameter Not Specified.");
		}
		else if((g_ScanType & ScanTypeArp) && ((g_ScanType & ScanTypeTcp) || (g_ScanType & ScanTypeUdp)))
		{
			throw std::exception("Incompatible Scan Types Specified.");
		}
		else if(!((g_ScanType & ScanTypeArp) || (g_ScanType & ScanTypeTcp) || (g_ScanType & ScanTypeUdp)))
		{
			throw std::exception("No Scan Type Specified.");
		}
		
		u_int minPacketBlockCount = 0;
		for(u_int i = 4; i < 32; ++i)
		{
			if(g_ScanType & (1 << i))
			{
				minPacketBlockCount++;
			}
		}
		if(minPacketBlockCount == 0)
		{
			minPacketBlockCount = 1;
		}
		if((g_uPacketBlockCount % minPacketBlockCount) != 0)
		{
			g_uPacketBlockCount = minPacketBlockCount;
		}
		if((g_uPacketQueueCount % g_uPacketBlockCount) != 0)
		{
			g_uPacketQueueCount += (g_uPacketQueueCount % g_uPacketBlockCount);
		}
		if(g_uWaitEndMs < (g_uPacketIntervalMs * 2))
		{
			g_uWaitEndMs = g_uPacketIntervalMs * 2;
		}
	}
	catch(const std::exception &e)
	{
		PrintUsage();
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *pDeviceList = NULL;
	pcap_if_t *pDeviceEnum = NULL;
	PIP_ADAPTER_INFO pAdapterInfo = NULL;

	InitializeCriticalSection(&g_ConsoleCriticalSection);
	SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE);

	try
	{
		if(!CryptAcquireContext(&g_hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
		{
			if(!CryptAcquireContext(&g_hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				throw std::exception("CryptAcquireContext() Failed.");
			}
		}

		if((g_hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		{
			throw std::exception("CreateEvent() Failed.");
		}

		if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &pDeviceList, pcapErrorBuffer) == -1)
		{
			throw std::exception("pcap_findalldevs_ex() Failed.");
		}

		u_int uDeviceEnum = 0;
		pDeviceEnum = pDeviceList;
		while(pDeviceEnum != NULL)
		{
			if(++uDeviceEnum == uDeviceId)
			{
				g_pDevice = pDeviceEnum;

				std::string targetDeviceName = g_pDevice->name;
				size_t npfOffset = targetDeviceName.find("NPF_");
				if(npfOffset == std::string::npos)
				{
					throw std::exception("Device Name Format Not Recognised.");
				}
				targetDeviceName = targetDeviceName.substr(npfOffset + 4);

				u_int uBufferSize = 0;
				if(GetAdaptersInfo(pAdapterInfo, reinterpret_cast<PULONG>(&uBufferSize)) == ERROR_BUFFER_OVERFLOW)
				{
					pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(new char[uBufferSize]);
					if(GetAdaptersInfo(pAdapterInfo, reinterpret_cast<PULONG>(&uBufferSize)) != ERROR_SUCCESS)
					{
						throw std::exception("GetAdaptersAddresses(pAdapterInfo) Failed.");
					}

					PIP_ADAPTER_INFO pAdapterInfoEnum = pAdapterInfo;
					do
					{
						if(targetDeviceName.compare(pAdapterInfoEnum->AdapterName) == 0)
						{
							g_pAdapterInfo = pAdapterInfoEnum;
							break;
						}
					}
					while(pAdapterInfoEnum = pAdapterInfoEnum->Next);

					if(pAdapterInfoEnum == NULL)
					{
						throw std::exception("Unable to Match Winpcap Device To Windows Device.");
					}
				}
				break;
			}
			pDeviceEnum = pDeviceEnum->next;
		}
		if((pDeviceEnum == NULL) || (g_pDevice == NULL) || (g_pAdapterInfo == NULL))
		{
			throw std::exception("Winpcap Device Not Found.");
		}

		if((g_SourceIp == 0x00000000) || (g_SourceNetMask == 0x00000000))
		{
			g_SourceIp = inet_addr(g_pAdapterInfo->IpAddressList.IpAddress.String);
			g_SourceNetMask = inet_addr(g_pAdapterInfo->IpAddressList.IpMask.String);
			if(g_DefaultRouteIp == 0x00000000)
			{
				g_DefaultRouteIp = inet_addr(g_pAdapterInfo->GatewayList.IpAddress.String);	
			}

			if(g_SourceIp == g_DefaultRouteIp)
			{
				throw std::exception("Default Route Ip Equal To Source Ip.");
			}
		}
		else if(g_SourceIp != inet_addr(g_pAdapterInfo->IpAddressList.IpAddress.String))
		{
			g_bNonAdapterIp = true;
		}

		GenerateScanStructs(targetString, portString);

		if((g_pAdapter = pcap_open(g_pDevice->name,
								   65536,
								   0,
								   1,
								   NULL,
								   pcapErrorBuffer)) == NULL)
		{
			throw std::exception("pcap_open() Failed.");
		}

		if((g_hPcapListenThread = CreateThread(NULL, 0, PcapListenThreadProc, NULL, 0, NULL)) == NULL)
		{
			throw std::exception("CreateThread() Failed.");
		}
		if((g_hPcapScanThread = CreateThread(NULL, 0, PcapScanThreadProc, NULL, 0, NULL)) == NULL)
		{
			throw std::exception("CreateThread() Failed.");
		}

		if((g_hHostNamesMutex = CreateMutex(NULL, FALSE, NULL)) == NULL)
		{
			throw std::exception("CreateMutex() Failed.");
		}
		if((g_hResolveThread = CreateThread(NULL, 0, ResolveThreadProc, NULL, 0, NULL)) == NULL)
		{
			throw std::exception("CreateThread() Failed.");
		}

		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Running. Press Ctrl+C to Abort." << std::endl << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		if(e.what()[0] != '\0')
		{
			std::cout << std::endl << "Error: " << e.what() << std::endl << std::endl;
		}
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	if(g_hPcapScanThread != NULL)
	{
		if(WaitForSingleObject(g_hPcapScanThread, INFINITE) != WAIT_OBJECT_0)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << std::endl << "Warning: WaitForSingleObject() Failed." << std::endl << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);
		}
		CloseHandle(g_hPcapScanThread);
		g_hPcapScanThread = NULL;

	}

	if(g_hExitEvent != NULL)
	{
		SetEvent(g_hExitEvent);
	}

	if(g_hPcapListenThread != NULL)
	{
		if(WaitForSingleObject(g_hPcapListenThread, INFINITE) != WAIT_OBJECT_0)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << std::endl << "Warning: WaitForSingleObject() Failed." << std::endl << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);
		}
		CloseHandle(g_hPcapListenThread);
		g_hPcapListenThread = NULL;
	}
	if(g_hResolveThread != NULL)
	{
		if(WaitForSingleObject(g_hResolveThread, INFINITE) != WAIT_OBJECT_0)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << std::endl << "Warning: WaitForSingleObject() Failed." << std::endl << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);
		}
		CloseHandle(g_hResolveThread);
		g_hResolveThread = NULL;
	}
	if(g_hHostNamesMutex != NULL)
	{
		CloseHandle(g_hHostNamesMutex);
		g_hHostNamesMutex = NULL;
	}

	if(!g_ScanStructs.empty())
	{
		if(!(g_ScanType & ScanTypeDummy))
		{
			char modulePath[1024];
			DWORD dwModulePathCount = 0;
			if((dwModulePathCount = GetModuleFileName(NULL, modulePath, sizeof(modulePath))) == 0)
			{
				throw std::exception("GetModuleFileName() Failed.");
			}

			for(DWORD i = dwModulePathCount; i >= 0; --i)
			{
				if(modulePath[i] == '\\')
				{
					modulePath[i + 1] = '\0';
					break;
				}
			}
			
			std::string ouiDat = modulePath;
			ouiDat += "Oui.dat";

			std::ifstream inOui(ouiDat.c_str(), std::ios::in);
			std::stringstream resultsStream;
			PrintResults(resultsStream, inOui);
			inOui.close();

			std::cout << std::endl
					  << "Results: " << std::endl
					  << std::endl
					  << resultsStream.str();

			std::ofstream outputFile(outputFileName.c_str(), std::ios::out | std::ios::trunc);
			if(!outputFile.is_open())
			{
				std::exception("Could Not Open Specified Output File.");
			}
			else
			{
				outputFile << std::endl
						   << "Scant " << g_cScantVersion << std::endl
						   << "Copyright (C)2007-2008 Liam Kirton <liam@int3.ws>" << std::endl
						   << std::endl
						   << "Built at " << __TIME__ << " on " << __DATE__ << std::endl
						   << std::endl
						   << resultsStream.str();
				outputFile.flush();
				outputFile.close();
			}
		}

		for(std::map<u_int, ScanStruct *>::iterator i = g_ScanStructs.begin(); i != g_ScanStructs.end(); ++i)
		{		
			if(i->second->hMutex != NULL)
			{
				CloseHandle(i->second->hMutex);
				i->second->hMutex = NULL;
				delete i->second;
			}
		}

		g_ScanStructs.clear();
	}
	
	if(pDeviceList != NULL)
	{
		pcap_freealldevs(pDeviceList);
		pDeviceList = NULL;
		pDeviceEnum = NULL;
		g_pDevice = NULL;
	}
	if(g_pAdapter != NULL)
	{
		pcap_close(g_pAdapter);
		g_pAdapter = NULL;
	}
	if(pAdapterInfo != NULL)
	{
		delete [] pAdapterInfo;
		pAdapterInfo = NULL;
	}
	
	if(g_hCryptProv != NULL)
	{
		CryptReleaseContext(g_hCryptProv, 0);
		g_hCryptProv = NULL;
	}

	if(g_hExitEvent != NULL)
	{
		CloseHandle(g_hExitEvent);
		g_hExitEvent = NULL;
	}

	SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, FALSE);
	DeleteCriticalSection(&g_ConsoleCriticalSection);

	if(timeEndPeriod(1) != TIMERR_NOERROR)
	{
		std::cout << "WARNING: timeEndPeriod(1) Failed." << std::endl << std::endl;
	}

	return 0;
}

// ========================================================================================================================

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType)
{
	if(g_hExitEvent != NULL)
	{
		SetEvent(g_hExitEvent);
	}
	return TRUE;
}

// ========================================================================================================================

DWORD WINAPI PcapListenThreadProc(LPVOID lpParameter)
{
	try
	{
		pcap_pkthdr *pPktHeader = NULL;
		const u_char *pPktData = NULL;

		while(WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0)
		{
			int pktResult = pcap_next_ex(g_pAdapter, &pPktHeader, &pPktData);
			if(pktResult < 0)
			{
				break;
			}
			else if((pktResult == 0) || (pPktHeader->caplen < sizeof(EthernetFrameHeader)))
			{
				continue;
			}

			const EthernetFrameHeader *pktEthernetFrameHeader = reinterpret_cast<const EthernetFrameHeader *>(pPktData);
			switch(pktEthernetFrameHeader->Type)
			{
				case EtherTypeArp:
					if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader)))
					{
						OnListenArp(pPktHeader, pPktData);
					}
					break;

				case EtherTypeIp:
					if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader)))
					{
						const IpPacketHeader *pktIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
						switch(pktIpPacketHeader->Protocol)
						{
							case IpProtocolIcmp:
								if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader)))
								{
									OnListenIpIcmp(pPktHeader, pPktData);
								}
								break;

							case IpProtocolTcp:
								if((pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(TcpPacketHeader))) &&
								   (g_ScanType & ScanTypeTcp))
								{
									OnListenIpTcp(pPktHeader, pPktData);
								}
								break;

							case IpProtocolUdp:
								if((pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(UdpPacketHeader))) &&
								   (g_ScanType & ScanTypeUdp))
								{
									OnListenIpUdp(pPktHeader, pPktData);
								}
								break;

							default:
								break;							
						}
					}
					break;

				default:
					break;
			}
		}
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Error: " << e.what() << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	SetEvent(g_hExitEvent);
	return 0;
}

// ========================================================================================================================

void OnListenArp(pcap_pkthdr *pPktHeader, const u_char *pPktData)
{
	const ArpPacketHeader *pktArpPacketHeader = reinterpret_cast<const ArpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
	switch(pktArpPacketHeader->Operation)
	{
		case ArpOperationWhoHas:
			if(g_bNonAdapterIp && (pktArpPacketHeader->TargetProtocolAddress == g_SourceIp))
			{
				EnterCriticalSection(&g_ConsoleCriticalSection);
				std::cout << "ARP WHO-HAS " << ((g_SourceIp & 0x000000FF)) << "."
											<< ((g_SourceIp & 0x0000FF00) >> 8) << "."
											<< ((g_SourceIp & 0x00FF0000) >> 16) << "."
											<< ((g_SourceIp & 0xFF000000) >> 24) << " TELL "
											<< ((pktArpPacketHeader->SenderProtocolAddress & 0x000000FF)) << "."
											<< ((pktArpPacketHeader->SenderProtocolAddress & 0x0000FF00) >> 8) << "."
											<< ((pktArpPacketHeader->SenderProtocolAddress & 0x00FF0000) >> 16) << "."
											<< ((pktArpPacketHeader->SenderProtocolAddress & 0xFF000000) >> 24) << " ("
											<< std::hex
											<< std::setfill('0')
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[0]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[1]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[2]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[3]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[4]) << ":"
											<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[5]) << ")"
											<< std::dec << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);

				const u_int arpRespPktMemSize = (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));
				u_char *arpRespPktData = new u_char[arpRespPktMemSize];

				EthernetFrameHeader *arpRespPktEthernetFrameHeader = reinterpret_cast<EthernetFrameHeader *>(arpRespPktData);
				SecureZeroMemory(arpRespPktEthernetFrameHeader, sizeof(EthernetFrameHeader));
				RtlCopyMemory(&arpRespPktEthernetFrameHeader->SourceMac, &g_pAdapterInfo->Address, 6);
				RtlCopyMemory(&arpRespPktEthernetFrameHeader->DestinationMac, &pktArpPacketHeader->SenderHardwareAddress, 6);
				arpRespPktEthernetFrameHeader->Type = EtherTypeArp;

				ArpPacketHeader *arpRespPktArpPacketHeader = reinterpret_cast<ArpPacketHeader *>(arpRespPktData + sizeof(EthernetFrameHeader));
				SecureZeroMemory(arpRespPktArpPacketHeader, sizeof(ArpPacketHeader));
				arpRespPktArpPacketHeader->HardwareAddressSpace = 0x0100;
				arpRespPktArpPacketHeader->ProtocolAddressSpace = 0x0008;
				arpRespPktArpPacketHeader->HardwareAddressLength = 0x06;
				arpRespPktArpPacketHeader->ProtocolAddressLength = 0x04;
				arpRespPktArpPacketHeader->Operation = ArpOperationIsAt;
				RtlCopyMemory(&arpRespPktArpPacketHeader->SenderHardwareAddress, &arpRespPktEthernetFrameHeader->SourceMac, 6);
				RtlCopyMemory(&arpRespPktArpPacketHeader->TargetHardwareAddress, &arpRespPktEthernetFrameHeader->DestinationMac, 6);
				arpRespPktArpPacketHeader->SenderProtocolAddress = g_SourceIp;
				arpRespPktArpPacketHeader->TargetProtocolAddress = pktArpPacketHeader->SenderProtocolAddress;

				pcap_sendpacket(g_pAdapter, arpRespPktData, sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));

				delete [] arpRespPktData;
			}
			break;

		case ArpOperationIsAt:
			if(pktArpPacketHeader->SenderProtocolAddress == g_DefaultRouteIp)
			{
				for(std::map<u_int, ScanStruct *>::iterator i = g_ScanStructs.begin(); i != g_ScanStructs.end(); ++i)
				{
					ScanStruct *pScanStruct = i->second;
					
					if((pScanStruct->Mac[0] == 0x00) &&
					   (pScanStruct->Mac[1] == 0x00) &&
					   (pScanStruct->Mac[2] == 0x00) &&
					   (pScanStruct->Mac[3] == 0x00) &&
					   (pScanStruct->Mac[4] == 0x00) &&
					   (pScanStruct->Mac[5] == 0x00))
					{
						if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
						{
							throw std::exception("WaitForSingleObject() Failed.");
						}

						QueryPerformanceCounter(&g_lCounterLastActivity);
						RtlCopyMemory(pScanStruct->Mac, &pktArpPacketHeader->SenderHardwareAddress, 6);
						pScanStruct->Attempt = 0;

						if(pScanStruct == g_DefaultRouteScanStruct)
						{
							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "ARP DEFAULT ROUTE " << ((g_DefaultRouteIp & 0x000000FF)) << "."
												<< ((g_DefaultRouteIp & 0x0000FF00) >> 8) << "."
												<< ((g_DefaultRouteIp & 0x00FF0000) >> 16) << "."
												<< ((g_DefaultRouteIp & 0xFF000000) >> 24) << " IS-AT "
												<< std::hex
												<< std::setfill('0')
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[0]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[1]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[2]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[3]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[4]) << ":"
												<< std::setw(2) << static_cast<u_short>(pktArpPacketHeader->SenderHardwareAddress[5])
												<< std::dec << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							g_DefaultRouteScanStruct = NULL;
						}

						ReleaseMutex(pScanStruct->hMutex);
					}
				}
			}

			if(g_ScanStructs.find(ntohl(pktArpPacketHeader->SenderProtocolAddress)) != g_ScanStructs.end())
			{
				ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktArpPacketHeader->SenderProtocolAddress)];
				if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
				{
					throw std::exception("WaitForSingleObject() Failed.");
				}
				if((pScanStruct->Mac[0] == 0xFF) &&
				   (pScanStruct->Mac[1] == 0xFF) &&
				   (pScanStruct->Mac[2] == 0xFF) &&
				   (pScanStruct->Mac[3] == 0xFF) &&
				   (pScanStruct->Mac[4] == 0xFF) &&
				   (pScanStruct->Mac[5] == 0xFF))
				{
					RtlCopyMemory(pScanStruct->Mac, &pktArpPacketHeader->SenderHardwareAddress, 6);
					pScanStruct->Attempt = 0;
					QueryPerformanceCounter(&g_lCounterLastActivity);
					
					EnterCriticalSection(&g_ConsoleCriticalSection);
					std::cout << "ARP " << ((pScanStruct->Ip & 0x000000FF)) << "."
										<< ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
										<< ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
										<< ((pScanStruct->Ip & 0xFF000000) >> 24) << " IS-AT "
										<< std::hex
										<< std::setfill('0')
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[0]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[1]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[2]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[3]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[4]) << ":"
										<< std::setw(2) << static_cast<u_short>(pScanStruct->Mac[5])
										<< std::dec << std::endl;
					LeaveCriticalSection(&g_ConsoleCriticalSection);
				}
				ReleaseMutex(pScanStruct->hMutex);
			}
			break;

		default:
			break;
	}
}

// ========================================================================================================================

void OnListenIpIcmp(pcap_pkthdr *pPktHeader, const u_char *pPktData)
{
	const IpPacketHeader *pktIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
	const IcmpPacketHeader *pktIcmpPacketHeader = reinterpret_cast<const IcmpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
	const IpPacketHeader *pktIcmpContainedIpPacketHeader = NULL;
	if(pPktHeader->caplen >= (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader) + sizeof(IpPacketHeader)))
	{
		pktIcmpContainedIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(IcmpPacketHeader));
	}

	if((g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end()) ||
	   ((pktIcmpContainedIpPacketHeader != NULL) && (g_ScanStructs.find(ntohl(pktIcmpContainedIpPacketHeader->DestinationAddress)) != g_ScanStructs.end())))
	{
		switch(pktIcmpPacketHeader->Type)
		{
			case IcmpTypeEchoReply:
			case IcmpTypeEchoRequest:
				if((g_ScanType & ScanTypeVerbose) && (g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end()))
				{
					EnterCriticalSection(&g_ConsoleCriticalSection);
					std::cout << "ICMP ECHO "
							  << ((pktIcmpPacketHeader->Type == IcmpTypeEchoReply) ? "REPLY" : "REQUEST") << " FROM "
							  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24)
							  << std::endl;
					LeaveCriticalSection(&g_ConsoleCriticalSection);
				}
				break;

			case IcmpTypeUnreachable:
				if(pktIcmpContainedIpPacketHeader != NULL)
				{
					bool bReported = false;
					if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolTcp)
					{
						const TcpPacketHeader *pktIcmpContaintedTcpPacketHeader = reinterpret_cast<const TcpPacketHeader *>(pPktData +
																															sizeof(EthernetFrameHeader) +
																															sizeof(IpPacketHeader) +
																															sizeof(IcmpPacketHeader) +
																															sizeof(IpPacketHeader));
						ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIcmpContainedIpPacketHeader->DestinationAddress)];
						if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
						{
							throw std::exception("WaitForSingleObject() Failed.");
						}

						u_short icmpPort = ntohs(pktIcmpContaintedTcpPacketHeader->DestinationPort);
						if(pScanStruct->Responses.find(icmpPort) == pScanStruct->Responses.end())
						{
							pScanStruct->Responses[icmpPort] = 0;
						}
						if(!(pScanStruct->Responses[icmpPort] & ResponseTypeTcpIcmp))
						{
							pScanStruct->Responses[icmpPort] |= ResponseTypeTcpIcmp;
						}
						else
						{
							bReported = true;
						}

						ReleaseMutex(pScanStruct->hMutex);
					}
					else if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolUdp)
					{
						const UdpPacketHeader *pktIcmpContaintedUdpPacketHeader = reinterpret_cast<const UdpPacketHeader *>(pPktData +
																															sizeof(EthernetFrameHeader) +
																															sizeof(IpPacketHeader) +
																															sizeof(IcmpPacketHeader) +
																															sizeof(IpPacketHeader));
						ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIcmpContainedIpPacketHeader->DestinationAddress)];
						if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
						{
							throw std::exception("WaitForSingleObject() Failed.");
						}

						u_short icmpPort = ntohs(pktIcmpContaintedUdpPacketHeader->DestinationPort);
						if(pScanStruct->Responses.find(icmpPort) == pScanStruct->Responses.end())
						{
							pScanStruct->Responses[icmpPort] = 0;
						}
						if(!(pScanStruct->Responses[icmpPort] & ResponseTypeUdpIcmp))
						{
							pScanStruct->Responses[icmpPort] |= ResponseTypeUdpIcmp;
						}
						else
						{
							bReported = true;
						}

						ReleaseMutex(pScanStruct->hMutex);
					}

					if((g_ScanType & ScanTypeVerbose) && !bReported)
					{
						EnterCriticalSection(&g_ConsoleCriticalSection);
						std::cout << "ICMP UNREACHABLE FROM "
								  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
								  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
								  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
								  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << " FOR "
								  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x000000FF)) << "."
								  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x0000FF00) >> 8) << "."
								  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x00FF0000) >> 16) << "."
								  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0xFF000000) >> 24) << " ";

						if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolTcp)
						{
							const TcpPacketHeader *pktIcmpContaintedTcpPacketHeader = reinterpret_cast<const TcpPacketHeader *>(pPktData +
																																sizeof(EthernetFrameHeader) +
																																sizeof(IpPacketHeader) +
																																sizeof(IcmpPacketHeader) +
																																sizeof(IpPacketHeader));
							std::cout << "TCP " << ntohs(pktIcmpContaintedTcpPacketHeader->DestinationPort) << " ";
						}
						else if(pktIcmpContainedIpPacketHeader->Protocol == IpProtocolUdp)
						{
							const UdpPacketHeader *pktIcmpContaintedUdpPacketHeader = reinterpret_cast<const UdpPacketHeader *>(pPktData +
																																sizeof(EthernetFrameHeader) +
																																sizeof(IpPacketHeader) +
																																sizeof(IcmpPacketHeader) +
																																sizeof(IpPacketHeader));
							std::cout << "UDP " << ntohs(pktIcmpContaintedUdpPacketHeader->DestinationPort) << " ";
						}

						switch(pktIcmpPacketHeader->Code)
						{
							case IcmpUnreachableCodeNetworkUnreachable:
								std::cout << "NETWORK UNREACHABLE";
								break;
							case IcmpUnreachableCodeHostUnreachable:
								std::cout << "HOST UNREACHABLE";
								break;
							case IcmpUnreachableCodeProtocolUnreachable:
								std::cout << "PROTOCOL UNREACHABLE";
								break;
							case IcmpUnreachableCodePortUnreachable:
								std::cout << "PORT UNREACHABLE";
								break;
							case IcmpUnreachableCodeDatagramUnfragmentable:
								std::cout << "UNFRAGMENTABLE";
								break;
							case IcmpUnreachableCodeSourceRouteFailed:
								std::cout << "SOURCE ROUTE FAILED";
								break;
							case IcmpUnreachableCodeDestinationNetworkUnknown:
								std::cout << "DESTINATION NETWORK UNKNOWN";
								break;
							case IcmpUnreachableCodeDestinationHostUnknown:
								std::cout << "DESTINATION HOST UNKNOWN";
								break;
							case IcmpUnreachableCodeSourceHostIsolated:
								std::cout << "HOST ISOLATED";
								break;
							case IcmpUnreachableCodeDestinationNetworkProhibited:
								std::cout << "NETWORK PROHIBITED";
								break;
							case IcmpUnreachableCodeDestinationHostProhibited:
								std::cout << "HOST PROHIBITED";
								break;
							case IcmpUnreachableCodeDestinationNetworkUnreachableTos:
								std::cout << "NETWORK UNREACHABLE TOS";
								break;
							case IcmpUnreachableCodeDestinationHostUnreachableTos:
								std::cout << "HOST UNREACHABLE TOS";
								break;
							case IcmpUnreachableCodeAdministrativelyProhibited:
								std::cout << "ADMINISTRATIVELY PROHIBITED";
								break;
							case IcmpUnreachableCodeHostPrecedenceViolation:
								std::cout << "HOST PRECEDENCE VIOLATION";
								break;
							case IcmpUnreachableCodePrecedenceCutoff:
								std::cout << "PRECEDENCE CUTOFF";
								break;
						}
						std::cout << std::endl;
						LeaveCriticalSection(&g_ConsoleCriticalSection);
					}
				}
				break;

			case IcmpTypeTimeExceeded:
				if((g_ScanType & ScanTypeVerbose) && (pktIcmpContainedIpPacketHeader != NULL))
				{
					EnterCriticalSection(&g_ConsoleCriticalSection);
					std::cout << "ICMP TIME EXCEEDED FROM "
							  << ((pktIpPacketHeader->SourceAddress & 0x000000FF)) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0x0000FF00) >> 8) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0x00FF0000) >> 16) << "."
							  << ((pktIpPacketHeader->SourceAddress & 0xFF000000) >> 24) << " FOR "
							  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x000000FF)) << "."
							  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x0000FF00) >> 8) << "."
							  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0x00FF0000) >> 16) << "."
							  << ((pktIcmpContainedIpPacketHeader->DestinationAddress & 0xFF000000) >> 24) << " ";
					switch(pktIcmpPacketHeader->Code)
					{
						case IcmpTimeExceededCodeInTransit:
							std::cout << "IN TRANSIT";
							break;
						case IcmpTimeExceededCodeFragmentReassembly:
							std::cout << "IN FRAGMENT REASSEMBLY";
							break;
					}
					std::cout << std::endl;
					LeaveCriticalSection(&g_ConsoleCriticalSection);
				}
				break;

			default:
				break;
		}
	}
}

// ========================================================================================================================

void OnListenIpTcp(pcap_pkthdr *pPktHeader, const u_char *pPktData)
{
	const IpPacketHeader *pktIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
	if(g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end())
	{
		const TcpPacketHeader *pktTcpPacketHeader = reinterpret_cast<const TcpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
		if(std::find(g_ScanPorts.begin(), g_ScanPorts.end(), ntohs(pktTcpPacketHeader->SourcePort)) != g_ScanPorts.end())
		{
			ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIpPacketHeader->SourceAddress)];
			if((ntohl(pktTcpPacketHeader->AcknowledgementNumber) - 1) == pScanStruct->PacketIsnBase)
			{
				if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
				{
					throw std::exception("WaitForSingleObject() Failed.");
				}

				u_short tcpPort = 0;
				switch(pktTcpPacketHeader->Flags)
				{
					case (TcpFlagSyn | TcpFlagAck):
						if(g_ScanType & ScanTypeRst)
						{
							pScanStruct->TcpRstQueue.push(((pktTcpPacketHeader->DestinationPort << 16) & 0xFFFF0000) | pktTcpPacketHeader->SourcePort);
						}
						
						tcpPort = ntohs(pktTcpPacketHeader->SourcePort);
						if(pScanStruct->Responses.find(tcpPort) == pScanStruct->Responses.end())
						{
							pScanStruct->Responses[tcpPort] = 0;
						}
						if(!(pScanStruct->Responses[tcpPort] & ResponseTypeTcpSynAck))
						{
							EnterCriticalSection(&g_ConsoleCriticalSection);
							std::cout << "TCP SYN+ACK " << ((pScanStruct->Ip & 0x000000FF)) << "."
														<< ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
														<< ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
														<< ((pScanStruct->Ip & 0xFF000000) >> 24) << " "
														<< ntohs(pktTcpPacketHeader->SourcePort) << std::endl;
							LeaveCriticalSection(&g_ConsoleCriticalSection);
							pScanStruct->Responses[tcpPort] |= ResponseTypeTcpSynAck;
							QueryPerformanceCounter(&g_lCounterLastActivity);
						}
						break;

					case (TcpFlagRst | TcpFlagAck):
						tcpPort = ntohs(pktTcpPacketHeader->SourcePort);
						if(pScanStruct->Responses.find(tcpPort) == pScanStruct->Responses.end())
						{
							pScanStruct->Responses[tcpPort] = 0;
						}
						if(!(pScanStruct->Responses[tcpPort] & ResponseTypeTcpRstAck))
						{
							if(g_ScanType & ScanTypeVerbose)
							{
								EnterCriticalSection(&g_ConsoleCriticalSection);
								std::cout << "TCP RST+ACK "	<< ((pScanStruct->Ip & 0x000000FF)) << "."
															<< ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
															<< ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
															<< ((pScanStruct->Ip & 0xFF000000) >> 24) << " "
															<< ntohs(pktTcpPacketHeader->SourcePort) << std::endl;
								LeaveCriticalSection(&g_ConsoleCriticalSection);
							}
							pScanStruct->Responses[tcpPort] |= ResponseTypeTcpRstAck;
							QueryPerformanceCounter(&g_lCounterLastActivity);
						}
						break;
				}

				ReleaseMutex(pScanStruct->hMutex);
			}
		}
	}
}

// ========================================================================================================================

void OnListenIpUdp(pcap_pkthdr *pPktHeader, const u_char *pPktData)
{
	const IpPacketHeader *pktIpPacketHeader = reinterpret_cast<const IpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader));
	if((g_ScanStructs.find(ntohl(pktIpPacketHeader->SourceAddress)) != g_ScanStructs.end()) && (pktIpPacketHeader->SourceAddress != g_SourceIp))
	{
		const UdpPacketHeader *pktUdpPacketHeader = reinterpret_cast<const UdpPacketHeader *>(pPktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader));
		if(std::find(g_ScanPorts.begin(), g_ScanPorts.end(), ntohs(pktUdpPacketHeader->SourcePort)) != g_ScanPorts.end())
		{
			ScanStruct *pScanStruct = g_ScanStructs[ntohl(pktIpPacketHeader->SourceAddress)];

			if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
			{
				throw std::exception("WaitForSingleObject() Failed.");
			}

			u_short udpPort = ntohs(pktUdpPacketHeader->SourcePort);
			if(pScanStruct->Responses.find(udpPort) == pScanStruct->Responses.end())
			{
				pScanStruct->Responses[udpPort] = 0;
			}
			if(!(pScanStruct->Responses[udpPort] & ResponseTypeUdp))
			{
				EnterCriticalSection(&g_ConsoleCriticalSection);
				std::cout << "UDP PACKET " << ((pScanStruct->Ip & 0x000000FF)) << "."
										   << ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
										   << ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
										   << ((pScanStruct->Ip & 0xFF000000) >> 24) << " "
										   << ntohs(pktUdpPacketHeader->SourcePort) << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);
				pScanStruct->Responses[udpPort] |= ResponseTypeUdp;
				QueryPerformanceCounter(&g_lCounterLastActivity);
			}

			ReleaseMutex(pScanStruct->hMutex);
		}
	}
}

// ========================================================================================================================

DWORD CALLBACK PcapScanThreadProc(LPVOID lpParameter)
{	
	// ----------------
	// Packet Templates
	// ----------------

	EthernetFrameHeader pktEthernetFrameHeader;
	SecureZeroMemory(&pktEthernetFrameHeader, sizeof(EthernetFrameHeader));
	RtlCopyMemory(&pktEthernetFrameHeader.SourceMac, &g_pAdapterInfo->Address, 6);
	pktEthernetFrameHeader.Type = 0;

	ArpPacketHeader pktArpPacketHeader;
	SecureZeroMemory(&pktArpPacketHeader, sizeof(ArpPacketHeader));
	pktArpPacketHeader.HardwareAddressSpace = 0x0100;
	pktArpPacketHeader.ProtocolAddressSpace = 0x0008;
	pktArpPacketHeader.HardwareAddressLength = 0x06;
	pktArpPacketHeader.ProtocolAddressLength = 0x04;
	pktArpPacketHeader.Operation = 0;
	RtlCopyMemory(&pktArpPacketHeader.SenderHardwareAddress, &pktEthernetFrameHeader.SourceMac, 6);
	RtlZeroMemory(&pktArpPacketHeader.TargetHardwareAddress, 6);
	pktArpPacketHeader.SenderProtocolAddress = g_SourceIp;
	pktArpPacketHeader.TargetProtocolAddress = 0;

	IpPacketHeader pktIpPacketHeader;
	SecureZeroMemory(&pktIpPacketHeader, sizeof(IpPacketHeader));
	pktIpPacketHeader.VersionInternetHeaderLength = 0x40 | (sizeof(IpPacketHeader) / 4);
	pktIpPacketHeader.TypeOfService = 0;
	pktIpPacketHeader.TotalLength = 0;
	pktIpPacketHeader.Identification = 0;
	pktIpPacketHeader.FlagsFragmentOffset = 0;
	pktIpPacketHeader.TimeToLive = 0xFF;
	pktIpPacketHeader.Protocol = 0;
	pktIpPacketHeader.Crc = 0;
	pktIpPacketHeader.SourceAddress = g_SourceIp;
	pktIpPacketHeader.DestinationAddress = 0;

	ChecksumPseudoHeader pktChecksumPseudoHeader;
	SecureZeroMemory(&pktChecksumPseudoHeader, sizeof(ChecksumPseudoHeader));
	pktChecksumPseudoHeader.SourceAddress = g_SourceIp;
	pktChecksumPseudoHeader.DestinationAddress = 0;
	pktChecksumPseudoHeader.Zero = 0;
	pktChecksumPseudoHeader.Protocol = 0;
	pktChecksumPseudoHeader.Length = 0;

	TcpPacketHeader pktTcpPacketHeader;
	SecureZeroMemory(&pktTcpPacketHeader, sizeof(TcpPacketHeader));
	pktTcpPacketHeader.SourcePort = 0;
	pktTcpPacketHeader.DestinationPort = 0;
	pktTcpPacketHeader.SequenceNumber = 0;
	pktTcpPacketHeader.AcknowledgementNumber = 0;
	pktTcpPacketHeader.DataOffset = (sizeof(TcpPacketHeader) / 4) << 4;
	pktTcpPacketHeader.Flags = 0;
	pktTcpPacketHeader.Window = 0x0040;
	pktTcpPacketHeader.UrgentPointer = 0;
	pktTcpPacketHeader.Checksum = 0;

	UdpPacketHeader pktUdpPacketHeader;
	SecureZeroMemory(&pktUdpPacketHeader, sizeof(UdpPacketHeader));

	char pktUdpBuffer[40]; // Note: Ensure (sizeof(pktUdpBuffer)) % 2 == 0.
	SecureZeroMemory(&pktUdpBuffer, sizeof(pktUdpBuffer));
	RtlCopyMemory(&pktUdpBuffer, "Scant (C)2007-2008 http://int3.ws/\x00\x00", 36);

	// -----------------
	// Packet Generation
	// -----------------

	const u_int pktTcpMemSize = sizeof(pcap_pkthdr) +
								sizeof(EthernetFrameHeader) +
								sizeof(IpPacketHeader) +
								sizeof(TcpPacketHeader);
	const u_int pktUdpMemSize = sizeof(pcap_pkthdr) +
								sizeof(EthernetFrameHeader) +
								sizeof(IpPacketHeader) +
								sizeof(UdpPacketHeader) +
								sizeof(pktUdpBuffer);

	const u_int pktDataSize = max(pktTcpMemSize, pktUdpMemSize);

	pcap_pkthdr pktHeader;
	pktHeader.caplen = pktHeader.len = 0;
	pktHeader.ts.tv_sec = pktHeader.ts.tv_usec = 0;

	pcap_send_queue *pktSendQueue = NULL;
	u_char *pktData = new u_char[pktDataSize];
	
	ScanStruct *pScanStruct = NULL;
	std::map<u_int, ScanStruct *>::iterator pScanStructIter = g_ScanStructs.begin();

	LARGE_INTEGER lCounterFrequency;
	LARGE_INTEGER lCounterNow;

	QueryPerformanceFrequency(&lCounterFrequency);
	QueryPerformanceCounter(&lCounterNow);
	QueryPerformanceCounter(&g_lCounterLastActivity);

	try
	{
		while((WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0) &&
			  ((g_lCounterLastActivity.QuadPart + (lCounterFrequency.QuadPart * g_uWaitEndMs) / 1000) > lCounterNow.QuadPart))
		{
			u_int pktSendQueueMemSize = (g_uPacketQueueCount * pktDataSize * 2);

			pktSendQueue = pcap_sendqueue_alloc(pktSendQueueMemSize);
			if(pktSendQueue == NULL)
			{
				throw std::exception("pcap_sendqueue_alloc() Failed.");
			}

			std::map<u_int, ScanStruct *>::iterator pScanStructLoopIter = pScanStructIter;
			std::vector<u_short>::iterator pScanPortLoopIter = pScanStructIter->second->CurrentPort;

			u_int currentQueueCount = 0;
			while(currentQueueCount < g_uPacketQueueCount)
			{
				if(pScanStruct != NULL)
				{
					ReleaseMutex(pScanStruct->hMutex);
					pScanStruct = NULL;
				}
				pScanStruct = pScanStructIter->second;
				if(WaitForSingleObject(pScanStruct->hMutex, INFINITE) != WAIT_OBJECT_0)
				{
					throw std::exception("WaitForSingleObject() Failed.");
				}
				
				if(((pScanStruct->Mac[0] == 0xFF) &&
					(pScanStruct->Mac[1] == 0xFF) &&
					(pScanStruct->Mac[2] == 0xFF) &&
					(pScanStruct->Mac[3] == 0xFF) &&
					(pScanStruct->Mac[4] == 0xFF) &&
					(pScanStruct->Mac[5] == 0xFF)) ||
				   ((pScanStruct->Mac[0] == 0x00) &&
					(pScanStruct->Mac[1] == 0x00) &&
					(pScanStruct->Mac[2] == 0x00) &&
					(pScanStruct->Mac[3] == 0x00) &&
					(pScanStruct->Mac[4] == 0x00) &&
					(pScanStruct->Mac[5] == 0x00)))
				{
					if((pScanStruct->Attempt < g_uPacketAttemptCount) &&
					   (pScanStruct->lCounterLastPacketTime.QuadPart + ((lCounterFrequency.QuadPart * g_uPacketIntervalMs) / 1000) <= lCounterNow.QuadPart))
					{
						pktEthernetFrameHeader.Type = EtherTypeArp;
						RtlCopyMemory(&pktEthernetFrameHeader.DestinationMac, &pScanStruct->Mac, 6);

						pktArpPacketHeader.Operation = ArpOperationWhoHas;
						pktArpPacketHeader.TargetProtocolAddress = 0;
						RtlCopyMemory(&pktArpPacketHeader.TargetHardwareAddress, &pScanStruct->Mac, 6);
						
						if(pScanStruct->Mac[0] == 0x00)
						{
							if(g_DefaultRouteScanStruct == NULL)
							{
								g_DefaultRouteScanStruct = pScanStruct;
							}

							if(g_DefaultRouteScanStruct == pScanStruct)
							{
								if(g_DefaultRouteIp == 0x00000000)
								{
									throw std::exception("Default Route Ip Not Set Or 0.0.0.0");
								}

								pktArpPacketHeader.TargetProtocolAddress = g_DefaultRouteIp;
								RtlFillMemory(&pktEthernetFrameHeader.DestinationMac, 6, 0xFF);
								RtlFillMemory(&pktArpPacketHeader.TargetHardwareAddress, 6, 0xFF);
							}
						}
						else
						{
							pktArpPacketHeader.TargetProtocolAddress = pScanStruct->Ip;
						}

						if(pktArpPacketHeader.TargetProtocolAddress != 0)
						{
							SecureZeroMemory(pktData, pktDataSize);
							RtlCopyMemory(pktData, &pktEthernetFrameHeader, sizeof(EthernetFrameHeader));
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktArpPacketHeader, sizeof(ArpPacketHeader));
							
							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(ArpPacketHeader));
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							pScanStruct->Attempt++;
						}
					}
				}
				else if(((g_ScanType & ScanTypeTcp) || (g_ScanType & ScanTypeUdp)) &&
					    (pScanStruct->Attempt < g_uPacketAttemptCount) &&
						(pScanStruct->lCounterLastPacketTime.QuadPart + ((lCounterFrequency.QuadPart * g_uPacketIntervalMs) / 1000) <= lCounterNow.QuadPart))
				{
					if(g_ScanType & ScanTypeRst)
					{
						while((pScanStruct->TcpRstQueue.size() > 0) && (currentQueueCount < g_uPacketQueueCount))
						{
							u_int rstPort = pScanStruct->TcpRstQueue.front();
							pScanStruct->TcpRstQueue.pop();
							
							pktEthernetFrameHeader.Type = EtherTypeIp;
							RtlCopyMemory(&pktEthernetFrameHeader.DestinationMac, &pScanStruct->Mac, 6);
							RtlCopyMemory(pktData, &pktEthernetFrameHeader, sizeof(EthernetFrameHeader));

							pktIpPacketHeader.DestinationAddress = pScanStruct->Ip;
							pktChecksumPseudoHeader.DestinationAddress = pScanStruct->Ip;

							pktIpPacketHeader.Crc = 0;
							pktIpPacketHeader.Protocol = IpProtocolTcp;
							pktChecksumPseudoHeader.Protocol = IpProtocolTcp;
							pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(TcpPacketHeader));
							pktChecksumPseudoHeader.Length = htons(sizeof(TcpPacketHeader));

							u_int ipCrc = 0;
							InitialiseChecksum(ipCrc);
							UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
							pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

							pktTcpPacketHeader.Checksum = 0;
							pktTcpPacketHeader.DestinationPort = rstPort & 0x0000FFFF;
							pktTcpPacketHeader.SourcePort = (rstPort & 0xFFFF0000) >> 16;
							pktTcpPacketHeader.SequenceNumber = htonl(pScanStruct->PacketIsnBase);
							pktTcpPacketHeader.SequenceNumber = htonl(ntohl(pktTcpPacketHeader.SequenceNumber) + 1);
							pktTcpPacketHeader.Flags = TcpFlagRst;
							
							u_int tcpChecksum = 0;
							InitialiseChecksum(tcpChecksum);
							UpdateChecksum(tcpChecksum, reinterpret_cast<u_short *>(&pktChecksumPseudoHeader), sizeof(ChecksumPseudoHeader) / sizeof(u_short));
							UpdateChecksum(tcpChecksum, reinterpret_cast<u_short *>(&pktTcpPacketHeader), sizeof(TcpPacketHeader) / sizeof(u_short));
							pktTcpPacketHeader.Checksum = FinaliseChecksum(tcpChecksum);

							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktTcpPacketHeader, sizeof(TcpPacketHeader));
							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(TcpPacketHeader));
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
						}
					}

					if((g_uPacketQueueCount - currentQueueCount) < g_uPacketBlockCount)
					{
						break;
					}

					for(u_int p = 0; (p < g_uPacketBlockCount) && (pScanStruct->Attempt < g_uPacketAttemptCount); )
					{
						bool tcpResponse = false;
						bool udpResponse = false;

						while(pScanStruct->CurrentPort != g_ScanPorts.end())
						{
							if(pScanStruct->Responses.find(*pScanStruct->CurrentPort) != pScanStruct->Responses.end())
							{
								tcpResponse = ((pScanStruct->Responses[*pScanStruct->CurrentPort] & ResponseTypeTcpSynAck) ||
											   (pScanStruct->Responses[*pScanStruct->CurrentPort] & ResponseTypeTcpRstAck) ||
											   (pScanStruct->Responses[*pScanStruct->CurrentPort] & ResponseTypeTcpIcmp));

								udpResponse = ((pScanStruct->Responses[*pScanStruct->CurrentPort] & ResponseTypeUdp) ||
											   (pScanStruct->Responses[*pScanStruct->CurrentPort] & ResponseTypeUdpIcmp));
							}
																		
							if(((g_ScanType & ScanTypeTcp) && !tcpResponse) || ((g_ScanType & ScanTypeUdp) && !udpResponse))
							{
								break;
							}
							pScanStruct->CurrentPort++;
						}
						
						if(pScanStruct->CurrentPort == g_ScanPorts.end())
						{
							if(++pScanStruct->Attempt < g_uPacketAttemptCount)
							{
								pScanStruct->CurrentPort = g_ScanPorts.begin();
							}
							else
							{
								pScanStruct->Attempt = g_uPacketAttemptCount;
								pScanStruct->CurrentPort = g_ScanPorts.end();
							}
							break;
						}

						pktEthernetFrameHeader.Type = EtherTypeIp;
						RtlCopyMemory(&pktEthernetFrameHeader.DestinationMac, &pScanStruct->Mac, 6);
						SecureZeroMemory(pktData, pktDataSize);
						RtlCopyMemory(pktData, &pktEthernetFrameHeader, sizeof(EthernetFrameHeader));

						pktIpPacketHeader.DestinationAddress = pScanStruct->Ip;
						pktChecksumPseudoHeader.DestinationAddress = pScanStruct->Ip;
						
						if((g_ScanType & ScanTypeTcp) && !(tcpResponse))
						{
							pktIpPacketHeader.Crc = 0;
							pktIpPacketHeader.Protocol = IpProtocolTcp;
							pktChecksumPseudoHeader.Protocol = IpProtocolTcp;
							pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(TcpPacketHeader));
							pktChecksumPseudoHeader.Length = htons(sizeof(TcpPacketHeader));

							u_int ipCrc = 0;
							InitialiseChecksum(ipCrc);
							UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
							pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

							pktTcpPacketHeader.Checksum = 0;
							pktTcpPacketHeader.DestinationPort = htons(*pScanStruct->CurrentPort);
							pktTcpPacketHeader.Flags = TcpFlagSyn;
							pktTcpPacketHeader.SequenceNumber = htonl(pScanStruct->PacketIsnBase);							

							if(g_ScanType & ScanTypeSport)
							{
								pktTcpPacketHeader.SourcePort = g_SourcePort;
							}
							else
							{
								if(!CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&pktTcpPacketHeader.SourcePort)))
								{
									throw std::exception("CryptGenRandom() Failed.");
								}
							}

							u_int tcpChecksum = 0;
							InitialiseChecksum(tcpChecksum);
							UpdateChecksum(tcpChecksum, reinterpret_cast<u_short *>(&pktChecksumPseudoHeader), sizeof(ChecksumPseudoHeader) / sizeof(u_short));
							UpdateChecksum(tcpChecksum, reinterpret_cast<u_short *>(&pktTcpPacketHeader), sizeof(TcpPacketHeader) / sizeof(u_short));
							pktTcpPacketHeader.Checksum = FinaliseChecksum(tcpChecksum);

							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktTcpPacketHeader, sizeof(TcpPacketHeader));
							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(TcpPacketHeader));
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							p++;
						}
						if((g_ScanType & ScanTypeUdp) && !(udpResponse))
						{
							pktIpPacketHeader.Crc = 0;
							pktIpPacketHeader.Protocol = IpProtocolUdp;
							pktChecksumPseudoHeader.Protocol = IpProtocolUdp;
							pktIpPacketHeader.TotalLength = htons(sizeof(IpPacketHeader) + sizeof(UdpPacketHeader) + sizeof(pktUdpBuffer));
							pktChecksumPseudoHeader.Length = htons(sizeof(UdpPacketHeader) + sizeof(pktUdpBuffer));
							
							u_int ipCrc = 0;
							InitialiseChecksum(ipCrc);
							UpdateChecksum(ipCrc, reinterpret_cast<u_short *>(&pktIpPacketHeader), (sizeof(IpPacketHeader)) / sizeof(u_short));
							pktIpPacketHeader.Crc = FinaliseChecksum(ipCrc);
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader), &pktIpPacketHeader, sizeof(IpPacketHeader));

							pktUdpPacketHeader.Checksum = 0;
							pktUdpPacketHeader.DestinationPort = htons(*pScanStruct->CurrentPort);
							pktUdpPacketHeader.Length = htons(sizeof(UdpPacketHeader) + sizeof(pktUdpBuffer));
							
							if(g_ScanType & ScanTypeSport)
							{
								pktUdpPacketHeader.SourcePort = g_SourcePort;
							}
							else
							{
								if(!CryptGenRandom(g_hCryptProv, 2, reinterpret_cast<BYTE *>(&pktUdpPacketHeader.SourcePort)))
								{
									throw std::exception("CryptGenRandom() Failed.");
								}
							}
							
							u_int udpChecksum = 0;
							InitialiseChecksum(udpChecksum);
							UpdateChecksum(udpChecksum, reinterpret_cast<u_short *>(&pktChecksumPseudoHeader), sizeof(ChecksumPseudoHeader) / sizeof(u_short));
							UpdateChecksum(udpChecksum, reinterpret_cast<u_short *>(&pktUdpPacketHeader), sizeof(UdpPacketHeader) / sizeof(u_short));
							UpdateChecksum(udpChecksum, reinterpret_cast<u_short *>(&pktUdpBuffer), sizeof(pktUdpBuffer) / sizeof(u_short));
							pktUdpPacketHeader.Checksum = FinaliseChecksum(udpChecksum);

							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader), &pktUdpPacketHeader, sizeof(UdpPacketHeader));
							RtlCopyMemory(pktData + sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(UdpPacketHeader), &pktUdpBuffer, sizeof(pktUdpBuffer));
							
							pktHeader.caplen = pktHeader.len = (sizeof(EthernetFrameHeader) + sizeof(IpPacketHeader) + sizeof(UdpPacketHeader) + sizeof(pktUdpBuffer));
							if(pcap_sendqueue_queue(pktSendQueue, &pktHeader, pktData) != 0)
							{
								throw std::exception("pcap_sendqueue_queue() Failed.");
							}

							QueryPerformanceCounter(&pScanStruct->lCounterLastPacketTime);
							currentQueueCount++;
							p++;
						}
						pScanStruct->CurrentPort++;
					}
				}

				if(g_lCounterLastActivity.QuadPart < pScanStruct->lCounterLastPacketTime.QuadPart)
				{
					g_lCounterLastActivity = pScanStruct->lCounterLastPacketTime;
				}
				if(pScanStruct != NULL)
				{
					ReleaseMutex(pScanStruct->hMutex);
					pScanStruct = NULL;
				}

				do
				{
					if(++pScanStructIter == g_ScanStructs.end())
					{
						pScanStructIter = g_ScanStructs.begin();
					}
					if(pScanStructIter == pScanStructLoopIter)
					{
						break;
					}
				}
				while(pScanStructIter->second->Attempt >= g_uPacketAttemptCount);
				
				if(pScanStructIter == pScanStructLoopIter)
				{
					break;
				}
			}

			if(pktSendQueue != NULL)
			{
				pcap_sendqueue_transmit(g_pAdapter, pktSendQueue, 0);
				pcap_sendqueue_destroy(pktSendQueue);
				pktSendQueue = NULL;
			}
			if(g_uPacketIntervalMs != 0)
			{
				Sleep(g_uPacketIntervalMs);
			}
			QueryPerformanceCounter(&lCounterNow);
		}

		SetEvent(g_hExitEvent);
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Error: " << e.what() << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);

		SetEvent(g_hExitEvent);
	}

	if(pScanStruct != NULL)
	{
		ReleaseMutex(pScanStruct->hMutex);
		pScanStruct = NULL;
	}
	if(pktData != NULL)
	{
		delete [] pktData;
		pktData = NULL;
	}
	if(pktSendQueue != NULL)
	{
		pcap_sendqueue_destroy(pktSendQueue);
		pktSendQueue = NULL;
	}

	return 0;
}

// ========================================================================================================================

DWORD CALLBACK ResolveThreadProc(LPVOID lpParameter)
{
	if(g_bResolveHosts)
	{
		while(WaitForSingleObject(g_hExitEvent, 100) != WAIT_OBJECT_0)
		{
			std::queue<u_int> resolveQueue;

			if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
			{
				for(std::map<u_int, std::string>::iterator i = g_HostNames.begin(); i != g_HostNames.end(); ++i)
				{
					if(i->second == "")
					{
						i->second = "?";
						resolveQueue.push(i->first);
					}
				}
				ReleaseMutex(g_hHostNamesMutex);
			}
			else
			{
				EnterCriticalSection(&g_ConsoleCriticalSection);
				std::cout << "Warning: WaitForSingleObject(g_hHostNamesMutex, 1000) Failed." << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);
			}

			while(!resolveQueue.empty())
			{
				u_int ip = resolveQueue.front();
				resolveQueue.pop();

				sockaddr_in sockAddrIn;
				SecureZeroMemory(&sockAddrIn, sizeof(sockAddrIn));
				sockAddrIn.sin_addr.S_un.S_addr = ip;
				sockAddrIn.sin_family = AF_INET;
				sockAddrIn.sin_port = 0;

				char nodeName[NI_MAXHOST + 1];
				SecureZeroMemory(&nodeName, sizeof(nodeName));

				std::string hostName;

				if(getnameinfo(reinterpret_cast<const SOCKADDR *>(&sockAddrIn),
							   sizeof(sockAddrIn),
							   reinterpret_cast<PCHAR>(&nodeName),
							   NI_MAXHOST,
							   NULL,
							   0,
							   0) != 0)
				{
					std::stringstream ipBuilder;
					ipBuilder << (ip & 0x000000FF) << "."
							  << ((ip & 0x0000FF00) >> 8) << "."
							  << ((ip & 0x00FF0000) >> 16) << "."
							  << ((ip & 0xFF000000) >> 24);
					hostName = ipBuilder.str();
				}
				else
				{
					hostName = nodeName;
				}

				if(WaitForSingleObject(g_hHostNamesMutex, 1000) == WAIT_OBJECT_0)
				{
					g_HostNames[ip] = hostName;
					ReleaseMutex(g_hHostNamesMutex);
				}
			}
		}
	}

	return 0;
}

// ========================================================================================================================

void GenerateScanStructs(std::string &targetString, std::string &portString)
{
	// ----------
	// portString
	// ----------

	u_int portBlockMarker = 0;
	while(!portString.empty() && (portBlockMarker != std::string::npos))
	{
		u_int nextPortBlockMarker = portString.find(',', portBlockMarker + 1);
		std::string portBlock = portString.substr(portBlockMarker + ((portBlockMarker == 0) ? 0 : 1), nextPortBlockMarker - portBlockMarker - ((portBlockMarker == 0) ? 0 : 1));
		portBlockMarker = nextPortBlockMarker;

		portBlock = portBlock.substr(portBlock.find_first_not_of(" \t\r\n"));
		portBlock = portBlock.substr(0, portBlock.find_last_not_of(" \t\r\n") + 1);

		u_short startPortRange = 0;
		u_short endPortRange = 0;

		u_int portRangeMarker = portBlock.find('-');
		if(portRangeMarker != std::string::npos)
		{
			startPortRange = static_cast<u_short>(strtol(portBlock.substr(0, portRangeMarker).c_str(), NULL, 10));
			endPortRange = static_cast<u_short>(strtol(portBlock.substr(portRangeMarker + 1).c_str(), NULL, 10));
		}
		else
		{
			startPortRange = endPortRange = static_cast<u_short>(strtol(portBlock.c_str(), NULL, 10));
		}

		if(startPortRange > endPortRange)
		{
			throw std::exception("Invalid /Port Range Specified.");
		}

		for(u_short p = startPortRange; (p >= startPortRange) && (p <= endPortRange); ++p)
		{
			g_ScanPorts.push_back(p);
		}
	}

	if(((g_ScanType & ScanTypeTcp) || (g_ScanType & ScanTypeUdp)) && (g_ScanPorts.empty()))
	{
		throw std::exception("Invalid /Port Range Specified.");
	}
	
	// ------------
	// targetString
	// ------------

	u_int targetBlockMarker = 0;
	while(targetBlockMarker != std::string::npos)
	{
		u_int nextTargetBlockMarker = targetString.find(';', targetBlockMarker + 1);
		std::string targetBlock = targetString.substr(targetBlockMarker + ((targetBlockMarker == 0) ? 0 : 1), nextTargetBlockMarker - targetBlockMarker - ((targetBlockMarker == 0) ? 0 : 1));
		targetBlockMarker = nextTargetBlockMarker;

		for(u_int i = 0; i < targetBlock.size(); ++i)
		{
			if(((targetBlock[i] >= '0') && (targetBlock[i] <= '9')) ||
			   (targetBlock[i] == '.') || (targetBlock[i] == '/') ||
			   (targetBlock[i] == ',') || (targetBlock[i] == '-'))
			{
				continue;
			}

			u_int subnetMaskBitsMarker = targetBlock.find('/');
			std::string hostName = targetBlock.substr(0, subnetMaskBitsMarker);
			std::string subnetString = "";
			if(subnetMaskBitsMarker != std::string::npos)
			{
				subnetString = targetBlock.substr(subnetMaskBitsMarker);
			}

			addrinfo *addrInfoList = NULL;
			if(getaddrinfo(hostName.c_str(), NULL, NULL, &addrInfoList) != 0)
			{
				std::string lookupError = "DNS Lookup for \"";
				lookupError += targetBlock;
				lookupError += "\" Failed.";
				throw std::exception(lookupError.c_str());
			}

			UINT ip = reinterpret_cast<sockaddr_in *>(addrInfoList->ai_addr)->sin_addr.S_un.S_addr;

			std::stringstream ipBuilder;
			ipBuilder << (ip & 0x000000FF) << "."
					  << ((ip & 0x0000FF00) >> 8) << "."
					  << ((ip & 0x00FF0000) >> 16) << "."
					  << ((ip & 0xFF000000) >> 24) << subnetString;
			targetBlock = ipBuilder.str();

			break;
		}

		u_int subnetMaskBitsMarker = targetBlock.find('/');
		u_short subnetMaskBits = 32;
		if(subnetMaskBitsMarker != std::string::npos)
		{
			subnetMaskBits = static_cast<u_short>(strtol(targetBlock.substr(subnetMaskBitsMarker + 1).c_str(), NULL, 10));
			if(subnetMaskBits > 32)
			{
				subnetMaskBits = 32;
			}
			targetBlock = targetBlock.substr(0, subnetMaskBitsMarker);
		}
		
		u_int subnetMask = 0xFFFFFFFF;
		for(u_int i = 0; i < (static_cast<u_int>(32) - subnetMaskBits); ++i)
		{
			subnetMask ^= ((0x01) << i);
		}

		std::string targetOctets[4];
		u_int targetOctetMarker = 0;
		for(u_int i = 0; i < 4; ++i)
		{
			if(targetOctetMarker == std::string::npos)
			{
				throw std::exception("Invalid /Target Specified.");
			}
			u_int nextTargetOctetMarker = targetBlock.find('.', targetOctetMarker + 1);
			targetOctets[i] = targetBlock.substr(targetOctetMarker + ((targetOctetMarker == 0) ? 0 : 1), nextTargetOctetMarker - targetOctetMarker - ((targetOctetMarker == 0) ? 0 : 1));
			targetOctetMarker = nextTargetOctetMarker;

			if(targetOctets[i].empty())
			{
				throw std::exception("Invalid /Target Specified.");
			}
		}

		u_int targetFirstOctetItemMarker = 0;
		while(targetFirstOctetItemMarker != std::string::npos)
		{
			u_int nextTargetFirstOctetItemMarker = targetOctets[0].find(',', targetFirstOctetItemMarker + 1);
			std::string targetFirstOctetItem = targetOctets[0].substr(targetFirstOctetItemMarker + ((targetFirstOctetItemMarker == 0) ? 0 : 1), nextTargetFirstOctetItemMarker - targetFirstOctetItemMarker - ((targetFirstOctetItemMarker == 0) ? 0 : 1));
			targetFirstOctetItemMarker = nextTargetFirstOctetItemMarker;

			u_int targetSecondOctetItemMarker = 0;
			while(targetSecondOctetItemMarker != std::string::npos)
			{
				u_int nextTargetSecondOctetItemMarker = targetOctets[1].find(',', targetSecondOctetItemMarker + 1);
				std::string targetSecondOctetItem = targetOctets[1].substr(targetSecondOctetItemMarker + ((targetSecondOctetItemMarker == 0) ? 0 : 1), nextTargetSecondOctetItemMarker - targetSecondOctetItemMarker - ((targetSecondOctetItemMarker == 0) ? 0 : 1));
				targetSecondOctetItemMarker = nextTargetSecondOctetItemMarker;

				u_int targetThirdOctetItemMarker = 0;
				while(targetThirdOctetItemMarker != std::string::npos)
				{
					u_int nextTargetThirdOctetItemMarker = targetOctets[2].find(',', targetThirdOctetItemMarker + 1);
					std::string targetThirdOctetItem = targetOctets[2].substr(targetThirdOctetItemMarker + ((targetThirdOctetItemMarker == 0) ? 0 : 1), nextTargetThirdOctetItemMarker - targetThirdOctetItemMarker - ((targetThirdOctetItemMarker == 0) ? 0 : 1));
					targetThirdOctetItemMarker = nextTargetThirdOctetItemMarker;

					u_int targetFourthOctetItemMarker = 0;
					while(targetFourthOctetItemMarker != std::string::npos)
					{
						u_int nextTargetFourthOctetItemMarker = targetOctets[3].find(',', targetFourthOctetItemMarker + 1);
						std::string targetFourthOctetItem = targetOctets[3].substr(targetFourthOctetItemMarker + ((targetFourthOctetItemMarker == 0) ? 0 : 1), nextTargetFourthOctetItemMarker - targetFourthOctetItemMarker - ((targetFourthOctetItemMarker == 0) ? 0 : 1));
						targetFourthOctetItemMarker = nextTargetFourthOctetItemMarker;

						std::string ipOctets[4] = {targetFirstOctetItem, targetSecondOctetItem, targetThirdOctetItem, targetFourthOctetItem};
						
						u_int lowIp = 0x00000000;
						u_int highIp = 0x00000000;

						for(u_int i = 0; i < 4; ++i)
						{
							size_t ipOctetRangeMarker = ipOctets[i].find("-");
							if(ipOctetRangeMarker == std::string::npos)
							{
								lowIp |= (strtol(ipOctets[i].c_str(), NULL, 10) << (8 * (3 - i)));
								highIp |= (strtol(ipOctets[i].c_str(), NULL, 10) << (8 * (3 - i)));
							}
							else
							{
								lowIp |= (strtol(ipOctets[i].substr(0, ipOctetRangeMarker).c_str(), NULL, 10) << (8 * (3 - i)));
								highIp |= (strtol(ipOctets[i].substr(ipOctetRangeMarker + 1).c_str(), NULL, 10) << (8 * (3 - i)));
							}
						}

						for(u_int a = ((lowIp & 0xFF000000) >> 24); a <= ((highIp & 0xFF000000) >> 24); ++a)
						{
							for(u_int b = ((lowIp & 0x00FF0000) >> 16); b <= ((highIp & 0x00FF0000) >> 16); ++b)
							{
								for(u_int c = ((lowIp & 0x0000FF00) >> 8); c <= ((highIp & 0x0000FF00) >> 8); ++c)
								{
									for(u_int d = (lowIp & 0x000000FF); d <= (highIp & 0x000000FF); ++d)
									{
										u_int ip = (((a << 24) & 0xFF000000) | ((b << 16) & 0x00FF0000) | ((c << 8) & 0x0000FF00) | (d & 0x000000FF));
										ip &= subnetMask;

										for(u_int i = 0; i < static_cast<u_int>(pow(2.0, 32.0 - subnetMaskBits)); ++i)
										{
											if(((ip | i) == ntohl(g_SourceIp)) || (!g_ScanStructs.empty() && (g_ScanStructs.find(ip | i) != g_ScanStructs.end())))
											{
												continue;
											}

											ScanStruct *pScanStruct = new ScanStruct;
											pScanStruct->Ip = htonl(ip | i);
											g_ScanStructs[(ip | i)] = pScanStruct;

											g_HostNames[pScanStruct->Ip] = "";

											pScanStruct->Attempt = 0;
											pScanStruct->CurrentPort = g_ScanPorts.begin();
											pScanStruct->bLocalSubnet = ((ntohl(pScanStruct->Ip) ^ ntohl(g_SourceIp)) & ntohl(g_SourceNetMask)) == 0;
											RtlFillMemory(&pScanStruct->Mac, 6, (pScanStruct->bLocalSubnet || (g_ScanType & ScanTypeArp)) ? 0xFF : 0x00);
											SecureZeroMemory(&pScanStruct->lCounterLastPacketTime, sizeof(LARGE_INTEGER));

											if((pScanStruct->hMutex = CreateMutex(NULL, FALSE, NULL)) == NULL)
											{
												throw std::exception("CreateMutex() Failed.");
											}
											if(!CryptGenRandom(g_hCryptProv, 4, reinterpret_cast<BYTE *>(&pScanStruct->PacketIsnBase)))
											{
												throw std::exception("CryptGenRandom() Failed.");
											}
											
											if(g_ScanType & ScanTypeDummy)
											{
												EnterCriticalSection(&g_ConsoleCriticalSection);
												std::cout << "SCAN "
														  << ((g_ScanType & ScanTypeArp) ? "ARP " : "")
														  << ((g_ScanType & ScanTypeTcp) ? "TCP " : "")
														  << ((g_ScanType & ScanTypeUdp) ? "UDP " : "")
														  << ((pScanStruct->Ip & 0x000000FF)) << "."
														  << ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
														  << ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
														  << ((pScanStruct->Ip & 0xFF000000) >> 24)
														  << " " << (!(g_ScanType & ScanTypeArp) ? (pScanStruct->bLocalSubnet ? "LOCAL" : "REMOTE") : "")
														  << std::endl;
												LeaveCriticalSection(&g_ConsoleCriticalSection);
											}											
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	if(g_ScanType & ScanTypeDummy)
	{
		throw std::exception("");
	}
}

// ========================================================================================================================

void PrintResults(std::ostream &stream, std::ifstream &inOui)
{
	for(std::map<u_int, ScanStruct *>::iterator i = g_ScanStructs.begin(); i != g_ScanStructs.end(); ++i)
	{
		ScanStruct *pScanStruct = i->second;
		if(((pScanStruct->Mac[0] == 0xFF) &&
			(pScanStruct->Mac[1] == 0xFF) &&
			(pScanStruct->Mac[2] == 0xFF) &&
			(pScanStruct->Mac[3] == 0xFF) &&
			(pScanStruct->Mac[4] == 0xFF) &&
			(pScanStruct->Mac[5] == 0xFF)) ||
		   ((pScanStruct->Mac[0] == 0x00) &&
			(pScanStruct->Mac[1] == 0x00) &&
			(pScanStruct->Mac[2] == 0x00) &&
			(pScanStruct->Mac[3] == 0x00) &&
			(pScanStruct->Mac[4] == 0x00) &&
			(pScanStruct->Mac[5] == 0x00)))
		{
			continue;
		}

		if(g_ScanType & ScanTypeArp)
		{
			stream << "ARP "
				   << ((pScanStruct->Ip & 0x000000FF)) << "."
				   << ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
				   << ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
				   << ((pScanStruct->Ip & 0xFF000000) >> 24) << " IS-AT "
				   << std::hex
				   << std::setfill('0')
				   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[0]) << ":"
				   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[1]) << ":"
				   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[2]) << ":"
				   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[3]) << ":"
				   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[4]) << ":"
				   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[5]) << " "
				   << std::dec
				   << "[";
			PrintResultsMacVendor(stream, inOui, reinterpret_cast<const u_char *>(&pScanStruct->Mac));
			stream << "]" << std::endl;
		}
		else
		{
			if(!pScanStruct->Responses.empty())
			{
				if(!g_bResolveHosts)
				{
					stream << ((pScanStruct->Ip & 0x000000FF)) << "."
						   << ((pScanStruct->Ip & 0x0000FF00) >> 8) << "."
						   << ((pScanStruct->Ip & 0x00FF0000) >> 16) << "."
						   << ((pScanStruct->Ip & 0xFF000000) >> 24);
				}
				else
				{
					PrintResultsHostName(stream, pScanStruct->Ip);
				}

				if(pScanStruct->bLocalSubnet)
				{
					stream << " [" << std::hex
						   << std::setfill('0')
						   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[0]) << ":"
						   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[1]) << ":"
						   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[2]) << ":"
						   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[3]) << ":"
						   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[4]) << ":"
						   << std::setw(2) << static_cast<u_short>(pScanStruct->Mac[5]) << " / "
						   << std::dec;
					PrintResultsMacVendor(stream, inOui, reinterpret_cast<const u_char *>(&pScanStruct->Mac));
					stream << "]";
				}
				stream << std::endl;

				if(g_ScanType & ScanTypeTcp)
				{
					stream << "  TCP SYN+ACK:";
					PrintResultsResponsesRange(stream, pScanStruct->Responses, ResponseTypeTcpSynAck);
					stream << std::endl	
						   << "  TCP RST+ACK:";
					PrintResultsResponsesRange(stream, pScanStruct->Responses, ResponseTypeTcpRstAck);
					stream << std::endl
						   << "  TCP ICMP UNREACHABLE:";
					PrintResultsResponsesRange(stream, pScanStruct->Responses, ResponseTypeTcpIcmp);
					stream << std::endl;
				}
				if(g_ScanType & ScanTypeUdp)
				{
					stream << "  UDP PACKET:";
					PrintResultsResponsesRange(stream, pScanStruct->Responses, ResponseTypeUdp);
					stream << std::endl
						   << "  UDP ICMP UNREACHABLE:";
					PrintResultsResponsesRange(stream, pScanStruct->Responses, ResponseTypeUdpIcmp);
					stream << std::endl;
				}
				stream << std::endl;
			}
		}
	}
}

// ========================================================================================================================

void PrintResultsHostName(std::ostream &stream, const u_int ip)
{
	if(g_HostNames.find(ip) != g_HostNames.end())
	{
		stream << g_HostNames[ip];
	}
}

// ========================================================================================================================

void PrintResultsMacVendor(std::ostream &stream, std::ifstream &inOui, const u_char *mac)
{
	std::string vendor = "Unknown";
	if(!inOui.is_open())
	{
		vendor = "Unknown - Missing Oui.dat";
	}
	else
	{
		inOui.seekg(0, std::ios::beg);
		while(!inOui.eof())
		{
			char lineBuffer[1024];
			inOui.getline(&lineBuffer[0], 1024);

			u_short bytesRead = inOui.gcount();
			lineBuffer[2] = '\0';
			lineBuffer[5] = '\0';
			lineBuffer[8] = '\0';
			if((strtol(reinterpret_cast<char *>(&lineBuffer[0]), NULL, 16) == mac[0]) &&
			   (strtol(reinterpret_cast<char *>(&lineBuffer[3]), NULL, 16) == mac[1]) &&
			   (strtol(reinterpret_cast<char *>(&lineBuffer[6]), NULL, 16) == mac[2]))
			{
				vendor = &lineBuffer[9];
				break;
			}			
		}
	}
	stream << "\"" << vendor << "\"";
}

// ========================================================================================================================

void PrintResultsResponsesRange(std::ostream &stream, std::map<u_short, u_short> &responses, u_short responseType)
{
	bool bResult = false;
	for(std::map<u_short, u_short>::iterator j = responses.begin(); j != responses.end(); ++j)
	{
		if(j->second & responseType)
		{
			stream << (!bResult ? " " : ", ") << (j->first);
			bResult = true;
			
			std::map<u_short, u_short>::iterator k = j;
			std::map<u_short, u_short>::iterator l = j;
			++l;

			while((l != responses.end()) && (((l->first - 1) == k->first) &&
											 (k->second & responseType) &&
											 (l->second & responseType)))
			{
				std::map<u_short, u_short>::iterator m = l;
				++m;
				if((m == responses.end()) ||
				   ((m != responses.end()) && ((m->first > (l->first + 1)) ||
											   !(m->second & responseType))))
				{
					stream << "-" << l->first;
					j = l;
					break;
				}
				++k;
				++l;
			}
		}
	}
}

// ========================================================================================================================

void PrintUsage()
{
	std::cout << "Usage: Scant.exe /Device <id> /Target <a.b.c-d.e,f,g[/x]> /Resolve" << std::endl
			  << "                 /Arp /Tcp /Rst /Udp /Port <x-y,z> /Sport <p>" << std::endl
			  << "                 /Interval <i> /Queue <q> /Block <b> /Retry <r>" << std::endl
			  << "                 /Ip <a.b.c.d> /Netmask <a.b.c.d> /Route <a.b.c.d>" << std::endl
			  << "                 /Output <f> /Dummy /Verbose" << std::endl << std::endl
			  << "Available Devices:" << std::endl << std::endl;

	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *pDeviceList = NULL;

	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &pDeviceList, pcapErrorBuffer) == -1)
	{
		std::cout << "Error: pcap_findalldevs_ex() Failed." << std::endl;
	}
	else
	{
		pcap_if_t *pDeviceEnum = pDeviceList;
		int deviceEnumCount = 0;
		while(pDeviceEnum != NULL)
		{
			std::cout << "  " << ++deviceEnumCount << ". " << pDeviceEnum->description << std::endl;
			pDeviceEnum = pDeviceEnum->next;
		}

		if(pDeviceList != NULL)
		{
			pcap_freealldevs(pDeviceList);
			pDeviceList = NULL;
		}
	}
	std::cout << std::endl;
}

// ========================================================================================================================