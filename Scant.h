// ========================================================================================================================
// Scant
//
// Copyright ©2007 Liam Kirton <liam@int3.ws>
// ========================================================================================================================
// Scant.h
//
// Created: 27/03/2007
// ========================================================================================================================

#pragma once

// ========================================================================================================================

#pragma pack(push, 1)

// ========================================================================================================================

typedef struct _EthernetFrameHeader
{
	u_char DestinationMac[6];
	u_char SourceMac[6];
	u_short Type;
} EthernetFrameHeader;

// ------------------------------------------------------------------------------------------------------------------------

typedef struct _ArpPacketHeader
{
	u_short HardwareAddressSpace;
	u_short ProtocolAddressSpace;
	u_char HardwareAddressLength;
	u_char ProtocolAddressLength;
	u_short Operation;
	u_char SenderHardwareAddress[6];
	u_int SenderProtocolAddress;
	u_char TargetHardwareAddress[6];
	u_int TargetProtocolAddress;
} ArpPacketHeader;

// ------------------------------------------------------------------------------------------------------------------------

typedef struct _IpPacketHeader
{
	u_char VersionInternetHeaderLength;
	u_char TypeOfService;
	u_short TotalLength;
	u_short Identification;
	u_short FlagsFragmentOffset;
	u_char TimeToLive;
	u_char Protocol;
	u_short Crc;
	u_int SourceAddress;
	u_int DestinationAddress;
} IpPacketHeader;

// ------------------------------------------------------------------------------------------------------------------------

typedef struct _IcmpPacketHeader
{
	u_char Type;
	u_char Code;
	u_short Checksum;
	u_short Id;
	u_short Sequence;
} IcmpPacketHeader;

// ------------------------------------------------------------------------------------------------------------------------

typedef struct _ChecksumPseudoHeader
{
	u_int SourceAddress;
	u_int DestinationAddress;
	u_char Zero;
	u_char Protocol;
	u_short Length;
} ChecksumPseudoHeader;

// ------------------------------------------------------------------------------------------------------------------------

typedef struct _TcpPacketHeader
{
	u_short SourcePort;
	u_short DestinationPort;
	u_int SequenceNumber;
	u_int AcknowledgementNumber;
	u_char DataOffset;
	u_char Flags;
	u_short Window;
	u_short Checksum;
	u_short UrgentPointer;
} TcpPacketHeader;

// ------------------------------------------------------------------------------------------------------------------------

typedef struct _UdpPacketHeader
{
	u_short SourcePort;
	u_short DestinationPort;
	u_short Length;
	u_short Checksum;
} UdpPacketHeader;

// ========================================================================================================================

#pragma pack(pop)

// ========================================================================================================================

typedef enum _EtherType
{
	EtherTypeIp = 0x0008,
	EtherTypeArp = 0x0608
} EtherType;

// ------------------------------------------------------------------------------------------------------------------------

typedef enum _ArpOperation
{
	ArpOperationWhoHas = 0x0100,
	ArpOperationIsAt = 0x0200
} ArpOperation;

// ------------------------------------------------------------------------------------------------------------------------

typedef enum _IpProtocol
{
	IpProtocolIcmp = 1,
	IpProtocolTcp = 6,
	IpProtocolUdp = 17
} IpProtocol;

// ------------------------------------------------------------------------------------------------------------------------

typedef enum _IcmpType
{
	IcmpTypeEchoReply = 0,
	IcmpTypeUnreachable = 3,
	IcmpTypeEchoRequest = 8,
	IcmpTypeTimeExceeded = 11
} IcmpType;

// ------------------------------------------------------------------------------------------------------------------------

typedef enum _IcmpUnreachableCode
{
	IcmpUnreachableCodeNetworkUnreachable = 0,
	IcmpUnreachableCodeHostUnreachable = 1,
	IcmpUnreachableCodeProtocolUnreachable = 2,
	IcmpUnreachableCodePortUnreachable = 3,
	IcmpUnreachableCodeDatagramUnfragmentable = 4,
	IcmpUnreachableCodeSourceRouteFailed = 5,
	IcmpUnreachableCodeDestinationNetworkUnknown = 6,
	IcmpUnreachableCodeDestinationHostUnknown = 7,
	IcmpUnreachableCodeSourceHostIsolated = 8,
	IcmpUnreachableCodeDestinationNetworkProhibited = 9,
	IcmpUnreachableCodeDestinationHostProhibited = 10,
	IcmpUnreachableCodeDestinationNetworkUnreachableTos = 11,
	IcmpUnreachableCodeDestinationHostUnreachableTos = 12,
	IcmpUnreachableCodeAdministrativelyProhibited = 13,
	IcmpUnreachableCodeHostPrecedenceViolation = 14,
	IcmpUnreachableCodePrecedenceCutoff = 15,
} IcmpUnreachableCode;

// ------------------------------------------------------------------------------------------------------------------------

typedef enum _IcmpTimeExceededCode
{
	IcmpTimeExceededCodeInTransit = 0,
	IcmpTimeExceededCodeFragmentReassembly = 1
} IcmpTimeExceededCode;

// ------------------------------------------------------------------------------------------------------------------------

typedef enum _TcpFlag
{
	TcpFlagFin = 0x01,
	TcpFlagSyn = 0x02,
	TcpFlagRst = 0x04,
	TcpFlagPsh = 0x08,
	TcpFlagAck = 0x10,
	TcpFlagUrg = 0x20,
	TcpFlagEce = 0x40,
	TcpFlagCwr = 0x80
} TcpFlag;

// ========================================================================================================================

void InitialiseChecksum(u_int &checksum)
{
	checksum = 0;
}

// ------------------------------------------------------------------------------------------------------------------------

void UpdateChecksum(u_int &checksum, u_short *dataWords, u_int dataWordCount)
{
	while(dataWordCount-- > 0)
	{
		checksum += *(dataWords++);
	}
}

// ------------------------------------------------------------------------------------------------------------------------

u_short FinaliseChecksum(u_int &checksum)
{
	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);
	return static_cast<u_short>(~checksum);
}

// ========================================================================================================================

typedef struct _ScanStruct
{
	HANDLE hMutex;

	u_char Mac[6];
	u_int Ip;
	
	bool bLocalSubnet;
	u_int Attempt;
	u_int PacketIsnBase;
	
	std::vector<u_short>::iterator CurrentPort;

	std::map<u_short, u_short> Responses;
	std::queue<u_int> TcpRstQueue;

	LARGE_INTEGER lCounterLastPacketTime;
} ScanStruct;

// ------------------------------------------------------------------------------------------------------------------------

typedef enum _ScanType
{
	ScanTypeDummy = 0x001,
	ScanTypeVerbose = 0x002,

	ScanTypeRst = 0x010,
	ScanTypeSport = 0x020,

	ScanTypeArp = 0x100,
	ScanTypeTcp = 0x200,
	ScanTypeUdp = 0x400
} ScanType;

// ------------------------------------------------------------------------------------------------------------------------

typedef enum _ResponseType
{
	ResponseTypeArp = 0x01,
	ResponseTypeTcpSynAck = 0x02,
	ResponseTypeTcpRstAck = 0x04,
	ResponseTypeTcpIcmp = 0x08,
	ResponseTypeUdp = 0x10,
	ResponseTypeUdpIcmp = 0x20,
} ResponseType;

// ========================================================================================================================