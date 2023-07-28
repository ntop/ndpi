/*
 * ndpi_protocol_ids.h
 *
 * Copyright (C) 2011-22 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef __NDPI_PROTOCOLS_IDS_H__
#define __NDPI_PROTOCOLS_IDS_H__

#define NDPI_PROTOCOL_SIZE                  2

typedef enum {
  NDPI_PROTOCOL_UNKNOWN               = 0,
  NDPI_PROTOCOL_FTP_CONTROL           = 1,
  NDPI_PROTOCOL_MAIL_POP              = 2,
  NDPI_PROTOCOL_MAIL_SMTP             = 3,
  NDPI_PROTOCOL_MAIL_IMAP             = 4,
  NDPI_PROTOCOL_DNS                   = 5,
  NDPI_PROTOCOL_IPP                   = 6,
  NDPI_PROTOCOL_HTTP                  = 7,
  NDPI_PROTOCOL_MDNS                  = 8,
  NDPI_PROTOCOL_NTP                   = 9,
  NDPI_PROTOCOL_NETBIOS               = 10,
  NDPI_PROTOCOL_NFS                   = 11,
  NDPI_PROTOCOL_SSDP                  = 12,
  NDPI_PROTOCOL_BGP                   = 13,
  NDPI_PROTOCOL_SNMP                  = 14,
  NDPI_PROTOCOL_XDMCP                 = 15,
  NDPI_PROTOCOL_SMBV1                 = 16, /* SMB version 1 */
  NDPI_PROTOCOL_SYSLOG                = 17,
  NDPI_PROTOCOL_DHCP                  = 18,
  NDPI_PROTOCOL_POSTGRES              = 19,
  NDPI_PROTOCOL_MYSQL                 = 20,
  NDPI_PROTOCOL_MS_OUTLOOK            = 21, /* Hotmail / Microsoft Outlook / Exchange */
  NDPI_PROTOCOL_VK                    = 22,
  NDPI_PROTOCOL_MAIL_POPS             = 23,
  NDPI_PROTOCOL_TAILSCALE             = 24,
  NDPI_PROTOCOL_YANDEX                = 25,
  NDPI_PROTOCOL_NTOP                  = 26,
  NDPI_PROTOCOL_COAP                  = 27,
  NDPI_PROTOCOL_VMWARE                = 28,
  NDPI_PROTOCOL_MAIL_SMTPS            = 29,
  NDPI_PROTOCOL_DTLS                  = 30,
  NDPI_PROTOCOL_UBNTAC2               = 31, /* Ubiquity UBNT AirControl = 2 */
  NDPI_PROTOCOL_KONTIKI               = 32,
  NDPI_PROTOCOL_YANDEX_MAIL           = 33,
  NDPI_PROTOCOL_YANDEX_MUSIC          = 34,
  NDPI_PROTOCOL_GNUTELLA              = 35,
  NDPI_PROTOCOL_EDONKEY               = 36,
  NDPI_PROTOCOL_BITTORRENT            = 37,
  NDPI_PROTOCOL_SKYPE_TEAMS_CALL      = 38, /* Skype call and videocalls */
  NDPI_PROTOCOL_SIGNAL                = 39,
  NDPI_PROTOCOL_MEMCACHED             = 40, /* Memcached */
  NDPI_PROTOCOL_SMBV23                = 41, /* SMB version 2/3 */
  NDPI_PROTOCOL_MINING                = 42, /* Ethereum, ZCash, Monero */
  NDPI_PROTOCOL_NEST_LOG_SINK         = 43, /* Nest Log Sink (Nest Protect) */
  NDPI_PROTOCOL_MODBUS                = 44, /* Modbus */
  NDPI_PROTOCOL_WHATSAPP_CALL         = 45, /* WhatsApp video ad audio calls go here */
  NDPI_PROTOCOL_DATASAVER             = 46, /* Protocols used to save data on Internet communications */
  NDPI_PROTOCOL_XBOX                  = 47,
  NDPI_PROTOCOL_QQ                    = 48,
  NDPI_PROTOCOL_TIKTOK                = 49,
  NDPI_PROTOCOL_RTSP                  = 50,
  NDPI_PROTOCOL_MAIL_IMAPS            = 51,
  NDPI_PROTOCOL_ICECAST               = 52,
  NDPI_PROTOCOL_CPHA                  = 53,
  NDPI_PROTOCOL_PPSTREAM              = 54,
  NDPI_PROTOCOL_ZATTOO                = 55,
  NDPI_PROTOCOL_YANDEX_MARKET         = 56,
  NDPI_PROTOCOL_YANDEX_DISK           = 57,
  NDPI_PROTOCOL_DISCORD               = 58,
  NDPI_PROTOCOL_TVUPLAYER             = 59,
  NDPI_PROTOCOL_MONGODB               = 60,
  NDPI_PROTOCOL_PLURALSIGHT           = 61,
  NDPI_PROTOCOL_YANDEX_CLOUD          = 62,
  NDPI_PROTOCOL_OCSP                  = 63,
  NDPI_PROTOCOL_VXLAN                 = 64,
  NDPI_PROTOCOL_IRC                   = 65,
  NDPI_PROTOCOL_MERAKI_CLOUD          = 66,
  NDPI_PROTOCOL_JABBER                = 67,
  NDPI_PROTOCOL_NATS                  = 68,
  NDPI_PROTOCOL_AMONG_US              = 69,
  NDPI_PROTOCOL_YAHOO                 = 70,
  NDPI_PROTOCOL_DISNEYPLUS            = 71,
  NDPI_PROTOCOL_GOOGLE_PLUS           = 72,
  NDPI_PROTOCOL_IP_VRRP               = 73,
  NDPI_PROTOCOL_STEAM                 = 74,
  NDPI_PROTOCOL_HALFLIFE2             = 75,
  NDPI_PROTOCOL_WORLDOFWARCRAFT       = 76,
  NDPI_PROTOCOL_TELNET                = 77,
  NDPI_PROTOCOL_STUN                  = 78,
  NDPI_PROTOCOL_IPSEC                 = 79,
  NDPI_PROTOCOL_IP_GRE                = 80,
  NDPI_PROTOCOL_IP_ICMP               = 81,
  NDPI_PROTOCOL_IP_IGMP               = 82,
  NDPI_PROTOCOL_IP_EGP                = 83,
  NDPI_PROTOCOL_IP_SCTP               = 84,
  NDPI_PROTOCOL_IP_OSPF               = 85,
  NDPI_PROTOCOL_IP_IP_IN_IP           = 86,
  NDPI_PROTOCOL_RTP                   = 87,
  NDPI_PROTOCOL_RDP                   = 88,
  NDPI_PROTOCOL_VNC                   = 89,
  NDPI_PROTOCOL_TUMBLR                = 90,
  NDPI_PROTOCOL_TLS                   = 91,
  NDPI_PROTOCOL_SSH                   = 92,
  NDPI_PROTOCOL_USENET                = 93,
  NDPI_PROTOCOL_MGCP                  = 94,
  NDPI_PROTOCOL_IAX                   = 95,
  NDPI_PROTOCOL_TFTP                  = 96,
  NDPI_PROTOCOL_AFP                   = 97,
  NDPI_PROTOCOL_YANDEX_METRIKA        = 98,
  NDPI_PROTOCOL_YANDEX_DIRECT         = 99,
  NDPI_PROTOCOL_SIP                   = 100,
  NDPI_PROTOCOL_TRUPHONE              = 101,
  NDPI_PROTOCOL_IP_ICMPV6             = 102,
  NDPI_PROTOCOL_DHCPV6                = 103,
  NDPI_PROTOCOL_ARMAGETRON            = 104,
  NDPI_PROTOCOL_CROSSFIRE             = 105,
  NDPI_PROTOCOL_DOFUS                 = 106,
  NDPI_PROTOCOL_ADS_ANALYTICS_TRACK   = 107, /* Generic id for advertisement/analytics/tracking stuff */
  NDPI_PROTOCOL_ADULT_CONTENT         = 108,
  NDPI_PROTOCOL_GUILDWARS             = 109,
  NDPI_PROTOCOL_AMAZON_ALEXA          = 110,
  NDPI_PROTOCOL_KERBEROS              = 111,
  NDPI_PROTOCOL_LDAP                  = 112,
  NDPI_PROTOCOL_MAPLESTORY            = 113,
  NDPI_PROTOCOL_MSSQL_TDS             = 114,
  NDPI_PROTOCOL_PPTP                  = 115,
  NDPI_PROTOCOL_WARCRAFT3             = 116,
  NDPI_PROTOCOL_WORLD_OF_KUNG_FU      = 117,
  NDPI_PROTOCOL_SLACK                 = 118,
  NDPI_PROTOCOL_FACEBOOK              = 119,
  NDPI_PROTOCOL_TWITTER               = 120,
  NDPI_PROTOCOL_DROPBOX               = 121,
  NDPI_PROTOCOL_GMAIL                 = 122,
  NDPI_PROTOCOL_GOOGLE_MAPS           = 123,
  NDPI_PROTOCOL_YOUTUBE               = 124,
  NDPI_PROTOCOL_SKYPE_TEAMS           = 125,
  NDPI_PROTOCOL_GOOGLE                = 126,
  NDPI_PROTOCOL_RPC                   = 127,
  NDPI_PROTOCOL_NETFLOW               = 128,
  NDPI_PROTOCOL_SFLOW                 = 129,
  NDPI_PROTOCOL_HTTP_CONNECT          = 130,
  NDPI_PROTOCOL_HTTP_PROXY            = 131,
  NDPI_PROTOCOL_CITRIX                = 132, /* It also includes the old NDPI_PROTOCOL_CITRIX_ONLINE */
  NDPI_PROTOCOL_NETFLIX               = 133,
  NDPI_PROTOCOL_LASTFM                = 134,
  NDPI_PROTOCOL_WAZE                  = 135,
  NDPI_PROTOCOL_YOUTUBE_UPLOAD        = 136, /* Upload files to youtube */
  NDPI_PROTOCOL_HULU                  = 137,
  NDPI_PROTOCOL_CHECKMK               = 138,
  NDPI_PROTOCOL_AJP                   = 139,
  NDPI_PROTOCOL_APPLE                 = 140,
  NDPI_PROTOCOL_WEBEX                 = 141,
  NDPI_PROTOCOL_WHATSAPP              = 142,
  NDPI_PROTOCOL_APPLE_ICLOUD          = 143,
  NDPI_PROTOCOL_VIBER                 = 144,
  NDPI_PROTOCOL_APPLE_ITUNES          = 145,
  NDPI_PROTOCOL_RADIUS                = 146,
  NDPI_PROTOCOL_WINDOWS_UPDATE        = 147,
  NDPI_PROTOCOL_TEAMVIEWER            = 148,
  NDPI_PROTOCOL_TUENTI                = 149,
  NDPI_PROTOCOL_LOTUS_NOTES           = 150,
  NDPI_PROTOCOL_SAP                   = 151,
  NDPI_PROTOCOL_GTP                   = 152,
  NDPI_PROTOCOL_WSD                   = 153,
  NDPI_PROTOCOL_LLMNR                 = 154,
  NDPI_PROTOCOL_TOCA_BOCA             = 155,
  NDPI_PROTOCOL_SPOTIFY               = 156,
  NDPI_PROTOCOL_MESSENGER             = 157,
  NDPI_PROTOCOL_H323                  = 158,
  NDPI_PROTOCOL_OPENVPN               = 159,
  NDPI_PROTOCOL_NOE                   = 160,
  NDPI_PROTOCOL_CISCOVPN              = 161,
  NDPI_PROTOCOL_TEAMSPEAK             = 162,
  NDPI_PROTOCOL_TOR                   = 163,
  NDPI_PROTOCOL_SKINNY                = 164,
  NDPI_PROTOCOL_RTCP                  = 165,
  NDPI_PROTOCOL_RSYNC                 = 166,
  NDPI_PROTOCOL_ORACLE                = 167,
  NDPI_PROTOCOL_CORBA                 = 168,
  NDPI_PROTOCOL_UBUNTUONE             = 169,
  NDPI_PROTOCOL_WHOIS_DAS             = 170,
  NDPI_PROTOCOL_SD_RTN                = 171, /* Agora SD-RTN: https://www.agora.io/en */
  NDPI_PROTOCOL_SOCKS                 = 172,
  NDPI_PROTOCOL_NINTENDO              = 173,
  NDPI_PROTOCOL_RTMP                  = 174,
  NDPI_PROTOCOL_FTP_DATA              = 175,
  NDPI_PROTOCOL_WIKIPEDIA             = 176,
  NDPI_PROTOCOL_ZMQ                   = 177,
  NDPI_PROTOCOL_AMAZON                = 178,
  NDPI_PROTOCOL_EBAY                  = 179,
  NDPI_PROTOCOL_CNN                   = 180,
  NDPI_PROTOCOL_MEGACO                = 181,
  NDPI_PROTOCOL_REDIS                 = 182,
  NDPI_PROTOCOL_PINTEREST             = 183,
  NDPI_PROTOCOL_VHUA                  = 184,
  NDPI_PROTOCOL_TELEGRAM              = 185,
  NDPI_PROTOCOL_VEVO                  = 186,
  NDPI_PROTOCOL_PANDORA               = 187,
  NDPI_PROTOCOL_QUIC                  = 188,
  NDPI_PROTOCOL_ZOOM                  = 189, /* Zoom video conference. */
  NDPI_PROTOCOL_EAQ                   = 190,
  NDPI_PROTOCOL_OOKLA                 = 191,
  NDPI_PROTOCOL_AMQP                  = 192,
  NDPI_PROTOCOL_KAKAOTALK             = 193, /* KakaoTalk Chat (no voice call) */
  NDPI_PROTOCOL_KAKAOTALK_VOICE       = 194, /* KakaoTalk Voice */
  NDPI_PROTOCOL_TWITCH                = 195,
  NDPI_PROTOCOL_DOH_DOT               = 196, /* DoH (DNS over HTTPS), DoT (DNS over TLS), DoQ (DNS over QUIC). TODO: rename in NDPI_PROTOCOL_DOH_DOT_DOQ? */
  NDPI_PROTOCOL_WECHAT                = 197,
  NDPI_PROTOCOL_MPEGTS                = 198,
  NDPI_PROTOCOL_SNAPCHAT              = 199,
  NDPI_PROTOCOL_SINA                  = 200,
  NDPI_PROTOCOL_HANGOUT_DUO           = 201, /* Google Hangout ad Duo (merged as they are very similar) */
  NDPI_PROTOCOL_IFLIX                 = 202,
  NDPI_PROTOCOL_GITHUB                = 203,
  NDPI_PROTOCOL_BJNP                  = 204,
  NDPI_PROTOCOL_REDDIT                = 205,
  NDPI_PROTOCOL_WIREGUARD             = 206,
  NDPI_PROTOCOL_SMPP                  = 207,
  NDPI_PROTOCOL_DNSCRYPT              = 208,
  NDPI_PROTOCOL_TINC                  = 209,
  NDPI_PROTOCOL_DEEZER                = 210,
  NDPI_PROTOCOL_INSTAGRAM             = 211,
  NDPI_PROTOCOL_MICROSOFT             = 212,
  NDPI_PROTOCOL_STARCRAFT             = 213,
  NDPI_PROTOCOL_TEREDO                = 214,
  NDPI_PROTOCOL_HOTSPOT_SHIELD        = 215,
  NDPI_PROTOCOL_IMO                   = 216,
  NDPI_PROTOCOL_GOOGLE_DRIVE          = 217,
  NDPI_PROTOCOL_OCS                   = 218,
  NDPI_PROTOCOL_MICROSOFT_365         = 219,
  NDPI_PROTOCOL_CLOUDFLARE            = 220,
  NDPI_PROTOCOL_MS_ONE_DRIVE          = 221,
  NDPI_PROTOCOL_MQTT                  = 222,
  NDPI_PROTOCOL_RX                    = 223,
  NDPI_PROTOCOL_APPLESTORE            = 224,
  NDPI_PROTOCOL_OPENDNS               = 225,
  NDPI_PROTOCOL_GIT                   = 226,
  NDPI_PROTOCOL_DRDA                  = 227,
  NDPI_PROTOCOL_PLAYSTORE             = 228,
  NDPI_PROTOCOL_SOMEIP                = 229,
  NDPI_PROTOCOL_FIX                   = 230,
  NDPI_PROTOCOL_PLAYSTATION           = 231,
  NDPI_PROTOCOL_PASTEBIN              = 232,
  NDPI_PROTOCOL_LINKEDIN              = 233,
  NDPI_PROTOCOL_SOUNDCLOUD            = 234,
  NDPI_PROTOCOL_CSGO                  = 235, /* Counter-Strike Global Offensive, Dota = 2 */
  NDPI_PROTOCOL_LISP                  = 236,
  NDPI_PROTOCOL_DIAMETER              = 237,
  NDPI_PROTOCOL_APPLE_PUSH            = 238,
  NDPI_PROTOCOL_GOOGLE_SERVICES       = 239,
  NDPI_PROTOCOL_AMAZON_VIDEO          = 240,
  NDPI_PROTOCOL_GOOGLE_DOCS           = 241,
  NDPI_PROTOCOL_WHATSAPP_FILES        = 242, /* Videos, pictures, voice messages... */
  NDPI_PROTOCOL_TARGUS_GETDATA        = 243,
  NDPI_PROTOCOL_DNP3                  = 244,
  NDPI_PROTOCOL_IEC60870              = 245, /* https://en.wikipedia.org/wiki/IEC_60870-5 */
  NDPI_PROTOCOL_BLOOMBERG             = 246,
  NDPI_PROTOCOL_CAPWAP                = 247,
  NDPI_PROTOCOL_ZABBIX                = 248,
  NDPI_PROTOCOL_S7COMM                = 249,
  NDPI_PROTOCOL_MSTEAMS               = 250,
  NDPI_PROTOCOL_WEBSOCKET             = 251,
  NDPI_PROTOCOL_ANYDESK               = 252,
  NDPI_PROTOCOL_SOAP                  = 253,
  NDPI_PROTOCOL_APPLE_SIRI            = 254,
  NDPI_PROTOCOL_SNAPCHAT_CALL         = 255,
  NDPI_PROTOCOL_HPVIRTGRP             = 256,
  NDPI_PROTOCOL_GENSHIN_IMPACT        = 257,
  NDPI_PROTOCOL_ACTIVISION            = 258,
  NDPI_PROTOCOL_FORTICLIENT           = 259,
  NDPI_PROTOCOL_Z3950                 = 260,
  NDPI_PROTOCOL_LIKEE                 = 261,
  NDPI_PROTOCOL_GITLAB                = 262,
  NDPI_PROTOCOL_AVAST_SECUREDNS       = 263,
  NDPI_PROTOCOL_CASSANDRA             = 264,
  NDPI_PROTOCOL_AMAZON_AWS            = 265,
  NDPI_PROTOCOL_SALESFORCE            = 266,
  NDPI_PROTOCOL_VIMEO                 = 267,
  NDPI_PROTOCOL_FACEBOOK_VOIP         = 268,
  NDPI_PROTOCOL_SIGNAL_VOIP           = 269,
  NDPI_PROTOCOL_FUZE                  = 270,
  NDPI_PROTOCOL_GTP_U                 = 271,
  NDPI_PROTOCOL_GTP_C                 = 272,
  NDPI_PROTOCOL_GTP_PRIME             = 273,
  NDPI_PROTOCOL_ALIBABA               = 274,
  NDPI_PROTOCOL_CRASHLYSTICS          = 275,
  NDPI_PROTOCOL_MICROSOFT_AZURE       = 276,
  NDPI_PROTOCOL_ICLOUD_PRIVATE_RELAY  = 277,
  NDPI_PROTOCOL_ETHERNET_IP           = 278,
  NDPI_PROTOCOL_BADOO                 = 279,
  NDPI_PROTOCOL_ACCUWEATHER           = 280,
  NDPI_PROTOCOL_GOOGLE_CLASSROOM      = 281,
  NDPI_PROTOCOL_HSRP                  = 282,
  NDPI_PROTOCOL_CYBERSECURITY         = 283, /* Cybersecurity companies */
  NDPI_PROTOCOL_GOOGLE_CLOUD          = 284,
  NDPI_PROTOCOL_TENCENT               = 285,
  NDPI_PROTOCOL_RAKNET                = 286,
  NDPI_PROTOCOL_XIAOMI                = 287,
  NDPI_PROTOCOL_EDGECAST              = 288,
  NDPI_PROTOCOL_CACHEFLY              = 289,
  NDPI_PROTOCOL_SOFTETHER             = 290,
  NDPI_PROTOCOL_MPEGDASH              = 291,
  NDPI_PROTOCOL_DAZN                  = 292,
  NDPI_PROTOCOL_GOTO                  = 293, /* GoTo products, mainly GoToMeeting */
  NDPI_PROTOCOL_RSH                   = 294,
  NDPI_PROTOCOL_1KXUN                 = 295,
  NDPI_PROTOCOL_IP_PGM                = 296,
  NDPI_PROTOCOL_IP_PIM                = 297,
  NDPI_PROTOCOL_COLLECTD              = 298,
  NDPI_PROTOCOL_TUNNELBEAR            = 299,
  NDPI_PROTOCOL_CLOUDFLARE_WARP       = 300,
  NDPI_PROTOCOL_I3D                   = 301, /* i3d.net: Game Hosting service */
  NDPI_PROTOCOL_RIOTGAMES             = 302,
  NDPI_PROTOCOL_PSIPHON               = 303,
  NDPI_PROTOCOL_ULTRASURF             = 304,
  NDPI_PROTOCOL_THREEMA               = 305,
  NDPI_PROTOCOL_ALICLOUD              = 306,
  NDPI_PROTOCOL_AVAST                 = 307,
  NDPI_PROTOCOL_TIVOCONNECT           = 308,
  NDPI_PROTOCOL_KISMET                = 309,
  NDPI_PROTOCOL_FASTCGI               = 310,
  NDPI_PROTOCOL_FTPS                  = 311,
  NDPI_PROTOCOL_NATPMP                = 312,
  NDPI_PROTOCOL_SYNCTHING             = 313,
  NDPI_PROTOCOL_CRYNET                = 314,
  NDPI_PROTOCOL_LINE                  = 315,
  NDPI_PROTOCOL_LINE_CALL             = 316,
  NDPI_PROTOCOL_APPLETVPLUS           = 317,
  NDPI_PROTOCOL_DIRECTV               = 318,
  NDPI_PROTOCOL_HBO                   = 319,
  NDPI_PROTOCOL_VUDU                  = 320,
  NDPI_PROTOCOL_SHOWTIME              = 321,
  NDPI_PROTOCOL_DAILYMOTION           = 322,
  NDPI_PROTOCOL_LIVESTREAM            = 323,
  NDPI_PROTOCOL_TENCENTVIDEO          = 324,
  NDPI_PROTOCOL_IHEARTRADIO           = 325,
  NDPI_PROTOCOL_TIDAL                 = 326,
  NDPI_PROTOCOL_TUNEIN                = 327,
  NDPI_PROTOCOL_SIRIUSXMRADIO         = 328,
  NDPI_PROTOCOL_MUNIN                 = 329,
  NDPI_PROTOCOL_ELASTICSEARCH         = 330,
  NDPI_PROTOCOL_TUYA_LP               = 331, /* TUYA LAN Protocol; IoT OS: https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n */
  NDPI_PROTOCOL_TPLINK_SHP            = 332, /* TP-LINK Smart Home Protocol */
  NDPI_PROTOCOL_SOURCE_ENGINE         = 333,
  NDPI_PROTOCOL_BACNET                = 334,
  NDPI_PROTOCOL_OICQ                  = 335,
  NDPI_PROTOCOL_HOTS                  = 336, /* Heroes of the Storm */
  NDPI_PROTOCOL_FACEBOOK_REEL_STORY   = 337,
  NDPI_PROTOCOL_SRTP                  = 338,
  NDPI_PROTOCOL_GAMBLING              = 339,
  NDPI_PROTOCOL_EPICGAMES             = 340,
  NDPI_PROTOCOL_GEFORCENOW            = 341,
  NDPI_PROTOCOL_NVIDIA                = 342,
  NDPI_PROTOCOL_BITCOIN               = 343, 
  NDPI_PROTOCOL_PROTONVPN             = 344,
  NDPI_PROTOCOL_APACHE_THRIFT         = 345,
  NDPI_PROTOCOL_ROBLOX                = 346,
  NDPI_PROTOCOL_MULLVAD               = 347,

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_protocol_ids.h"
#endif

  /*
    IMPORTANT
    before allocating a new identifier please fill up
    one of those named NDPI_PROTOCOL_FREE_XXX and not used
    (placeholders to avoid protocol renumbering)
  */

  /* IMPORTANT:NDPI_LAST_IMPLEMENTED_PROTOCOL MUST BE THE LAST ELEMENT */
  NDPI_LAST_IMPLEMENTED_PROTOCOL
} ndpi_protocol_id_t;

#define NDPI_PROTOCOL_NO_MASTER_PROTO    NDPI_PROTOCOL_UNKNOWN
#define NDPI_MAX_SUPPORTED_PROTOCOLS     NDPI_LAST_IMPLEMENTED_PROTOCOL
#define NDPI_MAX_NUM_CUSTOM_PROTOCOLS    (NDPI_NUM_BITS-NDPI_LAST_IMPLEMENTED_PROTOCOL)

#endif /* __NDPI_PROTOCOL_IDS_H__ */
