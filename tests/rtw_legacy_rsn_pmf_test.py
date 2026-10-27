#!/usr/bin/env python3
"""Check production RSN bytes for legacy mixed mode and required PMF/SAE."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'rtw80211/openbsd/net80211/ieee80211_output.c').read_text()
a=s.index('ieee80211_add_rsn_body(u_int8_t *frm,');fn=s[a:s.index('\n}\n',a)+3]
fixture=r'''
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdint>
using u_int8_t=uint8_t;using u_int16_t=uint16_t;
#define MICROSOFT_OUI ((const uint8_t*)"\x00\x50\xf2")
#define IEEE80211_OUI ((const uint8_t*)"\x00\x0f\xac")
#define LE_WRITE_2(p,v) do{(p)[0]=(v)&255;(p)[1]=((v)>>8)&255;}while(0)
#define IEEE80211_C_MFP 1
#define IEEE80211_F_MFPR 1
#define IEEE80211_F_PBAR 2
#define IEEE80211_NODE_PMKID 1
#define IEEE80211_PMKID_LEN 16
#define IEEE80211_RSNCAP_PTKSA_RCNT_MASK 0x000c
#define IEEE80211_RSNCAP_GTKSA_RCNT_MASK 0x0030
#define IEEE80211_RSNCAP_MFPC 0x0080
#define IEEE80211_RSNCAP_MFPR 0x0040
#define IEEE80211_RSNCAP_PBAC 0x1000
enum {IEEE80211_CIPHER_USEGROUP=1,IEEE80211_CIPHER_WEP40=2,IEEE80211_CIPHER_TKIP=4,IEEE80211_CIPHER_CCMP=8,IEEE80211_CIPHER_WEP104=16,IEEE80211_CIPHER_BIP=32};
enum {IEEE80211_AKM_8021X=1,IEEE80211_AKM_PSK=2,IEEE80211_AKM_SHA256_8021X=4,IEEE80211_AKM_SHA256_PSK=8,IEEE80211_AKM_SAE=16};
struct ieee80211com {unsigned ic_caps=1,ic_flags=0,ic_rsngroupmgmtcipher=IEEE80211_CIPHER_BIP;};
struct ieee80211_node {unsigned ni_rsngroupcipher=IEEE80211_CIPHER_TKIP,ni_rsnciphers=IEEE80211_CIPHER_CCMP,ni_rsnakms=IEEE80211_AKM_PSK,ni_rsncaps=0,ni_flags=0;uint8_t ni_pmkid[16]={};};
static void panic(const char*){abort();}
uint8_t*
'''+fn+r'''
int main(){
 ieee80211com ic;ieee80211_node ni;uint8_t buf[256]={};
 const uint8_t baseline[]={1,0,0,15,172,2,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
 auto end=ieee80211_add_rsn_body(buf,&ic,&ni,0);
 assert(end-buf==20&&!memcmp(buf,baseline,20));
 ni.ni_rsncaps=IEEE80211_RSNCAP_MFPC;
 end=ieee80211_add_rsn_body(buf,&ic,&ni,0);assert(end-buf==26&&buf[18]==0x80&&buf[25]==6);
 ni.ni_rsncaps=0;ic.ic_flags=IEEE80211_F_MFPR;
 end=ieee80211_add_rsn_body(buf,&ic,&ni,0);assert(end-buf==26&&buf[18]==0xc0);
 ic.ic_flags=0;ni.ni_rsngroupcipher=IEEE80211_CIPHER_CCMP;ni.ni_rsnakms=IEEE80211_AKM_SAE;
 end=ieee80211_add_rsn_body(buf,&ic,&ni,0);assert(end-buf==26&&buf[17]==8&&buf[18]==0x80);
 ni.ni_rsnakms=IEEE80211_AKM_PSK;
 end=ieee80211_add_rsn_body(buf,&ic,&ni,0);assert(end-buf==26&&buf[18]==0x80);
 ni.ni_rsngroupcipher=IEEE80211_CIPHER_TKIP;
 end=ieee80211_add_rsn_body(buf,&ic,&ni,1);assert(end-buf==18&&buf[3]==0x50&&buf[4]==0xf2);
 ni.ni_flags=IEEE80211_NODE_PMKID;
 end=ieee80211_add_rsn_body(buf,&ic,&ni,0);assert(end-buf==38&&buf[20]==1);
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)/'test.cpp';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: baseline legacy RSN bytes; required PMF, SAE, AES peers, WPA1 and PMKID retained')
