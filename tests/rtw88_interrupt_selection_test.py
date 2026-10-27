#!/usr/bin/env python3
"""Exercise the production interrupt-selection block with simulated IOKit failures."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
s = (root/'rtw/hal_rtw88/Rtw88PciTransport.cpp').read_text()
a = s.index('    // Prefer PCI message-signalled interrupts;')
b = s.index('    RTW_LOG("AirportRTW: transport ready', a)
block = s[a:b]
source = r'''
#include <cassert>
#include <vector>
using IOReturn = int;
constexpr int kIOReturnSuccess=0, kIOInterruptTypePCIMessaged=2;
#define RTW_DIAGNOSTIC(...) do {} while(0)
#define RTW_LOG(...) do {} while(0)
struct Device {
 std::vector<int> types; int getInterruptType(int i,int *t) {
 if(i >= (int)types.size()) return -1; *t=types[i]; return 0; }
};
static int creationFailure=-1, registrationFailure=-1, releases=0;
static std::vector<int> attempts;
struct IOInterruptEventSource {
 int index; template<class T> static IOInterruptEventSource *interruptEventSource(T*,void(*)(),Device*,int i) {
 attempts.push_back(i); return i==creationFailure ? nullptr : new IOInterruptEventSource{i}; }
 void release(){ ++releases; delete this; }
};
struct Loop { int addEventSource(IOInterruptEventSource *s){return s->index==registrationFailure ? -1 : 0;} };
struct Rtw88PciTransport {
 Device *pciDevice; Loop *workLoop; IOInterruptEventSource *interruptSource=nullptr;
 static void interruptOccurred() {} void recordAttachStage(const char*) {}
 bool setup() {
''' + block + r'''
 return true;
 }
};
void check(std::vector<int> types,int failCreate,int failRegister,int expected,std::vector<int> order,int freed) {
 creationFailure=failCreate; registrationFailure=failRegister; attempts.clear(); releases=0;
 Device d{types}; Loop l; Rtw88PciTransport t{&d,&l};
 assert(t.setup()==(expected>=0)); assert(attempts==order); assert(releases==freed);
 if(expected>=0){assert(t.interruptSource->index==expected);t.interruptSource->release();}
}
int main(){
 check({1,2},-1,-1,1,{1},0); // legacy first, MSI preferred
 check({1},-1,-1,0,{0},0); // legacy-only device
 check({1,2},1,-1,0,{1,0},0); // MSI creation fails
 check({1,2},-1,1,0,{1,0},1); // MSI registration fails, candidate released
 check({2,2},0,-1,1,{0,1},0); // next MSI candidate
 check({},-1,-1,-1,{},0); // no interrupts
 check({1,2},1,0,-1,{1,0},1); // all candidates fail
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp=Path(tmp)/'test.cpp'; exe=Path(tmp)/'test'
    cpp.write_text(source)
    subprocess.run(['xcrun','clang++','-std=c++14','-fsanitize=address,undefined',str(cpp),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
print('OK: RTW88 MSI preference, legacy fallback, registration failure cleanup')
