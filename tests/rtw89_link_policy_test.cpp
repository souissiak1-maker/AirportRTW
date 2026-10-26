#include "../rtw/hal_rtw89/Rtw89LinkPolicy.hpp"
#include <assert.h>
int main()
{
    using namespace Rtw89Link;
    assert(validChannel(5180, 5180, 20));
    assert(validChannel(5180, 5190, 40));
    assert(validChannel(5200, 5190, 40));
    assert(validChannel(5180, 5210, 80));
    assert(validChannel(5240, 5210, 80));
    assert(!validChannel(5180, 5180, 40));
    assert(!validChannel(5180, 5290, 80));
    assert(!validChannel(2412, 2442, 80));
    assert(!validChannel(5180, 5250, 160));
    // Each two-bit stream limit is negotiated independently; 3 is unsupported.
    assert(intersectMCS(0xfffa, 0xfff0) == 0xfff0);
    assert(intersectMCS(0xfffe, 0xfffa) == 0xfffe);
    assert(intersectMCS(0xffff, 0) == 0xffff);
    assert(intersectMCS(0, 0xffff) == 0xffff);
}
