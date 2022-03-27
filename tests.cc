#include <iostream>
#include "converter.h"

int main() {
    using namespace converter::func_spec;
    Function fun{"fun", Ret{"ptr"}, {{"longlong"}, {"ptr"}, {"long"}, {"uint"}}};

    Function fun_void{"fun", Ret{"void"}, {}};

    std::cout << converter::stubs::Stub::asmin(fun);
    std::cout << converter::stubs::Stub::asmin(fun_void);
}