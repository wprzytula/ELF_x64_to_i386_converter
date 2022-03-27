#include <iostream>
#include "converter.h"

int main() {
    using namespace converter;
    using namespace converter::stubs;
    using namespace converter::func_spec;
    Function fun{"fun", Ret{"ptr"}, {{"longlong"}, {"ptr"}, {"long"}, {"uint"}}};

    Function fun_void{"fun", Ret{"void"}, {}};

//    std::cout << converter::stubs::Stub::asmin(fun);

//    std::cout << converter::stubs::Stub::asmin(fun_void);

//    std::cout << converter::stubs::Stub::asmout(fun);

    Stub stub = Stub::stubin(fun);
//    getchar();
}