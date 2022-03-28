#include <iostream>
#include "converter.h"

int main() {
    using namespace converter::func_spec;
    Function fun{"fun", Ret{"ptr"}, {{"longlong"}, {"ptr"}, {"long"}, {"uint"}}};

    Function fun_void{"fun", Ret{"void"}, {}};

    Function f{"f", Ret{"int"}, {{"int"}, {"int"}}};

//    Function p{"f", Ret{"int"}, {{"int"}, {"int"}}};

//    std::cout << converter::stubs::Stub::asmin(fun);

//    std::cout << converter::stubs::Stub::asmin(fun_void);

    std::cout << converter::stubs::Stub::asmin(f);
}