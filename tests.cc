#include <iostream>
#include "converter.h"

int main() {
    using namespace converter;
    using namespace converter::stubs;
    using namespace converter::func_spec;
    using namespace converter::stubs;
    Function fun{"fun", Ret{"ptr"}, {{"longlong"}, {"ptr"}, {"long"}, {"uint"}}};

    Function fun_void{"fun", Ret{"void"}, {}};

    Function f{"f", Ret{"int"}, {{"int"}, {"int"}}};
    auto pnum = Function::from_line_decl("pnum void int");
    auto pstr = Function::from_line_decl("pstr void ptr");

//    Function p{"f", Ret{"int"}, {{"int"}, {"int"}}};

//    std::cout << converter::stubs::Stub::asmin(fun);

//    std::cout << converter::stubs::Stub::asmin(fun_void);

//    std::cout << converter::stubs::Stub::asmout(fun);

//    Stub stub = Stub::stubin(fun);
//    std::cout << converter::stubs::Stub::asmin(f);

    std::cout << Stub::asmout(pnum);
}