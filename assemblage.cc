#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <wait.h>
#include <fstream>
#include "assemblage.h"
#include "err.h"

namespace converter::assembly {
    static char const* LOCK_PREFIX = "lock_";
    static char const* CODE_PREFIX = "code_";

    namespace {
        class Tempfile {
            std::string lock_name{LOCK_PREFIX};
            size_t _file_num;
        public:
            explicit Tempfile() {
                for (size_t i = 0;; ++i) {
                    lock_name.append(std::to_string(i));
//                    if (access(lock_name.c_str(), F_OK) == 0) { // file already exists
//                        lock_name = LOCK_PREFIX;
//                        continue;
//                    }
                    int filedes;
                    filedes = open(lock_name.c_str(), O_WRONLY | O_CREAT | O_EXCL);
                    if (filedes == -1) {
                        if (errno == EEXIST) {
                            lock_name = LOCK_PREFIX;
                            continue;
                        } else {
                            syserr("Error in open()");
                        }
                    }
                    close(filedes);
                    _file_num = i;
                    return;
                }
            }
            ~Tempfile() {
                if (unlink(lock_name.c_str()) == -1) {
                    syserr("unlink");
                }
            }

            [[nodiscard]] size_t file_num() const {
                return _file_num;
            }
        };
    }

    std::string assemble(std::string const& asm_code) {
        static char const* AS = "as";
        static char const* OBJCOPY = "objcopy";

        // create tempfile for as -> objcopy -> converter communication
        Tempfile const codefile_lock;

        std::string const codefile{CODE_PREFIX + std::to_string(codefile_lock.file_num())};

        int us_to_as[2];
        if (pipe(us_to_as) != 0) {
            std::cerr << "Error in pipe().\n";
        }

        // fork AS process
        switch (fork()) {
            case 0: // child
                if (close(0) == -1)
                    syserr("Error in child, close(0)");
                if (dup(us_to_as[0]) != 0)
                    syserr("Error in child, dup(us_to_as[0])");
                if (close(us_to_as[0]) == -1)
                    syserr("Error in child, close(us_to_as[0])");
                if (close(us_to_as[1]) == -1)
                    syserr("Error in child, close (us_to_us[1])");

                execlp(AS, AS, "-o", codefile.c_str(), "-", nullptr);
                syserr("exec() failed");
            default: // parent
                if (close(us_to_as[0]) == -1)
                    syserr("Error in parent, close(us_to_as[0])");
        }

        if (write(us_to_as[1], asm_code.c_str(), asm_code.length()) == -1) {
            syserr("Error in write()");
        }

        if (close(us_to_as[1]) == -1)
            syserr("Error in parent, us_to_as(1)");

        if (wait(nullptr) == -1)
            syserr("Error in wait");

        // fork OBJCOPY process
        switch (fork()) {
            case 0: // child
                execlp(OBJCOPY, OBJCOPY, "-j", ".text", "-O", "binary", codefile.c_str()/*, codefile_lock.name().c_str()*/, nullptr);
                syserr("exec() failed");
            default: // parent
                break;
        }

        if (wait(nullptr) == -1)
            syserr("Error in wait");

        std::ifstream rx{codefile.c_str(), std::ios_base::binary | std::ios_base::in};
        std::istreambuf_iterator<char> eos;
        std::string machine_code(std::istreambuf_iterator<char>(rx), eos);

        if (unlink(codefile.c_str()) == -1) {
            syserr("unlink");
        }

        return machine_code;
    }
}