#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <wait.h>
#include <fstream>
#include "assemblage.h"
#include "err.h"

namespace converter::assembly {
    namespace {
        char const* AS = "as";
        char const* OBJCOPY = "objcopy";
        char const* CODE_PREFIX = "code_";
    }

    Tempfile::Tempfile() {
        for (size_t i = 0;; ++i) {
            lock_name.append(std::to_string(i));
//            if (access(lock_name.c_str(), F_OK) == 0) { // file already exists
//                lock_name = LOCK_PREFIX;
//                continue;
//            }
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
            printf("Created Tempfile with name %s\n", lock_name.c_str());
            return;
        }
    }

    Tempfile::~Tempfile() {
        if (lock_name.empty())
            return; // the object was likely moved
        printf("Trying to unlink Tempfile with num %lu, name %s\n", _file_num, lock_name.c_str());
        if (unlink(lock_name.c_str()) == -1) {
            syserr("unlink");
        }
    }

    void rid_gnu_property(std::string const& codefile, std::string const& outfile) {
        // fork OBJCOPY process
        switch (fork()) {
            case 0: // child
                execlp(OBJCOPY, OBJCOPY, "--remove-section", ".note.gnu.property", codefile.c_str(), outfile.c_str(), nullptr);
                syserr("exec() failed");
            default: // parent
                break;
        }

        if (wait(nullptr) == -1)
            syserr("Error in wait");
    }

    std::pair<Tempfile, std::string> assemble_to_file(std::string const& asm_code, bool binary_text_only) {
        // create tempfile for as -> objcopy -> converter communication
        Tempfile codefile_lock;

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

        int wstatus;
        if (wait(&wstatus) == -1)
            syserr("Error in wait");
        if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
            fatal("GNU AS process returned non-0 code.");
        }

        if (binary_text_only) {
            // fork OBJCOPY process
            switch (fork()) {
                case 0: // child
                    execlp(OBJCOPY, OBJCOPY, "-j", ".text", "-O", "binary", codefile.c_str()/*, codefile_lock.name().c_str()*/, nullptr);
                    syserr("exec() failed");
                default: // parent
                    break;
            }

            if (wait(&wstatus) == -1)
                syserr("Error in wait");
            if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
                fatal("OBJCOPY process returned non-0 code.");
            }
        }

        return std::pair<Tempfile, std::string>{std::move(codefile_lock), codefile};
    }

    std::string assemble(std::string const& asm_code, bool binary_text_only) {
        auto [codefile_lock, codefile] = assemble_to_file(asm_code, binary_text_only);

        std::ifstream rx{codefile.c_str(), std::ios_base::binary | std::ios_base::in};
        std::istreambuf_iterator<char> eos;
        std::string machine_code(std::istreambuf_iterator<char>(rx), eos);

        if (unlink(codefile.c_str()) == -1) {
            syserr("unlink");
        }

        return machine_code;
    }
}