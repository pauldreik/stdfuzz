# stdfuzz
for fuzzing the C++ standard library

## regex
Finds issues in all three major implementations.

### libstdc++ (gnu)
* Lots of issues which have already been reported by others, see duplicates of https://gcc.gnu.org/bugzilla/show_bug.cgi?id=61582

### libc++ (llvm)
* https://bugs.llvm.org/show_bug.cgi?id=51659, migrated here: [github 51001](https://github.com/llvm/llvm-project/issues/51001)

### Microsoft
* https://github.com/microsoft/STL/issues/2168

## charconv


## format
### libstdc++ (gnu)
* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110860 integer overflow in the following: ```std::format("{:f}",2e304)```
* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110862 out of bounds read on ```"{0:{0}"```
* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110968 out of bounds read on ```std::format("{:05L}",-1.f);```
* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110974 out of bounds read on ```"{:{}."```
* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=111102 illegal pointer arithmetic on ```std::format(L"{:65536}",1)```
* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=111162 signed integer overflow triggered by std::chrono::parse
* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=111163 signed integer overflow in ```std::format("{:%S}",std::chrono::duration....)```
### libc++ (llvm)
* https://github.com/llvm/llvm-project/issues/65011 out of bounds read outside the format string
