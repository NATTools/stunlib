[![Build Status](https://travis-ci.org/NPPT/sockaddrutil.svg?branch=master)](https://travis-ci.org/NPPT/sockaddrutil)
[![Coverage Status](https://coveralls.io/repos/NPPT/sockaddrutil/badge.svg?branch=master)](https://coveralls.io/r/NPPT/sockaddrutil?branch=master)

# Sockaddrutil
Idea is to make it a little less painfull to work with sockaddr and friends. 

## Compiling

`build.sh` does the following

    mkdir build     (hold all of the build files in a separate directory)
    cd build; cmake (create the makefiles)
    make            (To build the code)

You will end up with a library you can link
against in build/dist/lib.


## Development

You need to have [cmake](http://www.cmake.org/ to build.
Note that version 3.2 or newer is needed. (Some linux distributions are a bit slow to update, so manuall install may be needed.)

### Unit Tests

Build and run the checks with

    make test

If tests fail it can help to run the binaries in `build/dist/test` to see where
they fail.

Travis will compile and run the tests.

### Coverage

Coveralls use the coverage.sh script to generate coverage reports.

To manually generate lcov reports you can run the ./coveragereport.sh script.
A nice html page can be found in lcov/index.html

It can be a bit tricky to get your favorite platform to support gcov and
friends, but do not give up! (I had problems on os-x, but unfortunately I do not
remember how it was fixed)

### Coding Standard

TODO: make this more formal.

We like to do C90/C99ish style. Will make sure the library compile on most platforms.

Braces can be placed where you want them. But try to be consistent..

White-spaces when committing should be avoided. (Usual rant on diffs and
readability)

## Contributing

Fork and send pull requests.  Please add your name to the AUTHORS list in your
first patch.

# License

BSD 2-clause:

Copyright (c) 2015, Sockaddrutil AUTHORS
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
