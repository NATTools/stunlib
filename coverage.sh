#!/bin/bash

if [ ! -d "build" ]; then
    mkdir build
fi
cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -Dcoveralls=ON -Dcoveralls_send=ON && make all coveralls

#coveralls --include src -x '.c' --gcov-options '\-lp' -b src
