#
#
# top level build file for the stunlib library

## prepare CMAKE
cmake_minimum_required ( VERSION 3.2.0 )
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
include ( Uncrustify )
include ( GetGitRevisionDescription )
git_describe(VERSION --tags --dirty=-d)

string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" STUNLIB_VERSION_MAJOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" STUNLIB_VERSION_MINOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" STUNLIB_VERSION_PATCH "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.[0-9]+(.*)" "\\1" STUNLIB_VERSION_SHA1 "${VERSION}")

mark_as_advanced(STUNLIB_VERSION_MAJOR STUNLIB_VERSION_MINOR STUNLIB_VERSION_PATCH)

set ( STUNLIB_VERSION "${STUNLIB_VERSION_MAJOR}.${STUNLIB_VERSION_MINOR}.${STUNLIB_VERSION_PATCH}" )

project ( "stunlib" VERSION "${stunlib_VERSION}")

find_package(Doxygen)

## setup options
option ( verbose "Produce verbose makefile output" OFF )
option ( optimize "Set high optimization level" OFF )
option ( fatal_warnings "Treat build warnings as errors" ON )
option ( coveralls "Generate coveralls data" ON )
option ( coveralls_send "Send data to coveralls site" OFF )
option ( build_docs "Create docs using Doxygen" ${DOXYGEN_FOUND} )
option ( uncrustify "Uncrustify the source code" ${UNCRUSTIFY_FOUND} )

set ( dist_dir    ${CMAKE_BINARY_DIR}/dist )
set ( prefix      ${CMAKE_INSTALL_PREFIX} )
set ( exec_prefix ${CMAKE_INSTALL_PREFIX}/bin )
set ( libdir      ${CMAKE_INSTALL_PREFIX}/lib )
set ( includedir  ${CMAKE_INSTALL_PREFIX}/include )
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/stunlib.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/stunlib.pc @ONLY)
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/stunlib.pc DESTINATION lib/pkgconfig )

set ( package_prefix "${CMAKE_PACKAGE_NAME}-${CMAKE_SYSTEM_NAME}" )

set ( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/bin )
set ( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${dist_dir}/lib )
set ( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${dist_dir}/lib )
set ( CMAKE_BUILD_TYPE Debug )

## check and generate configuration

include ( CheckIncludeFiles )
include ( CheckLibraryExists )
include ( CheckFunctionExists )
include ( CheckTypeSize )

check_include_files ( stdint.h HAVE_STDINT_H )
check_include_files ( stdlib.h HAVE_STDLIB_H )
check_include_files ( stdbool.h HAVE_STDBOOL_H )
#check_function_exists ( arc4random HAVE_ARC4RANDOM )
#check_library_exists ( pthread pthread_create "" HAVE_LIBPTHREAD )
#check_library_exists ( m tan "" HAVE_LIBM )


configure_file ( ${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h )

## setup global compiler options
include_directories ( ${CMAKE_CURRENT_BINARY_DIR} )
if ( CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
     CMAKE_C_COMPILER_ID MATCHES "Clang" )
  message ( STATUS "adding GCC/Clang options ")
  add_definitions ( -std=gnu99 -Wall -Wextra -pedantic )
  ## disable VLA "is a GNU extension" warning
  add_definitions ( -Wno-gnu-zero-variadic-macro-arguments )
  if ( fatal_warnings )
    add_definitions ( -Werror )
  endif ()
  if ( optimize )
    add_definitions ( -O2 )
  endif ()
elseif ( MSVC )
  add_definitions ( /W3 )
  if ( fatal_warnings )
    add_definitions ( /WX )
  endif ()
else ()
  message ( FATAL_ERROR "unhandled compiler id: ${CMAKE_C_COMPILER_ID}" )
endif ()
if ( verbose )
  set ( CMAKE_VERBOSE_MAKEFILE ON )
endif ()



install (FILES AUTHORS LICENSE README.md DESTINATION .)

## setup packaging
set ( CPACK_GENERATOR "TGZ" )
set ( CPACK_PACKAGE_VERSION "${PROJECT_VERSION}" )
set ( CPACK_SOURCE_GENERATOR "TGZ" )
set ( CPACK_SOURCE_IGNORE_FILES "/\\\\.git/" )
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/.gitignore igs)
foreach (ig IN ITEMS ${igs})
    # remove comments
    string ( REGEX REPLACE "^\\s*#.*" "" ig "${ig}")
    # remove any other whitespace
    string ( STRIP "${ig}" ig)
    # anything left?
    if (ig)
      # dots are literal
      string ( REPLACE "." "\\\\." ig "${ig}" )
      # stars are on thars
      string ( REPLACE "*" ".*" ig "${ig}" )
      list ( APPEND CPACK_SOURCE_IGNORE_FILES "/${ig}/" )
    endif()
endforeach()

#message ( "CPACK_SOURCE_IGNORE_FILES: " ${CPACK_SOURCE_IGNORE_FILES} )
set ( CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_SOURCE_DIR}/README.md )
set ( CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" )

include ( CPack )
include ( CTest )
include ( LCov )

UncrustifyTop(${uncrustify})

if (build_docs)
    if(NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    else()
        set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
        set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

        configure_file(${doxyfile_in} ${doxyfile} @ONLY)

        add_custom_target(doc
            COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation wit1h Doxygen"
            VERBATIM)

        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc)
    endif()
endif()


Include(ExternalProject)
ExternalProject_Add(
   project_sockaddrutil
   GIT_REPOSITORY https://github.com/NATTools/sockaddrutil.git
   CMAKE_ARGS -Doptimize=OFF -Dbuild_docs=OFF -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
   INSTALL_DIR "${dist_dir}"
   UPDATE_DISCONNECTED 1
)

ExternalProject_Get_Property(project_sockaddrutil install_dir)
include_directories ( "${install_dir}/include" )
add_library(sockaddrutil STATIC IMPORTED)
set_property(TARGET sockaddrutil PROPERTY IMPORTED_LOCATION "${install_dir}/lib/${CMAKE_SHARED_MODULE_PREFIX}sockaddrutil${CMAKE_SHARED_LIBRARY_SUFFIX}")
add_dependencies(sockaddrutil project_sockaddrutil)


## include the parts
add_subdirectory ( include )
add_subdirectory ( src )
add_subdirectory ( test )
