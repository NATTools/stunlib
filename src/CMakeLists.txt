#
#
# compiling/installing sources for stunlib

set ( stunlib_srcs
      stunclient.c
      stunserver.c
      stunlib.c
      turnclient.c
      stuntrace.c
      stun_crypto.c
)

set (ADDITIONAL_LIBS "")

add_library ( stunlib SHARED ${stunlib_srcs} )
target_include_directories ( stunlib PUBLIC ../include )
target_include_directories ( stunlib PRIVATE ../src )


install ( TARGETS stunlib
          LIBRARY DESTINATION lib
          ARCHIVE DESTINATION lib
          RUNTIME DESTINATION bin)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

find_package( ZLIB )
if ( ZLIB_FOUND )
    include_directories( ${ZLIB_INCLUDE_DIRS} )
    list(APPEND ADDITIONAL_LIBS ${ZLIB_LIBRARIES})
    add_definitions(-DSTUNLIB_USE_ZLIB)
endif( ZLIB_FOUND )


find_package( OpenSSL )
if( OPENSSL_FOUND )
  include_directories( ${OPENSSL_INCLUDE_DIR} )
  list(APPEND ADDITIONAL_LIBS ${OPENSSL_LIBRARIES})
  add_definitions(-DSTUNLIB_USE_OPENSSL)
endif( OPENSSL_FOUND )

# Todo fix propper library discovery.
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
   list(APPEND ADDITIONAL_LIBS "bsd")
   add_definitions(-DSTUNLIB_USE_BSD)
endif()

target_link_libraries ( stunlib PRIVATE sockaddrutil
                        ${ADDITIONAL_LIBS})

if (coveralls)
    include(Coveralls)
    coveralls_turn_on_coverage()

    set(COVERAGE_SRCS "")
    foreach (S ${stunlib_srcs})
      get_filename_component(S_ABS ${S} ABSOLUTE)
      list (APPEND COVERAGE_SRCS ${S_ABS})
    endforeach()

    # Create the coveralls target.
    coveralls_setup(
        "${COVERAGE_SRCS}"
        ${coveralls_send}                 # If we should upload.
    )

    #add_dependencies(coveralls, all)
endif()
